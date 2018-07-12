#include "mptcp_rbs_optimizer_ebpf.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_ctx.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_optimizer_ebpf_regalloc.h"
#include "mptcp_rbs_queue.h"
#include "mptcp_rbs_sched.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"
#include <linux/bpf.h>
#include <asm/div64.h>

/** Some fixed temporaries */
enum { CTX_TMP, VARS_TMP, REGS_TMP, FIXED_TMP_COUNT };

/** Information about a filter/min/max/sum variable */
struct filter_var {
	const void *progress;
	int temp;
};

/*
 * Filter var information lists
 */

DECL_DA(filter_var_list, struct filter_var *);

#define INIT_FILTER_VAR_LIST(list) INIT_DA(list)

#define FREE_FILTER_VAR_LIST(list) FREE_DA(list)

#define PUSH_FILTER_VAR(list, var) ADD_DA_ITEM(list, var)

#define POP_FILTER_VAR(list) DELETE_DA_ITEM(list, GET_DA_LEN(list) - 1)

#define FOREACH_FILTER_VAR(list, var, cmds) FOREACH_DA_ITEM(list, var, cmds)

/** Context for eBPF code generation */
struct ebpf_ctx {
	/** Pointer to the optimization context */
	struct mptcp_rbs_opt_ctx *ctx;
	/** Number of used temporaries */
	int used_temps;
	/** Map with used temporaries */
	u64 used_temps_map;
	/** The buffer for string constants */
	char **strs;
	/** Length of strs */
	int strs_len;
	/** Capacity of instruction list inside the current block */
	int capacity;
	/** The current block */
	struct mptcp_rbs_cfg_block *block;
	/** The current eBPF block */
	struct mptcp_rbs_ebpf_block *eblock;
	/** List with active filter variables */
	struct filter_var_list filter_var_list;
	/** Variable number of a found *_NEXT value or -1 */
	int next_var;
	/** NULL eBPF block of the variable with *_NEXT value or NULL */
	struct mptcp_rbs_ebpf_block *next_var_null_eblock;
};

/** Information about a block that is stored inside the tag field */
struct block_info {
	/** The corresponding eBPF block of this block */
	struct mptcp_rbs_ebpf_block *eblock;
	/**
	 * Break eBPF block if this block is the beginning of a foreach loop or
	 * NULL
	 */
	struct mptcp_rbs_ebpf_block *break_eblock;
	/**
	 * Continue eBPF block if this block is the beginning of a foreach loop
	 * or NULL
	 */
	struct mptcp_rbs_ebpf_block *cont_eblock;
	/** Mask with reserved temporaries by a foreach loop */
	u64 reserved_temps_map;
};

#define BLOCK_INFO(block) ((struct block_info *) (block)->tag)

/**
 * Adds an eBPF instruction to a block
 * @eblock: The block where the instruction should be added
 * @capacity: Pointer to the capacity of the block
 * @instr: The instruction to add
 */
static void add_instr(struct mptcp_rbs_ebpf_block *eblock, int *capacity,
		      struct mptcp_rbs_ebpf_instr instr)
{
	if (*capacity == eblock->instr_count) {
		*capacity = *capacity == 0 ? 4 : *capacity << 1;
		eblock->instrs =
		    krealloc(eblock->instrs,
			     *capacity * sizeof(struct mptcp_rbs_ebpf_instr),
			     GFP_KERNEL);
	}

	eblock->instrs[eblock->instr_count] = instr;
	++eblock->instr_count;
}

#define add_instr_ectx(ectx, instr)                                            \
	add_instr(ectx->eblock, &ectx->capacity, instr)

#define TEMP_TO_MAP(t) (1 << (t))

/**
 * Reserves a temporary
 * @ectx: The generation context
 * @return: The reserved temporary
 */
static int reserve(struct ebpf_ctx *ectx)
{
	int i;
	int temp = -1;
	int count = 0;

	for (i = 0; i < 64; ++i) {
		if (TEMP_TO_MAP(i) & ectx->used_temps_map)
			++count;
		else if (temp == -1)
			temp = i;
	}

	ectx->used_temps_map |= TEMP_TO_MAP(temp);
	ectx->used_temps = max(ectx->used_temps, count);
	return temp;
}

/**
 * Reserves all temporaries in a bitmap
 * @ectx: The generation context
 * @reserved_map: The temporary bitmap
 */
static void reserve_all(struct ebpf_ctx *ectx, u64 reserved_map)
{
	BUG_ON(ectx->used_temps_map & reserved_map);

	ectx->used_temps_map |= reserved_map;
}

/**
 * Dereserves one temporary
 * @ectx: The generation context
 * @t: The temporary to dereserve
 */
static void dereserve(struct ebpf_ctx *ectx, int t)
{
	BUG_ON(!(ectx->used_temps_map & TEMP_TO_MAP(t)));

	ectx->used_temps_map &= ~TEMP_TO_MAP(t);
}

/**
 * Dereserves all temporaries in a bitmap
 * @ectx: The generation context
 * @reserved_map: The temporary bitmap
 */
static void dereserve_all(struct ebpf_ctx *ectx, u64 reserved_map)
{
	BUG_ON((ectx->used_temps_map & reserved_map) != reserved_map);

	ectx->used_temps_map &= ~reserved_map;
}

/*
 * Functions that can be called from inside eBPF code
 */

u64 ebpf_printk(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	printk(*((char **) &r1), r2);
	return 0;
}

u64 ebpf_add_drop(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb = *((struct sk_buff **) &r2);
	bool reinject = r3;

	mptcp_rbs_action_new(ctx->rbs_cb->open_actions, false, ACTION_KIND_DROP,
			     NULL, skb, reinject);
	return 0;
}

u64 ebpf_add_push(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct tcp_sock *sbf = *((struct tcp_sock **) &r2);
	struct sk_buff *skb = *((struct sk_buff **) &r3);
	bool reinject = r4;

	mptcp_rbs_action_new(ctx->rbs_cb->open_actions, false, ACTION_KIND_PUSH,
			     sbf, skb, reinject);
	return 0;
}

u64 ebpf_ktime_get_raw_ms(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
    u64 result = ktime_get_raw_ns();
    do_div(result, 1000000);
	return result;
}

u64 ebpf_random(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	unsigned int n;

	get_random_bytes(&n, sizeof(unsigned int));
	return n;
}

u64 ebpf_has_window_for(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct tcp_sock *sbf = *((struct tcp_sock **) &r2);
	struct sk_buff *skb = *((struct sk_buff **) &r3);
	unsigned int mss_now = tcp_current_mss(ctx->meta_sk);

	/* RBS copied from mptcp_sched.c */
	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (after(sbf->write_seq + min(skb->len, mss_now), tcp_wnd_end(sbf)))
		return 0;
	return 1;
}

u64 ebpf_bw_out_send(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	return mptcp_rbs_sbf_get_bw_send(mptcp_rbs_get_sbf_cb(sbf));
}

u64 ebpf_bw_out_ack(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	return mptcp_rbs_sbf_get_bw_ack(mptcp_rbs_get_sbf_cb(sbf));
}

u64 ebpf_sbf_user(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	return mptcp_rbs_get_sbf_cb(sbf)->user;
}

u64 ebpf_rtt_ms(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	return (sbf->srtt_us >> 3) / 1000;
}

u64 ebpf_queued(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	return (sbf->write_seq - sbf->snd_nxt) / sbf->mss_cache;
}

u64 ebpf_lossy(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct tcp_sock *sbf = *((struct tcp_sock **) &r1);

	if (inet_csk((struct sock *) sbf)->icsk_ca_state == TCP_CA_Loss) {
		mptcp_debug("sbf_is_available %p loss state -> false\n", sbf);
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(sbf))
			return true;
		else if (sbf->snd_una != sbf->high_seq)
			return true;
	}

	return false;
}

u64 ebpf_sent_on_all(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb = *((struct sk_buff **) &r2);
	u32 mask;
	struct tcp_sock *sbf;

	mask = TCP_SKB_CB(skb)->path_mask;
	sbf = ctx->mpcb->connection_list;

	while (sbf) {
		if (!(mask & mptcp_pi_to_flag(sbf->mptcp->path_index)))
			return 0;

		sbf = sbf->mptcp->next;
	}

	return 1;
}

u64 ebpf_skb_length(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct sk_buff *skb = *((struct sk_buff **) &r1);

	return TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
}

u64 ebpf_skb_seq(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct sk_buff *skb = *((struct sk_buff **) &r1);

	return TCP_SKB_CB(skb)->seq;
}

u64 ebpf_skb_psh(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct sk_buff *skb = *((struct sk_buff **) &r1);

	return TCP_SKB_CB(skb)->tcp_flags & TCPHDR_PSH;
}

u64 ebpf_q_next(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb_candidate = *((struct sk_buff **) &r2);
	struct sk_buff *skb;

	if (skb_candidate) {
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue,
				      skb_candidate))
			skb_candidate = NULL;
		else
			skb_candidate = skb_queue_next(
			    &ctx->meta_sk->sk_write_queue, skb_candidate);
	} else
		skb_candidate = ctx->rbs_cb->queue_position;

	skb = mptcp_rbs_next_in_queue(&ctx->meta_sk->sk_write_queue,
				      skb_candidate);

	return (size_t) skb;
}

u64 ebpf_qu_next(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb = *((struct sk_buff **) &r2);

	if (skb) {
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue, skb))
			skb = NULL;
		else {
			skb =
			    skb_queue_next(&ctx->meta_sk->sk_write_queue, skb);
		}
	} else {
		if (ctx->meta_sk->sk_write_queue.qlen == 0)
			skb = NULL;
		else
			skb = skb_peek(&ctx->meta_sk->sk_write_queue);
	}

	if (skb == ctx->rbs_cb->queue_position) {
		mptcp_debug(
		    "%s skb %p matches the queue_position, we are at the end\n",
		    __func__, skb);
		skb = NULL;
	}

	while (skb && TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue) {
		mptcp_debug("%s skips skb %p\n", __func__, skb);
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue, skb) ||
		    /* Empty because it points to the element in Q */
		    skb == ctx->rbs_cb->queue_position) {
			skb = NULL;
			break;
		} else
			skb =
			    skb_queue_next(&ctx->meta_sk->sk_write_queue, skb);
	}

	return (size_t) skb;
}

u64 ebpf_rq_next(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb_candidate = *((struct sk_buff **) &r2);
	struct sk_buff *skb;

	if (skb_candidate) {
		if (skb_queue_is_last(&ctx->mpcb->reinject_queue,
				      skb_candidate)) {
			skb_candidate = NULL;
		} else {
			skb_candidate = skb_queue_next(
			    &ctx->mpcb->reinject_queue, skb_candidate);
		}
	} else
		skb_candidate = skb_peek(&ctx->mpcb->reinject_queue);

	skb =
	    mptcp_rbs_next_in_queue(&ctx->mpcb->reinject_queue, skb_candidate);

	return (size_t) skb;
}

u64 ebpf_subflows_next(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct tcp_sock *sbf = *((struct tcp_sock **) &r2);

	if (sbf)
		sbf = sbf->mptcp->next;
	else
		sbf = ctx->mpcb->connection_list;

	/* Skip unavailable subflows */
	while (sbf && !mptcp_rbs_sbf_is_available(sbf)) {
		sbf = sbf->mptcp->next;
	}

	return (size_t) sbf;
}

u64 ebpf_varlist_expand(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_var *var = *((struct mptcp_rbs_var **) &r1);
	struct tcp_sock **item = *((struct tcp_sock ***) &r2);
	int capacity;
	int index;

	BUILD_BUG_ON(offsetof(struct mptcp_rbs_var, sbf_list_value) !=
		     offsetof(struct mptcp_rbs_var, skb_list_value));

	if (!item) {
		index = 0;
		capacity = 8;
	} else {
		index =
		    (item - var->sbf_list_value) / sizeof(struct tcp_sock *);
		capacity = (index + 1) * 2;
	}

	var->sbf_list_value =
	    krealloc(var->sbf_list_value, capacity * sizeof(struct tcp_sock *),
		     GFP_KERNEL);
	memset(&var->sbf_list_value[index], 0,
	       (capacity - index - 1) * sizeof(struct tcp_sock *));
	var->sbf_list_value[capacity - 1] = (struct tcp_sock *) 1;

	return (size_t) &var->sbf_list_value[index];
}

u64 ebpf_skb_list_pop(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	struct mptcp_rbs_eval_ctx *ctx = *((struct mptcp_rbs_eval_ctx **) &r1);
	struct sk_buff *skb = *((struct sk_buff **) &r2);
	enum mptcp_rbs_value_kind underlying_queue_kind =
	    (enum mptcp_rbs_value_kind) r3;

	ctx->side_effects = 1;

	if (underlying_queue_kind == VALUE_KIND_Q) {
		/*
		 * Pop an element from Q might be the queue_position or later
		 */
		if (skb == ctx->rbs_cb->queue_position) {
			mptcp_rbs_advance_send_head(
			    ctx->meta_sk, &ctx->rbs_cb->queue_position);
			mptcp_rbs_debug(
			    "rbs_q_pop returns %p, new queue head %p\n", skb,
			    ctx->rbs_cb->queue_position);
		} else {
			/* we can not unlink the packet, as all skbs have to
			 * stay in the circular buffer */
			mptcp_debug(
			    "%s sets not_in_queue for packet %p in Q, was %u\n",
			    __func__, skb,
			    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
			TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		}

		return (size_t) skb;
	}

	if (underlying_queue_kind == VALUE_KIND_RQ) {
		mptcp_debug("%s sets not_in_queue, to_free and to_unlink for "
			    "packet %p in RQ, was %u\n",
			    __func__, skb,
			    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
		TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		TCP_SKB_CB(skb)->mptcp_rbs.flags_to_free = 1;
		TCP_SKB_CB(skb)->mptcp_rbs.flags_to_unlink = 1;

		return (size_t) skb;
	}

	if (underlying_queue_kind == VALUE_KIND_QU) {
		mptcp_debug(
		    "%s sets not_in_queue for packet %p in QU, was %u\n",
		    __func__, skb,
		    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
		TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		return (size_t) skb;
	}

	BUG_ON(true);
	return 0;
}

static struct bpf_func_proto func_protos[] = {
	{
	    .func = &ebpf_printk,
	    .gpl_only = false,
	    .ret_type = RET_VOID,
	    .arg1_type = ARG_ANYTHING,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_add_drop,
	    .gpl_only = false,
	    .ret_type = RET_VOID,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	    .arg3_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_add_push,
	    .gpl_only = false,
	    .ret_type = RET_VOID,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	    .arg3_type = ARG_ANYTHING,
	    .arg4_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_ktime_get_raw_ms,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	},
	{
	    .func = &ebpf_random,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	},
	{
	    .func = &ebpf_has_window_for,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	    .arg3_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_bw_out_send,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_bw_out_ack,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_rtt_ms,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_lossy,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_queued,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_skb_length,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_skb_seq,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_skb_psh,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_sbf_user,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_sent_on_all,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_q_next,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_qu_next,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_rq_next,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_subflows_next,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_PTR_TO_CTX,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_varlist_expand,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	    .arg2_type = ARG_ANYTHING,
	},
	{
	    .func = &ebpf_skb_list_pop,
	    .gpl_only = false,
	    .ret_type = RET_INTEGER,
	    .arg1_type = ARG_ANYTHING,
	    .arg2_type = ARG_ANYTHING,
	    .arg3_type = ARG_ANYTHING,
	},
};

static const struct bpf_func_proto *get_func_proto(enum bpf_func_id func_id)
{
	int index = func_id - BPF_FUNC_mptcp_rbs_printk;
	if (index < 0 || index >= ARRAY_SIZE(func_protos))
		return NULL;
	return &func_protos[index];
}

static bool is_valid_access(int off, int size, enum bpf_access_type type, enum bpf_reg_type *reg_type)
{
	return false;
}

static struct bpf_verifier_ops bpf_ops = {
	.get_func_proto = get_func_proto,
	.is_valid_access = is_valid_access,
};

static bool gen_value(struct ebpf_ctx *ectx,
		      const struct mptcp_rbs_value *value, int temp,
		      struct mptcp_rbs_ebpf_block *null_eblock);

static bool gen_list_value(struct ebpf_ctx *ectx,
			   const struct mptcp_rbs_value *value, int temp,
			   struct mptcp_rbs_ebpf_block *null_eblock,
			   struct mptcp_rbs_ebpf_block **break_eblock,
			   struct mptcp_rbs_ebpf_block **cont_eblock,
			   u64 *reserved_temps_map);

static bool noinline mptcp_rbs_value_constint_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_constint *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, value->value));

	return false;
}

static bool noinline mptcp_rbs_value_conststring_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_conststring *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* Put the string in strs */
	int len = strlen(value->value);
	int idx = ectx->strs_len;
	char *new_str;

	++ectx->strs_len;
	ectx->strs =
	    krealloc(ectx->strs, ectx->strs_len * sizeof(char *), GFP_KERNEL);
	ectx->strs[idx] = kmalloc(len + 1, GFP_KERNEL);
	new_str = ectx->strs[idx];
	memcpy(new_str, value->value, len + 1);

	add_instr_ectx(
	    ectx,
	    EBPF_RAW_INSTR(((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
					      .dst_reg = 0,
					      .src_reg = 0,
					      .off = 0,
					      .imm = (u32)(size_t)(new_str) }),
			   -1, -1, -1, -1, -1, temp));
	add_instr_ectx(
	    ectx, EBPF_RAW_INSTR(((struct bpf_insn){
				     .code = 0,
				     .dst_reg = 0,
				     .src_reg = 0,
				     .off = 0,
				     .imm = ((u64)(size_t)(new_str)) >> 32 }),
				 -1, -1, -1, -1, -1, -1));

	return false;
}

static bool noinline mptcp_rbs_value_null_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_null *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* TODO We don't need this right? */
	BUG_ON(true);
	return false;
}

static bool noinline mptcp_rbs_value_bool_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_bool_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(s32)), temp, VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, bool_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, -1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_int_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_int_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(s64)), temp, VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, int_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, -1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_string_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_string_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(char *)), temp, VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, string_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_sbf_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct tcp_sock *)), temp,
			 VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, sbf_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_sbf_list_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct tcp_sock **)), temp,
			 VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, sbf_list_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_sbf_list_var_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int temp_ptr;
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	/* Check if variable is NULL */
	temp_ptr = reserve(ectx);
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct tcp_sock **)),
			 temp_ptr, VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, sbf_list_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_ptr, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(
	    ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct tcp_sock *)),
			       temp, temp_ptr, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);
	capacity = 0;
	add_instr(*cont_eblock, &capacity,
		  EBPF_ALU_IMM(BPF_ADD, temp_ptr, sizeof(struct tcp_sock *)));
	add_instr(*cont_eblock, &capacity,
		  EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct tcp_sock *)),
			       temp, temp_ptr, 0));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (sbf) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = TEMP_TO_MAP(temp_ptr);
	return true;
}

static bool noinline mptcp_rbs_value_skb_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct sk_buff *)), temp,
			 VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, skb_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_skb_list_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	struct mptcp_rbs_ebpf_block *eblock;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct sk_buff **)), temp,
			 VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, skb_list_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next = eblock;
	ectx->eblock->next_else = null_eblock;

	ectx->eblock = eblock;
	ectx->capacity = 0;

	return true;
}

static bool noinline mptcp_rbs_value_skb_list_var_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int temp_ptr;
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	/* Check if variable is NULL */
	temp_ptr = reserve(ectx);
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct sk_buff **)), temp_ptr,
			 VARS_TMP,
			 sizeof(struct mptcp_rbs_var) * value->var_number +
			     offsetof(struct mptcp_rbs_var, skb_list_value)));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_ptr, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct sk_buff *)),
				    temp, temp_ptr, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);
	capacity = 0;
	add_instr(*cont_eblock, &capacity,
		  EBPF_ALU_IMM(BPF_ADD, temp_ptr, sizeof(struct sk_buff *)));
	add_instr(*cont_eblock, &capacity,
		  EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct sk_buff *)),
			       temp, temp_ptr, 0));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (skb) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_ATOMIC);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = TEMP_TO_MAP(temp_ptr);
	return true;
}

static bool noinline mptcp_rbs_value_not_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_not *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->operand,
		      temp, null_eblock);

	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_XOR, temp, 1));

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_equal_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_equal *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JNE, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (unequal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_unequal_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_unequal *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JEQ, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (unequal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_less_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_less *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JGE, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (greater equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (less) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_less_equal_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_less_equal *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JGT, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (greater) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (less equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_greater_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_greater *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JGT, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (greater) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (less equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_greater_equal_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_greater_equal *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *last_eblock;
	int temp_right;
	int capacity;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JGE, temp, temp_right));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_right);

	last_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Add instructions to else (greater equal) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next_else = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Add instructions to then (less) branch */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	ectx->eblock->next = eblock;
	add_instr(eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(eblock, &capacity, EBPF_JMP_OFF());
	eblock->next = last_eblock;

	/* Set last_block as current */
	ectx->eblock = last_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_and_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_and *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *false_eblock;
	int capacity;

	/* Prepare the false block that is used instead of the null block */
	false_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(false_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(false_eblock, &capacity, EBPF_JMP_OFF());

	/* Calculate left operand */
	gen_value(ectx, (const struct mptcp_rbs_value *) value->left_operand,
		  temp, false_eblock);

	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = false_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	/* Calculate right operand */
	gen_value(ectx, (const struct mptcp_rbs_value *) value->right_operand,
		  temp, false_eblock);

	/* Create the last block as jump target for the false block */
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	false_eblock->next = ectx->eblock->next;
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	return false;
}

static bool noinline mptcp_rbs_value_or_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_or *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *true_eblock;
	struct mptcp_rbs_ebpf_block *false_eblock;
	int capacity;

	/* Prepare the true block */
	true_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(true_eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(true_eblock, &capacity, EBPF_JMP_OFF());

	/* Prepare the false block */
	false_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Calculate left operand */
	gen_value(ectx, (const struct mptcp_rbs_value *) value->left_operand,
		  temp, false_eblock);

	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	ectx->eblock->next_else = true_eblock;
	ectx->eblock->next = false_eblock;
	ectx->eblock = false_eblock;
	ectx->capacity = 0;

	/* Prepare the a new false block */
	false_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(false_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(false_eblock, &capacity, EBPF_JMP_OFF());

	/* Calculate right operand */
	gen_value(ectx, (const struct mptcp_rbs_value *) value->right_operand,
		  temp, false_eblock);

	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	true_eblock->next = ectx->eblock->next;
	false_eblock->next = ectx->eblock->next;
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	return false;
}

static bool noinline mptcp_rbs_value_add_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_add *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_right;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_ADD, temp, temp_right));
	dereserve(ectx, temp_right);

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_subtract_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_subtract *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_right;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_SUB, temp, temp_right));
	dereserve(ectx, temp_right);

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_multiply_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_multiply *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_right;

	null_eblock_used = gen_value(
	    ectx, (const struct mptcp_rbs_value *) value->left_operand, temp,
	    null_eblock);
	temp_right = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx,
		      (const struct mptcp_rbs_value *) value->right_operand,
		      temp_right, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_MUL, temp, temp_right));
	dereserve(ectx, temp_right);

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_divide_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_divide *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	int temp_right;

	gen_value(ectx, (const struct mptcp_rbs_value *) value->left_operand,
		  temp, null_eblock);
	temp_right = reserve(ectx);
	gen_value(ectx, (const struct mptcp_rbs_value *) value->right_operand,
		  temp_right, null_eblock);

	/* Check if right operand is 0 */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_right, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_DIV, temp, temp_right));
	dereserve(ectx, temp_right);

	return true;
}

static bool noinline mptcp_rbs_value_remainder_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_remainder *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	int temp_right;

	gen_value(ectx, (const struct mptcp_rbs_value *) value->left_operand,
		  temp, null_eblock);
	temp_right = reserve(ectx);
	gen_value(ectx, (const struct mptcp_rbs_value *) value->right_operand,
		  temp_right, null_eblock);

	/* Check if right operand is 0 */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_right, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_MOD, temp, temp_right));
	dereserve(ectx, temp_right);

	return true;
}

static bool noinline mptcp_rbs_value_is_null_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_is_null *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *true_eblock;
	int capacity;

	/* Prepare true block */
	true_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(true_eblock, &capacity, EBPF_MOV_IMM(temp, 1));
	add_instr(true_eblock, &capacity, EBPF_JMP_OFF());

	/* Calculate the operand */
	if (!gen_value(ectx, (const struct mptcp_rbs_value *) value->operand,
		       temp, true_eblock)) {
		mptcp_rbs_ebpf_block_free(true_eblock);
		true_eblock = NULL;
	}

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	if (true_eblock)
		true_eblock->next = ectx->eblock->next;
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	return false;
}

static bool noinline mptcp_rbs_value_is_not_null_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_is_not_null *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *false_eblock;
	int capacity;

	/* Prepare false block */
	false_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(false_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
	add_instr(false_eblock, &capacity, EBPF_JMP_OFF());

	/* Calculate the operand */
	if (!gen_value(ectx, (const struct mptcp_rbs_value *) value->operand,
		       temp, false_eblock)) {
		mptcp_rbs_ebpf_block_free(false_eblock);
		false_eblock = NULL;
	}

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	if (false_eblock)
		false_eblock->next = ectx->eblock->next;
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	return false;
}

static bool noinline mptcp_rbs_value_reg_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_reg *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(unsigned int)),
				    temp, REGS_TMP,
				    sizeof(unsigned int) * value->reg_number));

	return false;
}

static bool noinline mptcp_rbs_value_sbf_list_next_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_next *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp,
	    null_eblock, &BLOCK_INFO(ectx->block)->break_eblock,
	    &BLOCK_INFO(ectx->block)->cont_eblock,
	    &BLOCK_INFO(ectx->block)->reserved_temps_map);

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_skb_list_next_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_next *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp,
	    null_eblock, &BLOCK_INFO(ectx->block)->break_eblock,
	    &BLOCK_INFO(ectx->block)->cont_eblock,
	    &BLOCK_INFO(ectx->block)->reserved_temps_map);

	return null_eblock_used;
}

/*
 * Q sockbuffer list value
 */

static bool noinline mptcp_rbs_value_q_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_q *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	return false;
}

static bool noinline mptcp_rbs_value_q_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_q *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(ectx,
		       EBPF_CALL(ebpf_q_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(*cont_eblock, &capacity,
		  EBPF_CALL(ebpf_q_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (skb) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = 0;
	return false;
}

/*
 * QU sockbuffer list value
 */

static bool noinline mptcp_rbs_value_qu_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_qu *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	return false;
}

static bool noinline mptcp_rbs_value_qu_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_qu *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_qu_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(*cont_eblock, &capacity,
		  EBPF_CALL(ebpf_qu_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (skb) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = 0;
	return false;
}

/*
 * RQ sockbuffer list value
 */

static bool noinline mptcp_rbs_value_rq_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_rq *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	return false;
}

static bool noinline mptcp_rbs_value_rq_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_rq *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_rq_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(*cont_eblock, &capacity,
		  EBPF_CALL(ebpf_rq_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (skb) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = 0;
	return false;
}

/*
 * SUBFLOWS subflow list value
 */

static bool noinline mptcp_rbs_value_subflows_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_subflows *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	/* This function is only used to determine if the list is NULL */
	return false;
}

static bool noinline mptcp_rbs_value_subflows_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_subflows *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	int capacity;
	struct mptcp_rbs_ebpf_block *start_eblock;

	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(ectx, EBPF_CALL(ebpf_subflows_next, CTX_TMP, temp, -1,
				       -1, -1, temp));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	/* Prepare start block */
	start_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare break block */
	*break_eblock =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Prepare continue block */
	*cont_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(
	    *cont_eblock, &capacity,
	    EBPF_CALL(ebpf_subflows_next, CTX_TMP, temp, -1, -1, -1, temp));
	add_instr(*cont_eblock, &capacity, EBPF_JMP_OFF());
	(*cont_eblock)->next = start_eblock;

	/* while (sbf) { */
	ectx->eblock->next = start_eblock;
	ectx->eblock = start_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock->next_else = *break_eblock;

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	*reserved_temps_map = 0;
	return false;
}

/*
 * CURRENT_TIME_MS integer value
 */

static bool noinline mptcp_rbs_value_current_time_ms_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_current_time_ms *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_ktime_get_raw_ms, -1, -1, -1, -1, -1, temp));

	return false;
}

/*
 * RANDOM integer value
 */

static bool noinline mptcp_rbs_value_random_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_random *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	add_instr_ectx(ectx, EBPF_CALL(ebpf_random, -1, -1, -1, -1, -1, temp));

	return false;
}

/*
 * <subflow>.RTT integer value
 */

static bool noinline mptcp_rbs_value_sbf_rtt_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_rtt *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, srtt_us)));

	return null_eblock_used;
}

/*
 * <subflow>.RTT_VAR integer value
 */

static bool noinline mptcp_rbs_value_sbf_rtt_var_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_rtt_var *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, rttvar_us)));

	return null_eblock_used;
}

/*
 * <subflow>.RTT_MS integer value
 */
static bool noinline mptcp_rbs_value_sbf_rtt_ms_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_rtt_ms *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx, EBPF_CALL(ebpf_rtt_ms, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow>.QUEUED integer value
 */
static bool noinline mptcp_rbs_value_sbf_queued_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_queued *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx, EBPF_CALL(ebpf_queued, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow>.USER integer value
 */

static bool noinline mptcp_rbs_value_sbf_user_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_user *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx, EBPF_CALL(ebpf_sbf_user, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow>.IS_BACKUP boolean value
 */

static bool noinline mptcp_rbs_value_sbf_is_backup_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_is_backup *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	struct mptcp_tcp_sock bitfields;
	int val;
	int shift;
	int shift2;
	int temp2;

	/* We need to find a shift amount to access the low_prio and
	 * rcv_low_prio bit fields
	 */
	memset(&bitfields, 0, sizeof(struct mptcp_tcp_sock));
	bitfields.low_prio = 1;
	bitfields.rcv_low_prio = 1;
	val = *(&bitfields.map_data_len + 1);
	shift = 0;
	while (!(val & 1)) {
		val >>= 1;
		++shift;
	}
	val >>= 1;
	shift2 = shift + 1;
	while (!(val & 1)) {
		val >>= 1;
		++shift2;
	}

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct mptcp_tcp_sock *)),
			 temp, temp, offsetof(struct tcp_sock, mptcp)));
	add_instr_ectx(
	    ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u16)), temp, temp,
			       offsetof(struct mptcp_tcp_sock, map_data_len) +
				   sizeof(u16)));
	temp2 = reserve(ectx);
	add_instr_ectx(ectx, EBPF_MOV_REG(temp2, temp));
	if (shift)
		add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_RSH, temp, shift));
	if (shift2)
		add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_RSH, temp2, shift2));

	add_instr_ectx(ectx, EBPF_ALU_REG(BPF_OR, temp, temp2));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_AND, temp, 1));
	dereserve(ectx, temp2);

	return null_eblock_used;
}

/*
 * <subflow>.CWND integer value
 */

static bool noinline mptcp_rbs_value_sbf_cwnd_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_cwnd *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, snd_cwnd)));

	return null_eblock_used;
}

/*
 * <subflow>.SKBS_IN_FLIGHT integer value
 */

static bool noinline mptcp_rbs_value_sbf_skbs_in_flight_gen(
    struct ebpf_ctx *ectx,
    const struct mptcp_rbs_value_sbf_skbs_in_flight *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, packets_out)));

	return null_eblock_used;
}

/*
 * <subflow>.LOST_SKBS integer value
 */

static bool noinline mptcp_rbs_value_sbf_lost_skbs_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_lost_skbs *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, lost_out)));

	return null_eblock_used;
}

/*
 * <subflow>.HAS_WINDOW_FOR boolean value
 */

static bool noinline mptcp_rbs_value_sbf_has_window_for_gen(
    struct ebpf_ctx *ectx,
    const struct mptcp_rbs_value_sbf_has_window_for *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_skb;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);
	temp_skb = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb,
		      temp_skb, null_eblock) ||
	    null_eblock_used;
	add_instr_ectx(ectx, EBPF_CALL(ebpf_has_window_for, CTX_TMP, temp,
				       temp_skb, -1, -1, temp));
	dereserve(ectx, temp_skb);

	return null_eblock_used;
}

/*
 * <subflow>.ID integer value
 */

static bool noinline mptcp_rbs_value_sbf_id_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_id *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct mptcp_tcp_sock *)),
			 temp, temp, offsetof(struct tcp_sock, mptcp)));
	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u8)), temp, temp,
				    offsetof(struct mptcp_tcp_sock, sbf_id)));

	return null_eblock_used;
}

/*
 * <subflow>.DELAY_IN integer value
 */

static bool noinline mptcp_rbs_value_sbf_delay_in_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_delay_in *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct mptcp_tcp_sock *)),
			 temp, temp, offsetof(struct tcp_sock, mptcp)));
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
			 offsetof(struct mptcp_tcp_sock, mptcp_sched) +
			     offsetof(struct mptcp_rbs_sbf_cb, delay_in)));

	return null_eblock_used;
}

/*
 * <subflow>.DELAY_OUT integer value
 */

static bool noinline mptcp_rbs_value_sbf_delay_out_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_delay_out *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct mptcp_tcp_sock *)),
			 temp, temp, offsetof(struct tcp_sock, mptcp)));
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
			 offsetof(struct mptcp_tcp_sock, mptcp_sched) +
			     offsetof(struct mptcp_rbs_sbf_cb, delay_out)));

	return null_eblock_used;
}

/*
 * <subflow>.BW_OUT_ACK integer value
 */

static bool noinline mptcp_rbs_value_sbf_bw_out_ack_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_bw_out_ack *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_CALL(ebpf_bw_out_ack, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow>.BW_OUT_SEND integer value
 */

static bool noinline mptcp_rbs_value_sbf_bw_out_send_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_bw_out_send *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_CALL(ebpf_bw_out_send, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow>.SSTHRESH integer value
 */

static bool noinline mptcp_rbs_value_sbf_ssthresh_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_ssthresh *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx,
		       EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
				    offsetof(struct tcp_sock, snd_ssthresh)));

	return null_eblock_used;
}

/*
 * <subflow>.THROTTLED boolean value
 */

static bool noinline mptcp_rbs_value_sbf_throttled_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_throttled *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(unsigned long)), temp,
			       temp, offsetof(struct tcp_sock, tsq_flags)));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_RSH, temp, TSQ_THROTTLED));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_AND, temp, 1));

	return null_eblock_used;
}

/*
 * <subflow>.LOSSY boolean value
 */

static bool noinline mptcp_rbs_value_sbf_lossy_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_lossy *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf, temp,
		      null_eblock);

	add_instr_ectx(ectx, EBPF_CALL(ebpf_lossy, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <subflow list>.EMPTY boolean value
 */

static bool noinline mptcp_rbs_value_sbf_list_empty_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_empty *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_sbf;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	/* empty = true; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 1));

	temp_sbf = reserve(ectx);
	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp_sbf,
	    null_eblock, &break_eblock, &cont_eblock, &reserved_temps_map);

	/* empty = false; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = break_eblock;

	mptcp_rbs_ebpf_block_free(cont_eblock);

	dereserve(ectx, temp_sbf);
	dereserve_all(ectx, reserved_temps_map);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

/*
 * <subflow list>.FILTER subflow list value
 */

static bool noinline mptcp_rbs_value_sbf_list_filter_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_filter *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->list, temp,
		      null_eblock);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->cond, temp,
		      null_eblock) ||
	    null_eblock_used;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_sbf_list_filter_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_filter *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	bool null_eblock_used;
	int temp_t;
	struct filter_var var;
	struct mptcp_rbs_ebpf_block *cont_eblock2;
	int capacity;

	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp,
	    null_eblock, break_eblock, cont_eblock, reserved_temps_map);

	/* if (cond) */
	var.progress = &value->cur;
	var.temp = temp;
	PUSH_FILTER_VAR(&ectx->filter_var_list, &var);
	temp_t = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->cond,
		      temp_t, null_eblock) ||
	    null_eblock_used;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_t, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_t);
	POP_FILTER_VAR(&ectx->filter_var_list);
	ectx->eblock->next_else = *cont_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	/* Create extra continue block because they value above might free the
	 * continue block with the assumption that it is not used. But actually
	 * it is used
	 */
	cont_eblock2 = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(cont_eblock2, &capacity, EBPF_JMP_OFF());
	cont_eblock2->next = *cont_eblock;
	*cont_eblock = cont_eblock2;

	return null_eblock_used;
}

/*
 * Special value holding the actual subflow for FILTER subflow list value
 */

static bool noinline mptcp_rbs_value_sbf_list_filter_sbf_gen(
    struct ebpf_ctx *ectx,
    const struct mptcp_rbs_value_sbf_list_filter_sbf *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct filter_var *var;

	FOREACH_FILTER_VAR(&ectx->filter_var_list, var, {
		if (var->progress == value->cur) {
			add_instr_ectx(ectx, EBPF_MOV_REG(temp, var->temp));
			return false;
		}
	});

	/* Not found */
	BUG_ON(true);
	return false;
}

/*
 * <subflow list>.MAX subflow value
 */

static bool noinline mptcp_rbs_value_sbf_list_max_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_max *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	int temp_sbf;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;
	struct filter_var var;
	int temp_max;
	int temp_t;

	/* temp_max = -1; temp = NULL; */
	temp_max = reserve(ectx);
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp_max, -1));
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));

	temp_sbf = reserve(ectx);
	gen_list_value(ectx, (const struct mptcp_rbs_value *) value->list,
		       temp_sbf, null_eblock, &break_eblock, &cont_eblock,
		       &reserved_temps_map);

	/* if (temp_max < item) */
	var.progress = &value->cur;
	var.temp = temp_sbf;
	temp_t = reserve(ectx);
	PUSH_FILTER_VAR(&ectx->filter_var_list, &var);
	gen_value(ectx, (const struct mptcp_rbs_value *) value->cond, temp_t,
		  null_eblock);
	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JSGE, temp_max, temp_t));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	POP_FILTER_VAR(&ectx->filter_var_list);
	ectx->eblock->next_else = cont_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_MOV_REG(temp_max, temp_t));
	add_instr_ectx(ectx, EBPF_MOV_REG(temp, temp_sbf));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;
	dereserve(ectx, temp_t);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	/* Check if list was empty */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	dereserve(ectx, temp_sbf);
	dereserve(ectx, temp_max);
	dereserve_all(ectx, reserved_temps_map);

	return true;
}

/*
 * <subflow list>.MIN subflow value
 */

static bool noinline mptcp_rbs_value_sbf_list_min_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_min *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	int temp_sbf;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;
	struct filter_var var;
	int temp_min;
	int temp_t;

	/* temp_min = 0x100000000; temp = NULL; */
	temp_min = reserve(ectx);
	add_instr_ectx(
	    ectx,
	    EBPF_RAW_INSTR(((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
					      .dst_reg = temp_min,
					      .src_reg = 0,
					      .off = 0,
					      .imm = 0 }),
			   -1, -1, -1, -1, -1, temp_min));
	add_instr_ectx(ectx, EBPF_RAW_INSTR(((struct bpf_insn){.code = 0,
							       .dst_reg = 0,
							       .src_reg = 0,
							       .off = 0,
							       .imm = 1 }),
					    -1, -1, -1, -1, -1, -1));
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));

	temp_sbf = reserve(ectx);
	gen_list_value(ectx, (const struct mptcp_rbs_value *) value->list,
		       temp_sbf, null_eblock, &break_eblock, &cont_eblock,
		       &reserved_temps_map);

	/* if (temp_min > item) */
	var.progress = &value->cur;
	var.temp = temp_sbf;
	temp_t = reserve(ectx);
	PUSH_FILTER_VAR(&ectx->filter_var_list, &var);
	gen_value(ectx, (const struct mptcp_rbs_value *) value->cond, temp_t,
		  null_eblock);
	add_instr_ectx(ectx, EBPF_JMP_REG(BPF_JGE, temp_t, temp_min));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	POP_FILTER_VAR(&ectx->filter_var_list);
	ectx->eblock->next_else = cont_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_MOV_REG(temp_min, temp_t));
	add_instr_ectx(ectx, EBPF_MOV_REG(temp, temp_sbf));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;
	dereserve(ectx, temp_t);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	/* Check if list was empty */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	dereserve(ectx, temp_sbf);
	dereserve(ectx, temp_min);
	dereserve_all(ectx, reserved_temps_map);

	return true;
}

/*
 * <subflow list>.GET subflow value
 */

static bool noinline mptcp_rbs_value_sbf_list_get_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_get *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	int temp_i;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	temp_i = reserve(ectx);
	gen_value(ectx, (const struct mptcp_rbs_value *) value->index, temp_i,
		  null_eblock);

	gen_list_value(ectx, (const struct mptcp_rbs_value *) value->list, temp,
		       null_eblock, &break_eblock, &cont_eblock,
		       &reserved_temps_map);

	/* if (i == 0) */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_i, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = break_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	/* --i; */
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_SUB, temp_i, 1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	/* Check if index was found */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	dereserve(ectx, temp_i);
	dereserve_all(ectx, reserved_temps_map);

	return true;
}

/*
 * <subflow list>.COUNT integer value
 */

static bool noinline mptcp_rbs_value_sbf_list_count_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_count *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_sbf;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	/* i = 0; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));

	temp_sbf = reserve(ectx);
	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp_sbf,
	    null_eblock, &break_eblock, &cont_eblock, &reserved_temps_map);

	/* ++i; */
	add_instr_ectx(ectx, EBPF_ALU32_IMM(BPF_ADD, temp, 1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;

	dereserve(ectx, temp_sbf);
	dereserve_all(ectx, reserved_temps_map);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

/*
 * <subflow list>.SUM integer value
 */

static bool noinline mptcp_rbs_value_sbf_list_sum_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_sbf_list_sum *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_sbf;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;
	struct filter_var var;
	int temp_t;

	/* sum = 0; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));

	temp_sbf = reserve(ectx);
	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp_sbf,
	    null_eblock, &break_eblock, &cont_eblock, &reserved_temps_map);

	/* sum += item; */
	var.progress = &value->cur;
	var.temp = temp_sbf;
	PUSH_FILTER_VAR(&ectx->filter_var_list, &var);
	temp_t = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->cond,
		      temp_t, null_eblock) ||
	    null_eblock_used;
	add_instr_ectx(ectx, EBPF_ALU32_REG(BPF_ADD, temp, temp_t));
	dereserve(ectx, temp_t);
	POP_FILTER_VAR(&ectx->filter_var_list);

	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;

	dereserve(ectx, temp_sbf);
	dereserve_all(ectx, reserved_temps_map);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

/*
 * <sockbuffer>.SENT_ON boolean value
 */

static bool noinline mptcp_rbs_value_skb_sent_on_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_sent_on *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_sbf;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);
	temp_sbf = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->sbf,
		      temp_sbf, null_eblock) ||
	    null_eblock_used;

	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(struct mptcp_tcp_sock *)),
			 temp_sbf, temp_sbf, offsetof(struct tcp_sock, mptcp)));
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u8)), temp_sbf, temp_sbf,
			 offsetof(struct mptcp_tcp_sock, path_index)));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_SUB, temp_sbf, 1));

	add_instr_ectx(
	    ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u32)), temp, temp,
			       offsetof(struct sk_buff, cb) +
				   offsetof(struct tcp_skb_cb, path_mask)));
	add_instr_ectx(ectx, EBPF_ALU_REG(BPF_RSH, temp, temp_sbf));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_AND, temp, 1));
	dereserve(ectx, temp_sbf);

	return null_eblock_used;
}

/*
 * <sockbuffer>.SENT_ON_ALL boolean value
 */

static bool noinline mptcp_rbs_value_skb_sent_on_all_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_sent_on_all *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_sent_on_all, CTX_TMP, temp, -1, -1, -1, temp));

	return null_eblock_used;
}


/*
 * <sockbuffer>.LENGTH integer value
 */

static bool noinline mptcp_rbs_value_skb_length_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_length *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_skb_length, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}


/*
 * <sockbuffer>.SKB_SEQ integer value
 */

static bool noinline mptcp_rbs_value_skb_seq_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_seq *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_skb_seq, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}


/*
 * <sockbuffer>.PSH boolean value
 */

static bool noinline mptcp_rbs_value_skb_psh_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_psh *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_skb_psh, temp, -1, -1, -1, -1, temp));

	return null_eblock_used;
}

/*
 * <sockbuffer>.USER integer value
 */

static bool noinline mptcp_rbs_value_skb_user_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_user *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	union tcp_skb_cb_rbs bitfields;
	int shift;

	/* We need to find a shift amount to access the user bit field */
	bitfields.b = 0;
	bitfields.user = 0x1f;
	shift = 0;
	while (!(bitfields.b & 1)) {
		bitfields.b >>= 1;
		++shift;
	}

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->skb, temp,
		      null_eblock);

	add_instr_ectx(
	    ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(u8)), temp, temp,
			       offsetof(struct sk_buff, cb) +
				   offsetof(struct tcp_skb_cb, mptcp_rbs)));
	if (shift)
		add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_RSH, temp, shift));
	if (shift < 3)
		add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_AND, temp, 0x1f));

	return null_eblock_used;
}

/*
 * <sockbuffer list>.EMPTY boolean value
 */

static bool noinline mptcp_rbs_value_skb_list_empty_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_empty *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_skb;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	/* empty = true; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 1));

	temp_skb = reserve(ectx);
	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp_skb,
	    null_eblock, &break_eblock, &cont_eblock, &reserved_temps_map);

	/* empty = false; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = break_eblock;

	mptcp_rbs_ebpf_block_free(cont_eblock);

	dereserve(ectx, temp_skb);
	dereserve_all(ectx, reserved_temps_map);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

/*
 * <sockbuffer list>.POP() sockbuffer value
 */

static bool noinline mptcp_rbs_value_skb_list_pop_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_pop *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;
	int temp_underlying_queue_kind;

	gen_list_value(ectx, (const struct mptcp_rbs_value *) value->list, temp,
		       null_eblock, &break_eblock, &cont_eblock,
		       &reserved_temps_map);
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = break_eblock;
	mptcp_rbs_ebpf_block_free(cont_eblock);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	/* Check if list was empty */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	dereserve_all(ectx, reserved_temps_map);

	temp_underlying_queue_kind = reserve(ectx);
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp_underlying_queue_kind,
					  value->list->underlying_queue_kind));
	add_instr_ectx(ectx,
		       EBPF_CALL(ebpf_skb_list_pop, CTX_TMP, temp,
				 temp_underlying_queue_kind, -1, -1, temp));
	dereserve(ectx, temp_underlying_queue_kind);
	return true;
}

/*
 * <sockbuffer list>.FILTER() sockbuffer list value
 */

static bool noinline mptcp_rbs_value_skb_list_filter_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_filter *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;

	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->list, temp,
		      null_eblock);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->cond, temp,
		      null_eblock) ||
	    null_eblock_used;

	return null_eblock_used;
}

static bool noinline mptcp_rbs_value_skb_list_filter_gen2(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_filter *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock,
    struct mptcp_rbs_ebpf_block **break_eblock,
    struct mptcp_rbs_ebpf_block **cont_eblock, u64 *reserved_temps_map)
{
	bool null_eblock_used;
	int temp_t;
	struct filter_var var;
	struct mptcp_rbs_ebpf_block *cont_eblock2;
	int capacity;

	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp,
	    null_eblock, break_eblock, cont_eblock, reserved_temps_map);

	/* if (cond) */
	var.progress = &value->progress;
	var.temp = temp;
	PUSH_FILTER_VAR(&ectx->filter_var_list, &var);
	temp_t = reserve(ectx);
	null_eblock_used =
	    gen_value(ectx, (const struct mptcp_rbs_value *) value->cond,
		      temp_t, null_eblock) ||
	    null_eblock_used;
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp_t, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_t);
	POP_FILTER_VAR(&ectx->filter_var_list);
	ectx->eblock->next_else = *cont_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	/* Create extra continue block because they value above might free the
	 * continue block with the assumption that it is not used. But actually
	 * it is used
	 */
	cont_eblock2 = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(cont_eblock2, &capacity, EBPF_JMP_OFF());
	cont_eblock2->next = *cont_eblock;
	*cont_eblock = cont_eblock2;

	return null_eblock_used;
}

/*
 * Special value holding the actual sockbuffer for FILTER sockbuffer list value
 */

static bool noinline mptcp_rbs_value_skb_list_filter_skb_gen(
    struct ebpf_ctx *ectx,
    const struct mptcp_rbs_value_skb_list_filter_skb *value, int temp,
    struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct filter_var *var;

	FOREACH_FILTER_VAR(&ectx->filter_var_list, var, {
		if (var->progress == value->progress) {
			add_instr_ectx(ectx, EBPF_MOV_REG(temp, var->temp));
			return false;
		}
	});

	/* Not found */
	BUG_ON(true);
	return false;
}

/*
 * <sockbuffer list>.COUNT integer value
 */

static bool noinline mptcp_rbs_value_skb_list_count_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_count *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	bool null_eblock_used;
	int temp_skb;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	/* i = 0; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp, 0));

	temp_skb = reserve(ectx);
	null_eblock_used = gen_list_value(
	    ectx, (const struct mptcp_rbs_value *) value->list, temp_skb,
	    null_eblock, &break_eblock, &cont_eblock, &reserved_temps_map);

	/* ++i; */
	add_instr_ectx(ectx, EBPF_ALU32_IMM(BPF_ADD, temp, 1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;

	dereserve(ectx, temp_skb);
	dereserve_all(ectx, reserved_temps_map);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	return null_eblock_used;
}

/*
 * <sockbuffer list>.TOP sockbuffer value
 */

static bool noinline mptcp_rbs_value_skb_list_top_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_top *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;

	gen_list_value(ectx, (const struct mptcp_rbs_value *) value->list, temp,
		       null_eblock, &break_eblock, &cont_eblock,
		       &reserved_temps_map);
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = break_eblock;
	mptcp_rbs_ebpf_block_free(cont_eblock);

	ectx->eblock = break_eblock;
	ectx->capacity = 0;

	/* Check if list was empty */
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next_else = null_eblock;
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;

	dereserve_all(ectx, reserved_temps_map);

	return true;
}

/*
 * <sockbuffer list>.GET sockbuffer value
 */

static bool noinline mptcp_rbs_value_skb_list_get_gen(
    struct ebpf_ctx *ectx, const struct mptcp_rbs_value_skb_list_get *value,
    int temp, struct mptcp_rbs_ebpf_block *null_eblock)
{
	printk("%s is not implemented yet for eBPF.", __func__);
	BUG_ON(true);
	return true;
}

/**
 * Generates the eBPF instructions for a value in the current block. For values
 * returning lists this function can only check for NULL
 * @ectx: The generation context
 * @value: The CFG value
 * @temp: Temporary where the value should be stored
 * @null_eblock: The eBPF block the code should jump to if this value is NULL
 * @return: true if the null_eblock was referenced
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
static bool gen_value(struct ebpf_ctx *ectx,
		      const struct mptcp_rbs_value *value, int temp,
		      struct mptcp_rbs_ebpf_block *null_eblock)
{
#define APPLY_GEN_VALUE(ENUM, STRUCT)                                          \
	case ENUM:                                                             \
		return STRUCT##_gen(ectx, (const struct STRUCT *) value, temp, \
				    null_eblock);

	switch (value->kind) {
	case VALUE_KIND_CONSTINT:
		return mptcp_rbs_value_constint_gen(
		    ectx, (const struct mptcp_rbs_value_constint *) value, temp,
		    null_eblock);
	case VALUE_KIND_CONSTSTRING:
		return mptcp_rbs_value_conststring_gen(
		    ectx, (const struct mptcp_rbs_value_conststring *) value,
		    temp, null_eblock);
	case VALUE_KIND_NULL:
		return mptcp_rbs_value_null_gen(
		    ectx, (const struct mptcp_rbs_value_null *) value, temp,
		    null_eblock);
	case VALUE_KIND_BOOL_VAR:
		return mptcp_rbs_value_bool_var_gen(
		    ectx, (const struct mptcp_rbs_value_bool_var *) value, temp,
		    null_eblock);
	case VALUE_KIND_INT_VAR:
		return mptcp_rbs_value_int_var_gen(
		    ectx, (const struct mptcp_rbs_value_int_var *) value, temp,
		    null_eblock);
	case VALUE_KIND_STRING_VAR:
		return mptcp_rbs_value_string_var_gen(
		    ectx, (const struct mptcp_rbs_value_string_var *) value,
		    temp, null_eblock);
	case VALUE_KIND_SBF_VAR:
		return mptcp_rbs_value_sbf_var_gen(
		    ectx, (const struct mptcp_rbs_value_sbf_var *) value, temp,
		    null_eblock);
	case VALUE_KIND_SBFLIST_VAR:
		return mptcp_rbs_value_sbf_list_var_gen(
		    ectx, (const struct mptcp_rbs_value_sbf_list_var *) value,
		    temp, null_eblock);
	case VALUE_KIND_SKB_VAR:
		return mptcp_rbs_value_skb_var_gen(
		    ectx, (const struct mptcp_rbs_value_skb_var *) value, temp,
		    null_eblock);
	case VALUE_KIND_SKBLIST_VAR:
		return mptcp_rbs_value_skb_list_var_gen(
		    ectx, (const struct mptcp_rbs_value_skb_list_var *) value,
		    temp, null_eblock);
	case VALUE_KIND_NOT:
		return mptcp_rbs_value_not_gen(
		    ectx, (const struct mptcp_rbs_value_not *) value, temp,
		    null_eblock);
	case VALUE_KIND_EQUAL:
		return mptcp_rbs_value_equal_gen(
		    ectx, (const struct mptcp_rbs_value_equal *) value, temp,
		    null_eblock);
	case VALUE_KIND_UNEQUAL:
		return mptcp_rbs_value_unequal_gen(
		    ectx, (const struct mptcp_rbs_value_unequal *) value, temp,
		    null_eblock);
	case VALUE_KIND_LESS:
		return mptcp_rbs_value_less_gen(
		    ectx, (const struct mptcp_rbs_value_less *) value, temp,
		    null_eblock);
	case VALUE_KIND_LESS_EQUAL:
		return mptcp_rbs_value_less_equal_gen(
		    ectx, (const struct mptcp_rbs_value_less_equal *) value,
		    temp, null_eblock);
	case VALUE_KIND_GREATER:
		return mptcp_rbs_value_greater_gen(
		    ectx, (const struct mptcp_rbs_value_greater *) value, temp,
		    null_eblock);
	case VALUE_KIND_GREATER_EQUAL:
		return mptcp_rbs_value_greater_equal_gen(
		    ectx, (const struct mptcp_rbs_value_greater_equal *) value,
		    temp, null_eblock);
	case VALUE_KIND_AND:
		return mptcp_rbs_value_and_gen(
		    ectx, (const struct mptcp_rbs_value_and *) value, temp,
		    null_eblock);
	case VALUE_KIND_OR:
		return mptcp_rbs_value_or_gen(
		    ectx, (const struct mptcp_rbs_value_or *) value, temp,
		    null_eblock);
	case VALUE_KIND_ADD:
		return mptcp_rbs_value_add_gen(
		    ectx, (const struct mptcp_rbs_value_add *) value, temp,
		    null_eblock);
	case VALUE_KIND_SUBTRACT:
		return mptcp_rbs_value_subtract_gen(
		    ectx, (const struct mptcp_rbs_value_subtract *) value, temp,
		    null_eblock);
	case VALUE_KIND_MULTIPLY:
		return mptcp_rbs_value_multiply_gen(
		    ectx, (const struct mptcp_rbs_value_multiply *) value, temp,
		    null_eblock);
	case VALUE_KIND_DIVIDE:
		return mptcp_rbs_value_divide_gen(
		    ectx, (const struct mptcp_rbs_value_divide *) value, temp,
		    null_eblock);
	case VALUE_KIND_REMAINDER:
		return mptcp_rbs_value_remainder_gen(
		    ectx, (const struct mptcp_rbs_value_remainder *) value,
		    temp, null_eblock);
	case VALUE_KIND_IS_NULL:
		return mptcp_rbs_value_is_null_gen(
		    ectx, (const struct mptcp_rbs_value_is_null *) value, temp,
		    null_eblock);
	case VALUE_KIND_IS_NOT_NULL:
		return mptcp_rbs_value_is_not_null_gen(
		    ectx, (const struct mptcp_rbs_value_is_not_null *) value,
		    temp, null_eblock);
	case VALUE_KIND_REG:
		return mptcp_rbs_value_reg_gen(
		    ectx, (const struct mptcp_rbs_value_reg *) value, temp,
		    null_eblock);
	case VALUE_KIND_SBFLIST_NEXT:
		return mptcp_rbs_value_sbf_list_next_gen(
		    ectx, (const struct mptcp_rbs_value_sbf_list_next *) value,
		    temp, null_eblock);
	case VALUE_KIND_SKBLIST_NEXT:
		return mptcp_rbs_value_skb_list_next_gen(
		    ectx, (const struct mptcp_rbs_value_skb_list_next *) value,
		    temp, null_eblock);

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE) APPLY_GEN_VALUE(ENUM, STRUCT)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GEN_VALUE(ENUM, STRUCT)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GEN_VALUE(ENUM, STRUCT)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GEN_VALUE(ENUM, STRUCT)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GEN_VALUE(ENUM, STRUCT)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST
	}

	return false;
}
#pragma GCC diagnostic pop

/**
 * Generates the eBPF instructions for a list value in the current block
 * @ectx: The generation context
 * @value: The CFG value
 * @temp: Temporary where the item should be stored
 * @null_eblock: The eBPF block the code should jump to if this value is NULL
 * @break_eblock: Here will be stored the eBPF block that can be jumped to to
 * break from the loop
 * @cont_eblock: The eBPF block the code can use to continue to the next loop
 * iteration. Note that this block should directly jump to the start block of
 * the loop without any blocks inbetween
 * @reserved_temps: Number of temporaries that were reserved for the loop
 * @return: true if the null_eblock was referenced
 */
static bool gen_list_value(struct ebpf_ctx *ectx,
			   const struct mptcp_rbs_value *value, int temp,
			   struct mptcp_rbs_ebpf_block *null_eblock,
			   struct mptcp_rbs_ebpf_block **break_eblock,
			   struct mptcp_rbs_ebpf_block **cont_eblock,
			   u64 *reserved_temps_map)
{
#define APPLY_GEN2_VALUE_TYPE_KIND_BOOL(ENUM, STRUCT)
#define APPLY_GEN2_VALUE_TYPE_KIND_INT(ENUM, STRUCT)
#define APPLY_GEN2_VALUE_TYPE_KIND_STRING(ENUM, STRUCT)
#define APPLY_GEN2_VALUE_TYPE_KIND_SBF(ENUM, STRUCT)
#define APPLY_GEN2_VALUE_TYPE_KIND_SBFLIST(ENUM, STRUCT)                       \
	case ENUM:                                                             \
		return STRUCT##_gen2(ectx, (const struct STRUCT *) value,      \
				     temp, null_eblock, break_eblock,          \
				     cont_eblock, reserved_temps_map);
#define APPLY_GEN2_VALUE_TYPE_KIND_SKB(ENUM, STRUCT)
#define APPLY_GEN2_VALUE_TYPE_KIND_SKBLIST(ENUM, STRUCT)                       \
	APPLY_GEN2_VALUE_TYPE_KIND_SBFLIST(ENUM, STRUCT)
#define APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GEN2_VALUE_##RETURNTYPE(ENUM, STRUCT)

	switch (value->kind) {
	case VALUE_KIND_SBFLIST_VAR:
		return mptcp_rbs_value_sbf_list_var_gen2(
		    ectx, (const struct mptcp_rbs_value_sbf_list_var *) value,
		    temp, null_eblock, break_eblock, cont_eblock,
		    reserved_temps_map);
	case VALUE_KIND_SKBLIST_VAR:
		return mptcp_rbs_value_skb_list_var_gen2(
		    ectx, (const struct mptcp_rbs_value_skb_list_var *) value,
		    temp, null_eblock, break_eblock, cont_eblock,
		    reserved_temps_map);
#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GEN2_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST
	default: {
		BUG_ON(true);
		return false;
	}
	}
}

static void gen_smt_drop(struct ebpf_ctx *ectx,
			 const struct mptcp_rbs_smt_drop *smt)
{
	struct mptcp_rbs_ebpf_block *eblock;
	int temp_skb;
	int temp_reinject;

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	temp_skb = reserve(ectx);
	gen_value(ectx, (struct mptcp_rbs_value *) smt->skb, temp_skb, eblock);

	temp_reinject = reserve(ectx);
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp_reinject, smt->skb->reinject));
	add_instr_ectx(ectx, EBPF_CALL(ebpf_add_drop, CTX_TMP, temp_skb,
				       temp_reinject, -1, -1, -1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_reinject);
	dereserve(ectx, temp_skb);

	ectx->eblock->next = eblock;
	ectx->eblock = eblock;
	ectx->capacity = 0;
}

static void gen_smt_print(struct ebpf_ctx *ectx,
			  const struct mptcp_rbs_smt_print *smt)
{
	struct mptcp_rbs_ebpf_block *eblock;
	int temp_str;
	int temp_arg = -1;

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	temp_str = reserve(ectx);
	gen_value(ectx, (struct mptcp_rbs_value *) smt->msg, temp_str, eblock);
	if (smt->arg) {
		temp_arg = reserve(ectx);
		gen_value(ectx, smt->arg, temp_arg, eblock);
	}
	add_instr_ectx(
	    ectx, EBPF_CALL(ebpf_printk, temp_str, temp_arg, -1, -1, -1, -1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	if (temp_arg != -1)
		dereserve(ectx, temp_arg);
	dereserve(ectx, temp_str);

	ectx->eblock->next = eblock;
	ectx->eblock = eblock;
	ectx->capacity = 0;
}

static void gen_smt_push(struct ebpf_ctx *ectx,
			 const struct mptcp_rbs_smt_push *smt)
{
	struct mptcp_rbs_ebpf_block *eblock;
	int temp_sbf;
	int temp_skb;
	int temp_reinject;

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	temp_sbf = reserve(ectx);
	gen_value(ectx, (struct mptcp_rbs_value *) smt->sbf, temp_sbf, eblock);
	temp_skb = reserve(ectx);
	gen_value(ectx, (struct mptcp_rbs_value *) smt->skb, temp_skb, eblock);

	temp_reinject = reserve(ectx);
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp_reinject, smt->skb->reinject));
	add_instr_ectx(ectx, EBPF_CALL(ebpf_add_push, CTX_TMP, temp_sbf,
				       temp_skb, temp_reinject, -1, -1));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp_reinject);
	dereserve(ectx, temp_skb);
	dereserve(ectx, temp_sbf);

	ectx->eblock->next = eblock;
	ectx->eblock = eblock;
	ectx->capacity = 0;
}

static void gen_smt_set(struct ebpf_ctx *ectx,
			const struct mptcp_rbs_smt_set *smt)
{
	struct mptcp_rbs_ebpf_block *eblock;
	int temp;

	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	add_instr_ectx(
	    ectx,
	    EBPF_ST_MEM(bytes_to_bpf_size(sizeof(bool)), CTX_TMP,
			offsetof(struct mptcp_rbs_eval_ctx, side_effects), 1));
	temp = reserve(ectx);
	gen_value(ectx, (struct mptcp_rbs_value *) smt->value, temp, eblock);

	add_instr_ectx(ectx,
		       EBPF_STX_MEM(bytes_to_bpf_size(sizeof(unsigned int)),
				    REGS_TMP, temp,
				    smt->reg_number * sizeof(unsigned int)));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp);

	ectx->eblock->next = eblock;
	ectx->eblock = eblock;
	ectx->capacity = 0;
}

static void gen_smt_list_var(struct ebpf_ctx *ectx,
			     const struct mptcp_rbs_smt_var *smt)
{
	struct mptcp_rbs_ebpf_block *null_eblock;
	int temp_var;
	int temp_item;
	int temp_cur;
	int temp;
	struct mptcp_rbs_ebpf_block *break_eblock;
	struct mptcp_rbs_ebpf_block *cont_eblock;
	u64 reserved_temps_map;
	struct mptcp_rbs_ebpf_block *call_eblock;
	int capacity;

	temp_var = reserve(ectx);
	temp_item = reserve(ectx);
	temp_cur = reserve(ectx);

	/* Prepare null block */
	null_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(
	    null_eblock, &capacity,
	    EBPF_ST_MEM(bytes_to_bpf_size(sizeof(void *)), VARS_TMP,
			sizeof(struct mptcp_rbs_var) * smt->var_number +
			    offsetof(struct mptcp_rbs_var, sbf_list_value),
			0));
	add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

	/* Get var pointer */
	add_instr_ectx(ectx, EBPF_MOV_REG(temp_var, VARS_TMP));
	add_instr_ectx(
	    ectx, EBPF_ALU_IMM(BPF_ADD, temp_var,
			       sizeof(struct mptcp_rbs_var) * smt->var_number));

	/* cur = NULL; */
	add_instr_ectx(ectx, EBPF_MOV_IMM(temp_cur, 0));
	add_instr_ectx(ectx, EBPF_CALL(ebpf_varlist_expand, temp_var, temp_cur,
				       -1, -1, -1, temp_cur));

	if (gen_list_value(ectx, smt->value, temp_item, null_eblock,
			   &break_eblock, &cont_eblock, &reserved_temps_map))
		null_eblock->next = break_eblock;
	else
		mptcp_rbs_ebpf_block_free(null_eblock);

	/* Check if we have to allocate more space */
	temp = reserve(ectx);
	add_instr_ectx(ectx, EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(void *)),
					  temp, temp_cur, 0));
	add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JNE, temp, 0));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	dereserve(ectx, temp);
	ectx->eblock->next =
	    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);

	/* Fill the call block */
	call_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	capacity = 0;
	add_instr(call_eblock, &capacity,
		  EBPF_CALL(ebpf_varlist_expand, temp_var, temp_cur, -1, -1, -1,
			    temp_cur));
	add_instr(call_eblock, &capacity, EBPF_JMP_OFF());
	call_eblock->next = ectx->eblock->next;
	ectx->eblock->next_else = call_eblock;

	/* *cur = item; ++cur; */
	ectx->eblock = ectx->eblock->next;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_STX_MEM(bytes_to_bpf_size(sizeof(void *)),
					  temp_cur, temp_item, 0));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_ADD, temp_cur, sizeof(void *)));
	add_instr_ectx(ectx, EBPF_JMP_OFF());
	ectx->eblock->next = cont_eblock;

	ectx->eblock = break_eblock;
	ectx->capacity = 0;
	add_instr_ectx(ectx, EBPF_ST_MEM(bytes_to_bpf_size(sizeof(void *)),
					 temp_cur, 0, 0));

	dereserve(ectx, temp_cur);
	dereserve(ectx, temp_item);
	dereserve(ectx, temp_var);
	dereserve_all(ectx, reserved_temps_map);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
static void gen_smt_var(struct ebpf_ctx *ectx,
			const struct mptcp_rbs_smt_var *smt)
{
	enum mptcp_rbs_type_kind type;
	struct mptcp_rbs_ebpf_block *null_eblock;
	int capacity;
	int temp;

	/* var->type = type; */
	type = mptcp_rbs_value_get_type(smt->value->kind);
	add_instr_ectx(
	    ectx, EBPF_ST_MEM(
		      bytes_to_bpf_size(sizeof(enum mptcp_rbs_type_kind)),
		      VARS_TMP, sizeof(struct mptcp_rbs_var) * smt->var_number +
				    offsetof(struct mptcp_rbs_var, type),
		      type));

	/* We do not support lazy evaluation
	 * var->is_lazy = false;
	 */
	add_instr_ectx(
	    ectx, EBPF_ST_MEM(bytes_to_bpf_size(sizeof(bool)), VARS_TMP,
			      sizeof(struct mptcp_rbs_var) * smt->var_number +
				  offsetof(struct mptcp_rbs_var, is_lazy),
			      false));

	switch (type) {
	case TYPE_KIND_NULL:
		break;
	case TYPE_KIND_BOOL: {
		temp = reserve(ectx);

		/* Prepare null block */
		null_eblock =
		    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
		capacity = 0;
		add_instr(null_eblock, &capacity, EBPF_MOV_IMM(temp, -1));
		add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

		if (!gen_value(ectx, smt->value, temp, null_eblock))
			mptcp_rbs_ebpf_block_free(null_eblock);
		else {
			add_instr_ectx(ectx, EBPF_JMP_OFF());
			ectx->eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			null_eblock->next = ectx->eblock->next;
			ectx->eblock = ectx->eblock->next;
			ectx->capacity = 0;
		}

		add_instr_ectx(
		    ectx, EBPF_STX_MEM(
			      bytes_to_bpf_size(sizeof(s32)), VARS_TMP, temp,
			      sizeof(struct mptcp_rbs_var) * smt->var_number +
				  offsetof(struct mptcp_rbs_var, bool_value)));

		dereserve(ectx, temp);
		break;
	}
	case TYPE_KIND_INT: {
		temp = reserve(ectx);

		/* Prepare null block */
		null_eblock =
		    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
		capacity = 0;
		add_instr(null_eblock, &capacity, EBPF_MOV_IMM(temp, -1));
		add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

		if (!gen_value(ectx, smt->value, temp, null_eblock))
			mptcp_rbs_ebpf_block_free(null_eblock);
		else {
			add_instr_ectx(ectx, EBPF_JMP_OFF());
			ectx->eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			null_eblock->next = ectx->eblock->next;
			ectx->eblock = ectx->eblock->next;
			ectx->capacity = 0;
		}

		add_instr_ectx(
		    ectx, EBPF_STX_MEM(
			      bytes_to_bpf_size(sizeof(s64)), VARS_TMP, temp,
			      sizeof(struct mptcp_rbs_var) * smt->var_number +
				  offsetof(struct mptcp_rbs_var, int_value)));

		dereserve(ectx, temp);
		break;
	}
	case TYPE_KIND_STRING: {
		temp = reserve(ectx);

		/* Prepare null block */
		null_eblock =
		    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
		capacity = 0;
		add_instr(null_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
		add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

		if (!gen_value(ectx, smt->value, temp, null_eblock))
			mptcp_rbs_ebpf_block_free(null_eblock);
		else {
			add_instr_ectx(ectx, EBPF_JMP_OFF());
			ectx->eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			null_eblock->next = ectx->eblock->next;
			ectx->eblock = ectx->eblock->next;
			ectx->capacity = 0;
		}

		add_instr_ectx(
		    ectx,
		    EBPF_STX_MEM(
			bytes_to_bpf_size(sizeof(char *)), VARS_TMP, temp,
			sizeof(struct mptcp_rbs_var) * smt->var_number +
			    offsetof(struct mptcp_rbs_var, string_value)));

		dereserve(ectx, temp);
		break;
	}
	case TYPE_KIND_SBF: {
		temp = reserve(ectx);

		/* Prepare null block */
		null_eblock =
		    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
		capacity = 0;
		add_instr(null_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
		add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

		if (!gen_value(ectx, smt->value, temp, null_eblock))
			mptcp_rbs_ebpf_block_free(null_eblock);
		else {
			add_instr_ectx(ectx, EBPF_JMP_OFF());
			ectx->eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			if (smt->value->kind == VALUE_KIND_SBFLIST_NEXT)
				ectx->next_var_null_eblock = null_eblock;
			else
				null_eblock->next = ectx->eblock->next;
			ectx->eblock = ectx->eblock->next;
			ectx->capacity = 0;
		}

		add_instr_ectx(
		    ectx,
		    EBPF_STX_MEM(
			bytes_to_bpf_size(sizeof(struct tcp_sock *)), VARS_TMP,
			temp, sizeof(struct mptcp_rbs_var) * smt->var_number +
				  offsetof(struct mptcp_rbs_var, sbf_value)));

		dereserve(ectx, temp);

		/* Set next_var if the value was a *_NEXT call */
		if (smt->value->kind == VALUE_KIND_SBFLIST_NEXT)
			ectx->next_var = smt->var_number;
		break;
	}
	case TYPE_KIND_SBFLIST:
	case TYPE_KIND_SKBLIST: {
		gen_smt_list_var(ectx, smt);
		break;
	}
	case TYPE_KIND_SKB: {
		temp = reserve(ectx);

		/* Prepare null block */
		null_eblock =
		    kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
		capacity = 0;
		add_instr(null_eblock, &capacity, EBPF_MOV_IMM(temp, 0));
		add_instr(null_eblock, &capacity, EBPF_JMP_OFF());

		if (!gen_value(ectx, smt->value, temp, null_eblock))
			mptcp_rbs_ebpf_block_free(null_eblock);
		else {
			add_instr_ectx(ectx, EBPF_JMP_OFF());
			ectx->eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			if (smt->value->kind == VALUE_KIND_SKBLIST_NEXT)
				ectx->next_var_null_eblock = null_eblock;
			else
				null_eblock->next = ectx->eblock->next;
			ectx->eblock = ectx->eblock->next;
			ectx->capacity = 0;
		}

		add_instr_ectx(
		    ectx,
		    EBPF_STX_MEM(
			bytes_to_bpf_size(sizeof(struct sk_buff *)), VARS_TMP,
			temp, sizeof(struct mptcp_rbs_var) * smt->var_number +
				  offsetof(struct mptcp_rbs_var, skb_value)));
		dereserve(ectx, temp);

		/* Set next_var if the value was a *_NEXT call */
		if (smt->value->kind == VALUE_KIND_SKBLIST_NEXT)
			ectx->next_var = smt->var_number;
		break;
	}
	}
}
#pragma GCC diagnostic pop

/**
 * Generates the eBPF instructions for a statement in the current block
 * @ectx: The generation context
 * @smt: The CFG statement
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
static void gen_smt(struct ebpf_ctx *ectx, const struct mptcp_rbs_smt *smt)
{
	switch (smt->kind) {
	case SMT_KIND_DROP: {
		gen_smt_drop(ectx, (const struct mptcp_rbs_smt_drop *) smt);
		break;
	}
	case SMT_KIND_PRINT: {
		gen_smt_print(ectx, (const struct mptcp_rbs_smt_print *) smt);
		break;
	}
	case SMT_KIND_PUSH: {
		gen_smt_push(ectx, (const struct mptcp_rbs_smt_push *) smt);
		break;
	}
	case SMT_KIND_SET: {
		gen_smt_set(ectx, (const struct mptcp_rbs_smt_set *) smt);
		break;
	}
	case SMT_KIND_VAR: {
		gen_smt_var(ectx, (const struct mptcp_rbs_smt_var *) smt);
		break;
	}
	case SMT_KIND_VOID: {
		/* We do not generate eBPF code for VOID */
		break;
	}
	case SMT_KIND_EBPF: {
		/* Cannot generate eBPF code from eBPF */
		BUG_ON(true);
		break;
	}
	case SMT_KIND_SET_USER: {
		printk("eBPF for set user is not implemented yet\n");
		BUG_ON(true);
		break;
	}
	}
}
#pragma GCC diagnostic pop

static bool path_exists_helper(const struct mptcp_rbs_cfg_block *a,
			       const struct mptcp_rbs_cfg_block *b,
			       struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block;
	FOREACH_BLOCK(list, block, {
		if (a == block)
			return false;
	});
	ADD_BLOCK(list, (struct mptcp_rbs_cfg_block *) a);

	if (a == b)
		return true;
	if (a->next && path_exists_helper(a->next, b, list))
		return true;
	if (a->next_else && path_exists_helper(a->next_else, b, list))
		return true;

	return false;
}

static bool path_exists(const struct mptcp_rbs_cfg_block *a,
			const struct mptcp_rbs_cfg_block *b)
{
	struct mptcp_rbs_cfg_block_list list;
	bool found;

	INIT_BLOCK_LIST(&list);
	found = path_exists_helper(a, b, &list);
	FREE_BLOCK_LIST(&list);

	return found;
}

/**
 * Generates the eBPF instructions for a CFG block and its successors
 * @ectx: The generation context
 * @block: The CFG block
 * @list: List with CFG blocks that were already processed
 * @return: The generated eBPF block
 */
static struct mptcp_rbs_ebpf_block *gen_block(
    struct ebpf_ctx *ectx, struct mptcp_rbs_cfg_block *block,
    struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block2;
	struct mptcp_rbs_cfg_block *old_block;
	struct mptcp_rbs_ebpf_block *old_eblock;
	int old_capacity;
	int old_next_var;
	struct mptcp_rbs_ebpf_block *eblock;
	struct mptcp_rbs_ebpf_block *else_eblock;
	struct mptcp_rbs_smt *smt;
	int temp;
	int capacity;

	/* Check if the block is already in the list */
	FOREACH_BLOCK(list, block2, {
		if (block == block2)
			return BLOCK_INFO(block)->eblock;
	});
	ADD_BLOCK(list, block);

	/* Remember current block and its capacity */
	old_block = ectx->block;
	old_eblock = ectx->eblock;
	old_capacity = ectx->capacity;
	old_next_var = ectx->next_var;

	/* Create eBPF block */
	eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	block->tag = kzalloc(sizeof(struct block_info), GFP_KERNEL);
	BLOCK_INFO(block)->eblock = eblock;
	ectx->block = block;
	ectx->eblock = eblock;
	ectx->capacity = 0;

	/* Generate code of the statements */
	ectx->next_var = -1;
	smt = block->first_smt;
	while (smt) {
		/* Make sure that no statement follows after a var statement
		 * with *_NEXT value
		 */
		BUG_ON(ectx->next_var != -1);

		gen_smt(ectx, smt);
		smt = smt->next;
	}

	/* Evaluate condition if there is one */
	if (block->condition) {
		if (ectx->next_var != -1) {
			/* Must be part of a foreach loop */
			BUG_ON(block->condition->kind !=
			       VALUE_KIND_IS_NOT_NULL);
			BUG_ON(((const struct mptcp_rbs_value_is_not_null *)
				    block->condition)
				       ->operand->kind != VALUE_KIND_SBF_VAR &&
			       ((const struct mptcp_rbs_value_is_not_null *)
				    block->condition)
				       ->operand->kind != VALUE_KIND_SKB_VAR);

			/* Release temporaries of foreach loop because the else
			 * branch is outside of it
			 */
			dereserve_all(ectx,
				      BLOCK_INFO(block)->reserved_temps_map);

			else_eblock = BLOCK_INFO(block)->break_eblock;
			capacity = 0;
			add_instr(else_eblock, &capacity, EBPF_JMP_OFF());

			/* Set the jump target of the null block after the whole
			 * loop
			 */
			if (ectx->next_var_null_eblock)
				ectx->next_var_null_eblock->next = else_eblock;
		} else {
			else_eblock = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			capacity = 0;
			add_instr(else_eblock, &capacity, EBPF_JMP_OFF());

			temp = reserve(ectx);
			gen_value(ectx,
				  (struct mptcp_rbs_value *) block->condition,
				  temp, else_eblock);
			add_instr_ectx(ectx, EBPF_JMP_IMM(BPF_JEQ, temp, 0));
			dereserve(ectx, temp);
			ectx->eblock->next_else = else_eblock;
		}

		if (block->next_else) {
			else_eblock->next =
			    gen_block(ectx, block->next_else, list);
		} else {
			else_eblock->next = kzalloc(
			    sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
			capacity = 0;
			add_instr(else_eblock->next, &capacity, EBPF_EXIT());
		}

		if (ectx->next_var != -1) {
			/* The next branch is in the foreach loop -> reserve the
			 * temporaries of the foreach loop again
			 */
			reserve_all(ectx,
				    BLOCK_INFO(block)->reserved_temps_map);
		}
	} else
		BUG_ON(ectx->next_var != -1);

	/* Add jump to next block */
	if (block->next) {
		/* Check if the jump target is a loop start */
		bool is_loop_start = false;
		FOREACH_BLOCK(list, block2, {
			if (block->next == block2) {
				is_loop_start =
				    BLOCK_INFO(block2)->break_eblock != NULL;
				break;
			}
		});

		if (is_loop_start) {
			/* If there exists a path from block->next to block
			 * without using the break block we have to use the
			 * continue block
			 */
			if (path_exists(block->next->next, block))
				ectx->eblock->next =
				    BLOCK_INFO(block->next)->cont_eblock;
			else
				ectx->eblock->next =
				    BLOCK_INFO(block->next)->eblock;
		} else
			ectx->eblock->next = gen_block(ectx, block->next, list);
		add_instr_ectx(ectx, EBPF_JMP_OFF());
	} else
		add_instr_ectx(ectx, EBPF_EXIT());

	/* Reset current block and its capacity */
	if (ectx->next_var != -1) {
		/* Release temporaries of foreach loop because we are now
		 * outside of it
		 */
		dereserve_all(ectx, BLOCK_INFO(block)->reserved_temps_map);
	}

	ectx->block = old_block;
	ectx->eblock = old_eblock;
	ectx->capacity = old_capacity;
	ectx->next_var = old_next_var;

	return eblock;
}

/**
 * Generates the eBPF instructions for a CFG
 * @ectx: The generation context
 * @return: The first eBPF block
 */
static struct mptcp_rbs_ebpf_block *gen(struct ebpf_ctx *ectx)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_ebpf_block *first_eblock;
	struct mptcp_rbs_cfg_block *block;

	/* Generate start block that puts values in fixed temporaries */
	first_eblock = kzalloc(sizeof(struct mptcp_rbs_ebpf_block), GFP_KERNEL);
	ectx->eblock = first_eblock;
	ectx->capacity = 0;
	ectx->used_temps = FIXED_TMP_COUNT;
	ectx->used_temps_map = ((u64) -1ll) >> (64 - FIXED_TMP_COUNT);
	add_instr_ectx(ectx, EBPF_MOV_RAW_REG(CTX_TMP, BPF_REG_ARG1));
	add_instr_ectx(ectx, EBPF_MOV_REG(VARS_TMP, CTX_TMP));
	add_instr_ectx(ectx,
		       EBPF_ALU_IMM(BPF_ADD, VARS_TMP,
				    offsetof(struct mptcp_rbs_eval_ctx, vars)));
	add_instr_ectx(
	    ectx,
	    EBPF_LDX_MEM(bytes_to_bpf_size(sizeof(void *)), REGS_TMP, CTX_TMP,
			 offsetof(struct mptcp_rbs_eval_ctx, rbs_cb)));
	add_instr_ectx(ectx, EBPF_ALU_IMM(BPF_ADD, REGS_TMP,
					  offsetof(struct mptcp_rbs_cb, regs)));
	add_instr_ectx(ectx, EBPF_JMP_OFF());

	INIT_BLOCK_LIST(&list);
	first_eblock->next =
	    gen_block(ectx, ectx->ctx->variation->first_block, &list);
	FOREACH_BLOCK(&list, block, kfree(block->tag));
	FREE_BLOCK_LIST(&list);

	return first_eblock;
}

void mptcp_rbs_opt_ebpf(struct mptcp_rbs_opt_ctx *ctx)
{
	struct ebpf_ctx ectx;
	struct bpf_prog *prog;
	struct mptcp_rbs_cfg_block *block;
	struct mptcp_rbs_ebpf_block *first_eblock;
	int err;

	/* Generate code */
	memset(&ectx, 0, sizeof(struct ebpf_ctx));
	ectx.ctx = ctx;
	INIT_FILTER_VAR_LIST(&ectx.filter_var_list);
	first_eblock = gen(&ectx);
	FREE_FILTER_VAR_LIST(&ectx.filter_var_list);

	/* Register functions that can be called from eBPF */
	prog = bpf_prog_alloc(bpf_prog_size(1), 0);
	atomic_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = true;
	prog->aux->ops = &bpf_ops;
	prog->type = BPF_PROG_TYPE_RBS;

	/* Run register allocator */
	prog = mptcp_rbs_ebpf_alloc_regs(first_eblock, ectx.used_temps, prog);
	mptcp_rbs_ebpf_blocks_free(first_eblock);

	/* JIT the result */
	bpf_prog_select_runtime(prog, &err);

	/* Create eBPF statement and replace whole CFG with it */
	mptcp_rbs_cfg_blocks_free(ctx->variation->first_block);

	block = kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	block->first_smt = (struct mptcp_rbs_smt *) mptcp_rbs_smt_ebpf_new(
	    prog, ectx.strs, ectx.strs_len);
	ctx->variation->first_block = block;
}

static struct bpf_prog_type_list rbs_bpf_tl = {
	.ops = &bpf_ops,
	.type = BPF_PROG_TYPE_RBS,
};

static int __init register_ebpf_prog_type(void)
{
	bpf_register_prog_type(&rbs_bpf_tl);
	return 0;
}
module_init(register_ebpf_prog_type);
