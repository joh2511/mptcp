#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_ctx.h"
#include "mptcp_rbs_optimizer_ebpf_disasm.h"
#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_sched.h"
#include "mptcp_rbs_value.h"
#include <linux/filter.h>
#include <linux/slab.h>

struct mptcp_rbs_smt_drop *mptcp_rbs_smt_drop_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_smt_drop *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_drop), GFP_KERNEL);
	smt->kind = SMT_KIND_DROP;
	smt->free = mptcp_rbs_smt_drop_free;
	smt->execute = mptcp_rbs_smt_drop_execute;
	smt->skb = skb;

	return smt;
}

void mptcp_rbs_smt_drop_free(struct mptcp_rbs_smt_drop *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

void mptcp_rbs_smt_drop_execute(struct mptcp_rbs_smt_drop *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return;
    
    ctx->rbs_cb->execution_bucket += 5;

	mptcp_rbs_action_new(ctx->rbs_cb->open_actions, false, ACTION_KIND_DROP,
			     NULL, skb, self->skb->reinject);
}

struct mptcp_rbs_smt_drop *mptcp_rbs_smt_drop_clone(
    const struct mptcp_rbs_smt_drop *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_drop *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_drop), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->skb = (struct mptcp_rbs_value_skb *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->skb, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_print *mptcp_rbs_smt_print_new(
    struct mptcp_rbs_value_string *msg, struct mptcp_rbs_value *arg)
{
	struct mptcp_rbs_smt_print *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_print), GFP_KERNEL);
	smt->kind = SMT_KIND_PRINT;
	smt->free = mptcp_rbs_smt_print_free;
	smt->execute = mptcp_rbs_smt_print_execute;
	smt->msg = msg;
	smt->arg = arg;

	return smt;
}

void mptcp_rbs_smt_print_free(struct mptcp_rbs_smt_print *self)
{
	MPTCP_RBS_VALUE_FREE(self->msg);
	MPTCP_RBS_VALUE_FREE(self->arg);
	kfree(self);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
void mptcp_rbs_smt_print_execute(struct mptcp_rbs_smt_print *self,
				 struct mptcp_rbs_eval_ctx *ctx)
{
	char *msg = self->msg->execute(self->msg, ctx);
	char str[512];
    struct inet_sock *isk = inet_sk(ctx->meta_sk);

	if (!msg)
		return;
	if (!self->arg) {
		printk("ProgMP %p %08X:%04X %08X:%04X: %s\n", ctx->meta_sk,
                       isk->inet_rcv_saddr,
					   ntohs(isk->inet_sport),
					   isk->inet_daddr,
					   ntohs(isk->inet_dport),
                       msg);
		return;
	}

	/* build prefix */
	memset(str, 0, sizeof(str));
	snprintf(str, sizeof(str), "ProgMP %p %08X:%04X %08X:%04X: %s\n", ctx->meta_sk,
                       isk->inet_rcv_saddr,
					   ntohs(isk->inet_sport),
					   isk->inet_daddr,
					   ntohs(isk->inet_dport),
                       msg);
	msg = str;

	switch (mptcp_rbs_value_get_type(self->arg->kind)) {
	case TYPE_KIND_BOOL: {
		struct mptcp_rbs_value_bool *arg =
		    (struct mptcp_rbs_value_bool *) self->arg;
		s32 value = arg->execute(arg, ctx);
		if (value != -1)
			printk(msg, value != 0);
		break;
	}
	case TYPE_KIND_INT: {
		struct mptcp_rbs_value_int *arg =
		    (struct mptcp_rbs_value_int *) self->arg;
		s64 value = arg->execute(arg, ctx);
		if (value != -1)
			printk(msg, (unsigned int) value);
		break;
	}
	case TYPE_KIND_STRING: {
		struct mptcp_rbs_value_string *arg =
		    (struct mptcp_rbs_value_string *) self->arg;
		char *value = arg->execute(arg, ctx);
		if (value)
			printk(msg, value);
		break;
	}
	case TYPE_KIND_NULL: {
		printk(msg, NULL);
		break;
	}
	case TYPE_KIND_SBF: {
		struct mptcp_rbs_value_sbf *arg =
		    (struct mptcp_rbs_value_sbf *) self->arg;
		struct tcp_sock *value = arg->execute(arg, ctx);
		if (value) {
			printk(msg, value, value->mptcp->sbf_id);
		} else {
			printk(msg, 0, 0);
		}
		break;
	}
	case TYPE_KIND_SKB: {
		struct mptcp_rbs_value_skb *arg =
		    (struct mptcp_rbs_value_skb *) self->arg;
		struct sk_buff *value = arg->execute(arg, ctx);
		if (value) {
			printk(msg, value, TCP_SKB_CB(value)->seq,
			       TCP_SKB_CB(value)->end_seq);
		} else {
			printk(msg, 0, 0, 0);
		}
		break;
	}
	case TYPE_KIND_SBFLIST:
	case TYPE_KIND_SKBLIST:
		/* Not possible */
		break;
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_smt_print *mptcp_rbs_smt_print_clone(
    const struct mptcp_rbs_smt_print *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_print *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_print), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->msg = (struct mptcp_rbs_value_string *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->msg, user_ctx, user_func);
	if (clone->arg)
		clone->arg =
		    mptcp_rbs_value_clone(clone->arg, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_push *mptcp_rbs_smt_push_new(
    struct mptcp_rbs_value_sbf *sbf, struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_smt_push *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_push), GFP_KERNEL);
	smt->kind = SMT_KIND_PUSH;
	smt->free = mptcp_rbs_smt_push_free;
	smt->execute = mptcp_rbs_smt_push_execute;
	smt->sbf = sbf;
	smt->skb = skb;

	return smt;
}

void mptcp_rbs_smt_push_free(struct mptcp_rbs_smt_push *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

void mptcp_rbs_smt_push_execute(struct mptcp_rbs_smt_push *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;
	struct sk_buff *skb;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return;
    
    ctx->rbs_cb->execution_bucket += 5;

	mptcp_rbs_action_new(ctx->rbs_cb->open_actions, false, ACTION_KIND_PUSH,
			     sbf, skb, self->skb->reinject);
}

struct mptcp_rbs_smt_push *mptcp_rbs_smt_push_clone(
    const struct mptcp_rbs_smt_push *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_push *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_push), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->sbf = (struct mptcp_rbs_value_sbf *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->sbf, user_ctx, user_func);
	clone->skb = (struct mptcp_rbs_value_skb *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->skb, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_set_user *mptcp_rbs_smt_set_user_new(
    struct mptcp_rbs_value_sbf *sbf, struct mptcp_rbs_value_int *value)
{
	struct mptcp_rbs_smt_set_user *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_set_user), GFP_KERNEL);
	smt->kind = SMT_KIND_SET_USER;
	smt->free = mptcp_rbs_smt_set_user_free;
	smt->execute = mptcp_rbs_smt_set_user_execute;
	smt->sbf = sbf;
	smt->value = value;

	return smt;
}

void mptcp_rbs_smt_set_user_free(struct mptcp_rbs_smt_set_user *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	MPTCP_RBS_VALUE_FREE(self->value);
	kfree(self);
}

void mptcp_rbs_smt_set_user_execute(struct mptcp_rbs_smt_set_user *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;
	s64 val;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return;

        val = self->value->execute(self->value, ctx);

	/* even eval to null is a side effect */
	ctx->side_effects = 1;

	if (val != -1) {
//		*((unsigned long*)&sbf->mptcp->mptcp_sched[0]) = val;
		 mptcp_rbs_get_sbf_cb(sbf)->user = val;
        }
}

struct mptcp_rbs_smt_set_user *mptcp_rbs_smt_set_user_clone(
    const struct mptcp_rbs_smt_set_user *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_set_user *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_set_user), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->sbf = (struct mptcp_rbs_value_sbf *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->sbf, user_ctx, user_func);
	clone->value = (struct mptcp_rbs_value_int *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->value, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_set *mptcp_rbs_smt_set_new(
    int reg_number, struct mptcp_rbs_value_int *value)
{
	struct mptcp_rbs_smt_set *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_set), GFP_KERNEL);
	smt->kind = SMT_KIND_SET;
	smt->free = mptcp_rbs_smt_set_free;
	smt->execute = mptcp_rbs_smt_set_execute;
	smt->reg_number = reg_number;
	smt->value = value;

	return smt;
}

void mptcp_rbs_smt_set_free(struct mptcp_rbs_smt_set *self)
{
	MPTCP_RBS_VALUE_FREE(self->value);
	kfree(self);
}

void mptcp_rbs_smt_set_execute(struct mptcp_rbs_smt_set *self,
			       struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->value->execute(self->value, ctx);

	/* even eval to null is a side effect */
	ctx->side_effects = 1;

	if (val != -1)
		ctx->rbs_cb->regs[self->reg_number] = val;
}

struct mptcp_rbs_smt_set *mptcp_rbs_smt_set_clone(
    const struct mptcp_rbs_smt_set *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_set *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_set), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->value = (struct mptcp_rbs_value_int *) mptcp_rbs_value_clone(
	    (struct mptcp_rbs_value *) clone->value, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_var *mptcp_rbs_smt_var_new(int var_number, bool is_lazy,
						struct mptcp_rbs_value *value)
{
	struct mptcp_rbs_smt_var *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_var), GFP_KERNEL);
	smt->kind = SMT_KIND_VAR;
	smt->free = mptcp_rbs_smt_var_free;
	smt->execute = mptcp_rbs_smt_var_execute;
	smt->var_number = var_number;
	smt->is_lazy = is_lazy;
	smt->value = value;

	return smt;
}

void mptcp_rbs_smt_var_free(struct mptcp_rbs_smt_var *self)
{
	MPTCP_RBS_VALUE_FREE(self->value);
	kfree(self);
}

static struct tcp_sock **sbf_list_store(struct mptcp_rbs_value_sbf_list *value,
					struct mptcp_rbs_eval_ctx *ctx)
{
	int len = 0;
	bool is_null;
	void *prev = NULL;
	struct tcp_sock *sbf;
	struct tcp_sock **list;
	struct tcp_sock **tmp;

	sbf = value->execute(value, ctx, &prev, &is_null);
	if (is_null)
		return NULL;

	while (sbf) {
		++len;
		sbf = value->execute(value, ctx, &prev, &is_null);
	}

	list = kmalloc(sizeof(struct tcp_sock *) * (len + 1), GFP_ATOMIC);
	if (!list) {
		mptcp_rbs_debug("WARNING: Cannot allocate %zu bytes to store a "
				"subflow list inside a variable. Setting "
				"variable value to NULL\n",
				sizeof(struct tcp_sock *) * (len + 1));
		return NULL;
	}

	tmp = list;
	prev = NULL;
	sbf = value->execute(value, ctx, &prev, &is_null);
	while (sbf) {
		*tmp = sbf;
		++tmp;
		sbf = value->execute(value, ctx, &prev, &is_null);
	}
	*tmp = NULL; /* implicit end with NULL */

if(len == 0) {
	printk("%s allocates space for %d subflows\n", __func__, len);
} else if(len == 1) {
	printk("%s allocates space for %d subflows, with first one %p\n", __func__, len, *list);
} else if(len > 1) {
	printk("%s allocates space for %d subflows, with first one %p, second %p\n", __func__, len, *list, *(list + 1));
}

	return list;
}

static struct sk_buff **skb_list_store(struct mptcp_rbs_value_skb_list *value,
				       struct mptcp_rbs_eval_ctx *ctx)
{
	int len = 0;
	bool is_null;
	void *prev = NULL;
	struct sk_buff *skb;
	struct sk_buff **list;
	struct sk_buff **tmp;

	skb = value->execute(value, ctx, &prev, &is_null);
	if (is_null)
		return NULL;

	while (skb) {
		++len;
		skb = value->execute(value, ctx, &prev, &is_null);
	}

	list = kmalloc(sizeof(struct sk_buff *) * (len + 1), GFP_ATOMIC);
	if (!list) {
		mptcp_rbs_debug("WARNING: Cannot allocate %zu bytes to store a "
				"sockbuffer list inside a variable. Setting "
				"variable value to NULL\n",
				sizeof(struct sk_buff *) * (len + 1));
		return NULL;
	}

	tmp = list;
	prev = NULL;
	skb = value->execute(value, ctx, &prev, &is_null);
	while (skb) {
		*tmp = skb;
		++tmp;
		skb = value->execute(value, ctx, &prev, &is_null);
	}
	*tmp = NULL;

	return list;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
void mptcp_rbs_smt_var_execute(struct mptcp_rbs_smt_var *self,
			       struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];
	enum mptcp_rbs_type_kind type =
	    mptcp_rbs_value_get_type(self->value->kind);

	var->type = type;
	var->is_lazy = self->is_lazy;

	if (self->is_lazy)
		var->lazy_value = self->value;
	else {
		switch (type) {
		case TYPE_KIND_NULL:
			break;
		case TYPE_KIND_BOOL: {
			struct mptcp_rbs_value_bool *bool_value =
			    (struct mptcp_rbs_value_bool *) self->value;

			var->bool_value = bool_value->execute(bool_value, ctx);
			break;
		}
		case TYPE_KIND_INT: {
			struct mptcp_rbs_value_int *int_value =
			    (struct mptcp_rbs_value_int *) self->value;

			var->int_value = int_value->execute(int_value, ctx);
			break;
		}
		case TYPE_KIND_STRING: {
			struct mptcp_rbs_value_string *string_value =
			    (struct mptcp_rbs_value_string *) self->value;

			var->string_value =
			    string_value->execute(string_value, ctx);
			break;
		}
		case TYPE_KIND_SBF: {
			struct mptcp_rbs_value_sbf *sbf_value =
			    (struct mptcp_rbs_value_sbf *) self->value;

			var->sbf_value = sbf_value->execute(sbf_value, ctx);
			break;
		}
		case TYPE_KIND_SBFLIST: {
			struct mptcp_rbs_value_sbf_list *sbf_list_value =
			    (struct mptcp_rbs_value_sbf_list *) self->value;
printk("%s for meta_sk %p\n", __func__, ctx->mpcb->meta_sk);
			var->sbf_list_value =
			    sbf_list_store(sbf_list_value, ctx);
			break;
		}
		case TYPE_KIND_SKB: {
			struct mptcp_rbs_value_skb *skb_value =
			    (struct mptcp_rbs_value_skb *) self->value;

			var->skb_value = skb_value->execute(skb_value, ctx);
			break;
		}
		case TYPE_KIND_SKBLIST: {
			struct mptcp_rbs_value_skb_list *skb_list_value =
			    (struct mptcp_rbs_value_skb_list *) self->value;

			var->skb_list_value =
			    skb_list_store(skb_list_value, ctx);
			break;
		}
		}
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_smt_var *mptcp_rbs_smt_var_clone(
    const struct mptcp_rbs_smt_var *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_var), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	clone->value = mptcp_rbs_value_clone(clone->value, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_void *mptcp_rbs_smt_void_new(struct mptcp_rbs_value *value)
{
	struct mptcp_rbs_smt_void *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_void), GFP_KERNEL);
	smt->kind = SMT_KIND_VOID;
	smt->free = mptcp_rbs_smt_void_free;
	smt->execute = mptcp_rbs_smt_void_execute;
	smt->value = value;

	return smt;
}

void mptcp_rbs_smt_void_free(struct mptcp_rbs_smt_void *self)
{
	MPTCP_RBS_VALUE_FREE(self->value);
	kfree(self);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
void mptcp_rbs_smt_void_execute(struct mptcp_rbs_smt_void *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	if (!self->value)
		return;

	switch (mptcp_rbs_value_get_type(self->value->kind)) {
	case TYPE_KIND_NULL: {
		/* Do nothing */
		break;
	}
	case TYPE_KIND_BOOL: {
		struct mptcp_rbs_value_bool *value =
		    (struct mptcp_rbs_value_bool *) self->value;

		value->execute(value, ctx);
		break;
	}
	case TYPE_KIND_INT: {
		struct mptcp_rbs_value_int *value =
		    (struct mptcp_rbs_value_int *) self->value;

		value->execute(value, ctx);
		break;
	}
	case TYPE_KIND_STRING: {
		struct mptcp_rbs_value_string *value =
		    (struct mptcp_rbs_value_string *) self->value;

		value->execute(value, ctx);
		break;
	}
	case TYPE_KIND_SBF: {
		struct mptcp_rbs_value_sbf *value =
		    (struct mptcp_rbs_value_sbf *) self->value;

		value->execute(value, ctx);
		break;
	}
	case TYPE_KIND_SBFLIST: {
		struct mptcp_rbs_value_sbf_list *value =
		    (struct mptcp_rbs_value_sbf_list *) self->value;
		void *prev = NULL;
		bool is_null;

		value->execute(value, ctx, &prev, &is_null);
		break;
	}
	case TYPE_KIND_SKB: {
		struct mptcp_rbs_value_skb *value =
		    (struct mptcp_rbs_value_skb *) self->value;

		value->execute(value, ctx);
		break;
	}
	case TYPE_KIND_SKBLIST: {
		struct mptcp_rbs_value_skb_list *value =
		    (struct mptcp_rbs_value_skb_list *) self->value;
		void *prev = NULL;
		bool is_null;

		value->execute(value, ctx, &prev, &is_null);
		break;
	}
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_smt_void *mptcp_rbs_smt_void_clone(
    const struct mptcp_rbs_smt_void *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_smt_void *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_smt_void), GFP_KERNEL);
	*clone = *smt;
	clone->next = NULL;
	if (clone->value)
		clone->value =
		    mptcp_rbs_value_clone(clone->value, user_ctx, user_func);

	return clone;
}

struct mptcp_rbs_smt_ebpf *mptcp_rbs_smt_ebpf_new(struct bpf_prog *prog,
						  char **strs, int strs_len)
{
	struct mptcp_rbs_smt_ebpf *smt;

	smt = kzalloc(sizeof(struct mptcp_rbs_smt_ebpf), GFP_KERNEL);
	smt->kind = SMT_KIND_EBPF;
	smt->free = mptcp_rbs_smt_ebpf_free;
	smt->execute = mptcp_rbs_smt_ebpf_execute;
	smt->prog = prog;
	smt->strs = strs;
	smt->strs_len = strs_len;

	return smt;
}

void mptcp_rbs_smt_ebpf_free(struct mptcp_rbs_smt_ebpf *self)
{
	int i;

	if (self->prog)
		bpf_prog_free(self->prog);
	if (self->strs) {
		for (i = 0; i < self->strs_len; ++i) {
			kfree(self->strs[i]);
		}
		kfree(self->strs);
	}
	kfree(self);
}

void mptcp_rbs_smt_ebpf_execute(struct mptcp_rbs_smt_ebpf *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	BPF_PROG_RUN(self->prog, (struct sk_buff *) ctx);
}

void mptcp_rbs_smts_free(struct mptcp_rbs_smt *smt)
{
	while (smt) {
		struct mptcp_rbs_smt *old_smt = smt;
		smt = smt->next;
		old_smt->free(old_smt);
	}
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
struct mptcp_rbs_smt *mptcp_rbs_smt_clone(
    const struct mptcp_rbs_smt *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	switch (smt->kind) {
	case SMT_KIND_DROP:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_drop_clone(
		    (const struct mptcp_rbs_smt_drop *) smt, user_ctx,
		    user_func);
	case SMT_KIND_PRINT:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_print_clone(
		    (const struct mptcp_rbs_smt_print *) smt, user_ctx,
		    user_func);
	case SMT_KIND_PUSH:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_push_clone(
		    (const struct mptcp_rbs_smt_push *) smt, user_ctx,
		    user_func);
    case SMT_KIND_SET_USER:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_set_user_clone(
		    (const struct mptcp_rbs_smt_set_user*) smt, user_ctx,
		    user_func);
	case SMT_KIND_SET:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_set_clone(
		    (const struct mptcp_rbs_smt_set *) smt, user_ctx,
		    user_func);
	case SMT_KIND_VAR:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_var_clone(
		    (const struct mptcp_rbs_smt_var *) smt, user_ctx,
		    user_func);
	case SMT_KIND_VOID:
		return (struct mptcp_rbs_smt *) mptcp_rbs_smt_void_clone(
		    (const struct mptcp_rbs_smt_void *) smt, user_ctx,
		    user_func);
	case SMT_KIND_EBPF: {
		/* This should never be called */
		BUG_ON(true);
		return NULL;
	}
	}
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
int mptcp_rbs_smt_print(const struct mptcp_rbs_smt *smt, char *buffer)
{
	int len;
	int tmp_len;

	switch (smt->kind) {
	case SMT_KIND_DROP: {
		const struct mptcp_rbs_smt_drop *drop =
		    (const struct mptcp_rbs_smt_drop *) smt;

		len = sprintf_null(&buffer, "DROP(");
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) drop->skb, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		len += sprintf_null(&buffer, ");");
		return len;
	}
	case SMT_KIND_PRINT: {
		const struct mptcp_rbs_smt_print *print =
		    (const struct mptcp_rbs_smt_print *) smt;

		len = sprintf_null(&buffer, "PRINT(");
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) print->msg, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		if (print->arg) {
			len += sprintf_null(&buffer, ", ");
			tmp_len = mptcp_rbs_value_print(
			    (const struct mptcp_rbs_value *) print->arg,
			    buffer);
			len += tmp_len;
			if (buffer)
				buffer += tmp_len;
		}
		len += sprintf_null(&buffer, ");");
		return len;
	}
	case SMT_KIND_PUSH: {
		const struct mptcp_rbs_smt_push *push =
		    (const struct mptcp_rbs_smt_push *) smt;

		len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) push->sbf, buffer);
		if (buffer)
			buffer += len;
		len += sprintf_null(&buffer, ".PUSH(");
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) push->skb, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		len += sprintf_null(&buffer, ");");
		return len;
	}
    case SMT_KIND_SET_USER: {
		const struct mptcp_rbs_smt_set_user *set_user =
		    (const struct mptcp_rbs_smt_set_user *) smt;

		len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) set_user->sbf, buffer);
		if (buffer)
			buffer += len;
		len += sprintf_null(&buffer, ".SET_USER(");
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) set_user->value, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		len += sprintf_null(&buffer, ");");
		return len;
	}
	case SMT_KIND_SET: {
		const struct mptcp_rbs_smt_set *set =
		    (const struct mptcp_rbs_smt_set *) smt;

		len = sprintf_null(&buffer, "SET(R%d, ", set->reg_number + 1);
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) set->value, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		len += sprintf_null(&buffer, ");");
		return len;
	}
	case SMT_KIND_VAR: {
		const struct mptcp_rbs_smt_var *var =
		    (const struct mptcp_rbs_smt_var *) smt;

		len = sprintf_null(&buffer, "VAR v%d = ", var->var_number + 1);
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) var->value, buffer);
		len += tmp_len;
		if (buffer)
			buffer += tmp_len;
		if (var->is_lazy)
			len += sprintf_null(&buffer, " LAZY");
		len += sprintf_null(&buffer, ";");
		return len;
	}
	case SMT_KIND_VOID: {
		const struct mptcp_rbs_smt_void *void_ =
		    (const struct mptcp_rbs_smt_void *) smt;

		len = sprintf_null(&buffer, "VOID");
		if (void_->value) {
			len += sprintf_null(&buffer, "(");
			tmp_len = mptcp_rbs_value_print(
			    (const struct mptcp_rbs_value *) void_->value,
			    buffer);
			len += tmp_len;
			if (buffer)
				buffer += tmp_len;
			len += sprintf_null(&buffer, ")");
		}
		len += sprintf_null(&buffer, ";");
		return len;
	}
	case SMT_KIND_EBPF: {
		const struct mptcp_rbs_smt_ebpf *ebpf =
		    (const struct mptcp_rbs_smt_ebpf *) smt;

		return mptcp_rbs_ebpf_dump(ebpf->prog, buffer);
	}
	}
}
#pragma GCC diagnostic pop
