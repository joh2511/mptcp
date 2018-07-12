/* Rule-based MPTCP Scheduler */

#include "mptcp_rbs_sched.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_ctx.h"
#include "mptcp_rbs_exec.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_queue.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_user.h"

#include <asm/atomic.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/tcp.h> // required for after(...)
#include <net/mptcp.h>
#include <asm/msr.h>

static const char *default_rules = "SCHEDULER simple;\n"
                                   "VAR sbfCandidates = SUBFLOWS.FILTER(sbf => sbf.CWND > \n"
                                   "     sbf.SKBS_IN_FLIGHT + sbf.QUEUED AND !sbf.THROTTLED AND !sbf.LOSSY);\n"
                                   "IF (sbfCandidates.EMPTY) { RETURN; }\n"
				   "IF (!RQ.EMPTY) {\n"
				   "  sbfCandidates.GET(0).PUSH(RQ.POP());\n"
				   "  RETURN;\n"
				   "}\n"
				   "IF (!Q.EMPTY) {\n"
				   "  sbfCandidates.GET(0).PUSH(Q.POP());\n"
				   "}";

/* Linked list with all schedulers */
static struct mptcp_rbs_scheduler *schedulers;
/* The default scheduler */
static struct mptcp_rbs_scheduler *default_scheduler;

/* Parameters to control scheduler */
bool mptcp_rbs_extended_msgs __read_mostly = false;
module_param(mptcp_rbs_extended_msgs, bool, 0644);
MODULE_PARM_DESC(mptcp_rbs_extended_msgs, "Should we give a bit more dmesg's?");

/* Parameters to control the advanced ooo receive ops */
bool mptcp_ooo_opt __read_mostly = false;
module_param(mptcp_ooo_opt, bool, 0644);
MODULE_PARM_DESC(mptcp_ooo_opt, "Should we run the advanced ooo receive ops?");

/* Parameters to turn off CWND */
bool ignoreSbfCwndConfig __read_mostly = false;
module_param(ignoreSbfCwndConfig, bool, 0644);
MODULE_PARM_DESC(ignoreSbfCwndConfig, "Ignore congestion control.");

static bool mptcp_rbs_clean_reinject_queue __read_mostly = true;
module_param(mptcp_rbs_clean_reinject_queue, bool, 0644);
MODULE_PARM_DESC(mptcp_rbs_clean_reinject_queue,
		 "Should the reinjection queue be cleaned?");

static bool mptcp_rbs_check_for_gaps_in_seq __read_mostly = false;
module_param(mptcp_rbs_check_for_gaps_in_seq, bool, 0644);
MODULE_PARM_DESC(
    mptcp_rbs_check_for_gaps_in_seq,
    "Should the scheduler check if there is a gap in the sequence numbers?");

static bool mptcp_rbs_check_for_work_conservingness __read_mostly = false;
module_param(mptcp_rbs_check_for_work_conservingness, bool, 0644);
MODULE_PARM_DESC(
    mptcp_rbs_check_for_work_conservingness,
    "Should the scheduler check if the program is work conserving?");

u32 mptcp_ooo_number_matches = 0;

static bool mptcp_rbs_is_available(const struct sock *sk,
				   const struct sk_buff *skb,
				   bool zero_wnd_test, bool cwnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}
	return true;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_rbs_dont_reinject_skb(const struct tcp_sock *tp,
				       const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	* another one.
	*/
	return skb &&
	       /* Has the skb already been enqueued into this subsocket? */
	       mptcp_pi_to_flag(tp->mptcp->path_index) &
		   TCP_SKB_CB(skb)->path_mask;
}

static struct sock *mptcp_rbs_get_available_subflow(struct sock *meta_sk,
						    struct sk_buff *skb,
						    bool zero_wnd_test)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *backupsk = NULL;

	mptcp_rbs_debug(
	    "### asked for available subflow for meta_sk %p and skb %p with "
	    "zerownd %u called from %pS\n",
	    meta_sk, skb, zero_wnd_test, __builtin_return_address(0));

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN && skb &&
	    mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk)
		{
			if (tcp_sk(sk)->mptcp->path_index ==
				mpcb->dfin_path_index &&
			    mptcp_rbs_is_available(sk, skb, zero_wnd_test,
						   true))
				return sk;
		}
	}

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk)
	{
		struct tcp_sock *tp = tcp_sk(sk);

		if (!mptcp_rbs_is_available(sk, skb, zero_wnd_test, true))
			continue;

		if (mptcp_rbs_dont_reinject_skb(tp, skb)) {
			backupsk = sk;
			continue;
		}

		bestsk = sk;
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}

	mptcp_rbs_debug("returning with sk %p", sk);
	return sk;
}

/* only call this if open action is empty, as we might otherwise free packets
 * which are still in open_action */
static void clean_up_reinjection_queue(struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sk_buff *skb = skb_peek(&mpcb->reinject_queue);
	u32 counter = 0;
	mptcp_rbs_debug("%s for rq %p with peek %p and size %u\n", __func__,
			&mpcb->reinject_queue, skb, mpcb->reinject_queue.qlen);

	while (skb) {
		struct sk_buff *tmp = skb;
		counter++;

		if (counter == 1000) {
			printk("%s found more than %u packets in rq with qlen "
			       "%u\n",
			       __func__, counter, mpcb->reinject_queue.qlen);
		} else if (counter > 10000) {
			printk("%s finished it with %u packets in rq and qlen "
			       "%u\n",
			       __func__, counter, mpcb->reinject_queue.qlen);
			break;
		}

		if (skb_queue_is_last(&mpcb->reinject_queue, skb)) {
			skb = NULL;
			mptcp_rbs_debug("%s for rq %p next in rq is NULL\n",
					__func__, &mpcb->reinject_queue);
		} else {
			skb = skb_queue_next(&mpcb->reinject_queue, skb);
			mptcp_rbs_debug("%s for rq %p next in rq is %p\n",
					__func__, &mpcb->reinject_queue, skb);
		}

		if (after(meta_tp->snd_una, TCP_SKB_CB(tmp)->end_seq) ||
		    (TCP_SKB_CB(tmp)->mptcp_rbs.flags_to_unlink &&
		     TCP_SKB_CB(tmp)->mptcp_rbs.flags_to_free)) {

			/* Segment already reached the peer, remove it */
			mptcp_rbs_debug(
			    "rbs_clean_up_reinjection queue removes skb %p  "
			    "with end_seq %u seq %u and snd_una %u with next "
			    "skb %p with to_unlink %u and with to_free %u and "
			    "not_in_queue %u\n",
			    tmp, TCP_SKB_CB(tmp)->end_seq, TCP_SKB_CB(tmp)->seq,
			    meta_tp->snd_una, skb,
			    TCP_SKB_CB(tmp)->mptcp_rbs.flags_to_unlink,
			    TCP_SKB_CB(tmp)->mptcp_rbs.flags_to_free,
			    TCP_SKB_CB(tmp)->mptcp_rbs.flags_not_in_queue);

			__skb_unlink(tmp, &mpcb->reinject_queue);
			__kfree_skb(tmp);
		}
	}
}

u32 get_number_of_available_subflows(struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	u32 result = 0;

	mptcp_for_each_sk(mpcb, sk)
	{
		struct tcp_sock *tp = (struct tcp_sock *) sk;
		if (mptcp_rbs_sbf_is_available(tp)) {
			result++;
		}
	}

	return result;
}

u32 get_number_of_available_subflows_with_cwnd(struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *sk;
	u32 result = 0;

	mptcp_for_each_sk(mpcb, sk)
	{
		struct tcp_sock *tp = (struct tcp_sock *) sk;
		if (mptcp_rbs_sbf_is_available(tp) &&
		    tp->packets_out < tp->snd_cwnd)
			result++;
	}

	return result;
}

static struct sk_buff *process_actions(struct tcp_sock *meta_tp, int *reinject,
				       struct sock **sbf)
{
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);
	enum mptcp_rbs_action_kind kind;
	struct sk_buff *skb;
	unsigned int end_seq;

	FOREACH_ACTION(
	    rbs_cb->open_actions, kind, *((struct tcp_sock **) sbf), skb,
	    end_seq, *reinject, {
		    if (kind == ACTION_KIND_PUSH) {
			    mptcp_rbs_debug("Answer with OPEN PUSH ACTION with "
					    "skb %p on sbf %p (reinjection "
					    "%i)\n",
					    skb, *sbf, *reinject);

			    /*
			     * The packet might be already acknowledged, so we
			     * check
			     * the sequence numbers
			     */
			    if (!after(end_seq, meta_tp->snd_una)) {
				    mptcp_rbs_debug("rbs recovered from "
						    "acknowledged seq without "
						    "touching skb\n");
				    continue;
			    }

			    return skb;
		    } else if (kind == ACTION_KIND_DROP) {
			    mptcp_rbs_debug("Execute OPEN DROP ACTION with skb "
					    "%p (reinjection %i)\n",
					    skb, *reinject);
			    /* nothing to do... TODO: remove from open action
			     * table
			     */
		    } else
			    BUG_ON(true);
	    });

	*reinject = false;
	*sbf = NULL;
	return NULL;
}

#ifdef CONFIG_MPTCP_RBSMEASURE

/* Functions for measurements with SystemTap */

void noinline mptcp_rbs_scheduler_opt(const char *sched_name, int sbf_num,
				      int status)
{
	asm("nop");
}

void noinline mptcp_rbs_scheduler_switch(const struct sock *meta_sk,
					 const char *sched_name,
					 int old_sbf_num, int sbf_num)
{
	asm("nop");
}

#endif

/* Determines if a scheduler is currently optimized.
 * 0 = no
 * 1 = yes - the following static variables are currently filled with data
 * 2 = yes - the following static variables hold valid data
 */
static atomic_t optimizing = ATOMIC_INIT(0);
/* The scheduler to optimize */
static struct mptcp_rbs_scheduler *opt_scheduler;
/* Number of subflows the scheduler should be optimized for */
static u32 opt_sbf_num;
/* Index of the variation where the optimized code should be stored */
static int opt_variation_idx;

/* Number of calls necessary to start an subflow number dependent optimization.
 * If the number of subflows changes the counter should restart
 */
#define MIN_CALLS_TO_OPT 10

static int opt_thread_func(void *data)
{
	struct mptcp_rbs_scheduler_variation variation;

	while (true) {
		if (atomic_read(&optimizing) != 2) {
			msleep(2);
			continue;
		}

		barrier();

		mptcp_rbs_debug("optimizing scheduler %s for %d subflows\n",
				opt_scheduler->name, opt_sbf_num);

#ifdef CONFIG_MPTCP_RBSMEASURE
		mptcp_rbs_scheduler_opt(opt_scheduler->name, opt_sbf_num, 1);
#endif

		/* Copy the default variation */
		variation.first_block = mptcp_rbs_cfg_blocks_clone(
		    opt_scheduler->variations[0].first_block, NULL, NULL);
		variation.used_vars = opt_scheduler->variations[0].used_vars;
		variation.sbf_num = opt_sbf_num;

		/* Apply optimizations */
		mptcp_rbs_optimize(&variation, &opt_scheduler->del, opt_sbf_num,
				   mptcp_rbs_opts_enabled == 2);

		/* "Publish" the optimized variation */
		opt_scheduler->variations[opt_variation_idx].used_vars =
		    variation.used_vars;
		opt_scheduler->variations[opt_variation_idx].sbf_num =
		    variation.sbf_num;
		opt_scheduler->variations[opt_variation_idx].first_block =
		    variation.first_block;

#ifdef CONFIG_MPTCP_RBSMEASURE
		mptcp_rbs_scheduler_opt(opt_scheduler->name, opt_sbf_num, 0);
#endif

		mptcp_rbs_debug("scheduler %s was optimized for %d subflows\n",
				opt_scheduler->name, opt_sbf_num);

		atomic_set(&optimizing, 0);
	}

	return 0;
}

struct sk_buff *mptcp_rbs_next_segment(struct sock *meta_sk, int *reinject,
				       struct sock **subsk, unsigned int *limit)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);
	struct mptcp_rbs_eval_ctx ctx;
	struct sk_buff *skb;
	u32 number_of_subflows;
	u64 begin_time;
	u64 begin_time2;
	int i;
	unsigned int number_of_evaluations = 0;
	struct mptcp_rbs_scheduler_variation *old_variation;

	mptcp_rbs_debug("rbs meta_sk->send_head = %p, own queue = %p , "
			"packets in flight %i , cwnd %i, wnd %i and q size %u "
			"packets_out %u\n",
			tcp_send_head(meta_sk), rbs_cb->queue_position,
			meta_tp->packets_out, meta_tp->snd_cwnd,
			(tcp_wnd_end(meta_tp) - meta_tp->write_seq),
			mptcp_rbs_q_size(meta_sk, rbs_cb->queue_position),
			meta_tp->packets_out);

	// TODO check that we have at least window?

	if (!rbs_cb || !rbs_cb->scheduler) {
		mptcp_rbs_debug("rbs_cb or scheduler invalid\n");
		return NULL;
	}
    
    if(rbs_cb->execution_bucket == 0) {
        printk("%s: WARNING: Execution bucket exceeded for scheduler %s. Now aborting new call.", __func__, rbs_cb->scheduler->name);
        return NULL;
    }

#ifdef CONFIG_MPTCP_RBSMEASURE
	/* first time measurment */
	begin_time = rdtsc();
#endif

	/*
	 * If we still have open actions from previous rule evaluations,
	 * simply return their results in order
	 */
	skb = process_actions(meta_tp, reinject, subsk);
	if (skb) {
#ifdef CONFIG_MPTCP_RBSMEASURE
		rbs_cb->scheduler->total_time_oa_skb +=
		    rdtsc() - begin_time;
		rbs_cb->scheduler->total_count_oa_skb++;
#endif

		/* we want to run all existing checks after the rule execution
		 * to ensure
		 * that we do not miss a packet for the gap test */
		goto after_rbs_exec;
	}

	mptcp_rbs_debug("rbs scheduler no open actions\n");

	/* only clean the queue if we are sure there is no open action which
	 * might use it */
	if (mptcp_rbs_clean_reinject_queue)
		clean_up_reinjection_queue(meta_tp);

	number_of_subflows = get_number_of_available_subflows(meta_tp);
	old_variation = rbs_cb->variation;
	rbs_cb->variation = &rbs_cb->scheduler->variations[0];

	if (mptcp_rbs_opts_enabled) {
		/* Check if there is a specific variation */
		for (i = 1; i < MPTCP_RBS_VARIATION_COUNT; ++i) {
			if (!rbs_cb->scheduler->variations[i].first_block)
				break;

			if (rbs_cb->scheduler->variations[i].sbf_num ==
			    number_of_subflows) {
				rbs_cb->variation =
				    &rbs_cb->scheduler->variations[i];
				break;
			}
		}

		/* If we have place for another optimized variation */
		if (i != MPTCP_RBS_VARIATION_COUNT) {
			if (rbs_cb->last_number_of_subflows !=
			    number_of_subflows) {
				rbs_cb->last_number_of_subflows =
				    number_of_subflows;
				rbs_cb->calls_since_sbf_change = 0;
			} else if (rbs_cb->calls_since_sbf_change >
				       MIN_CALLS_TO_OPT &&
				   number_of_subflows &&
				   rbs_cb->variation ==
				       &rbs_cb->scheduler->variations[0]) {
				/* We should optimize for this number of
				 * subflows
				 */
				if (!atomic_cmpxchg(&optimizing, 0, 1)) {
					opt_scheduler = rbs_cb->scheduler;
					opt_sbf_num = number_of_subflows;
					opt_variation_idx = i;
					barrier();
					atomic_inc(&optimizing);
				}
				rbs_cb->calls_since_sbf_change = 0;
			} else
				++rbs_cb->calls_since_sbf_change;
		}
	}

	if (old_variation != rbs_cb->variation) {
#ifdef CONFIG_MPTCP_RBSMEASURE
		mptcp_rbs_scheduler_switch(meta_sk, rbs_cb->scheduler->name,
					   old_variation->sbf_num,
					   rbs_cb->variation->sbf_num);
#endif

		mptcp_rbs_debug(
		    "switching for %p to scheduler optimized for %d subflows\n",
		    meta_sk, rbs_cb->variation->sbf_num);
	}

	/*
	 * We repeat the execution till it returns a packet in case
	 * the rule execution had side effects.
	 *
	 * A side effect is the change of a register or the execution of
	 * a POP operation.
	 *
	 * This is repeated at most X times, to ensure that
	 * we terminate in case of unsuitable schedulers.
	 */
	do {
		/* Prepare context */
		memset(&ctx, 0, sizeof(struct mptcp_rbs_eval_ctx));
		ctx.meta_sk = meta_sk;
		ctx.mpcb = meta_tp->mpcb;
		ctx.rbs_cb = rbs_cb;
		ctx.side_effects = 0;

		/* Increase execution counter */
		++rbs_cb->exec_count;

#ifdef CONFIG_MPTCP_RBSMEASURE
		begin_time2 = rdtsc();
#endif

		/* Execute the rules and apply new actions if there are any */
		mptcp_rbs_exec(&ctx);
		skb = process_actions(meta_tp, reinject, subsk);

#ifdef CONFIG_MPTCP_RBSMEASURE
		if (skb) {
			rbs_cb->scheduler->total_exec_count_skb++;
			rbs_cb->scheduler->total_exec_time_skb +=
			    rdtsc() - begin_time2;
		} else {
			rbs_cb->scheduler->total_exec_count_no_skb++;
			rbs_cb->scheduler->total_exec_time_no_skb +=
			    rdtsc() - begin_time2;
		}
#endif

		number_of_evaluations++;

        	if(number_of_evaluations >= 5) {
            		printk("%s: WARNING: Exceeded 5 evaluations for scheduler %s. Now aborting.", __func__, rbs_cb->scheduler->name);
            		break;
        	}
	} while(!skb && ctx.side_effects);

#ifdef CONFIG_MPTCP_RBSMEASURE
	if (skb) {
		rbs_cb->scheduler->total_time_noa_skb +=
		    rdtsc() - begin_time;
		rbs_cb->scheduler->total_count_noa_skb++;
	} else {
		rbs_cb->scheduler->total_time_noa_no_skb +=
		    rdtsc() - begin_time;
		rbs_cb->scheduler->total_count_noa_no_skb++;
	}
#endif

after_rbs_exec:

	if (mptcp_rbs_check_for_gaps_in_seq && skb) {
		/*
		 * is there a gap between the beginning of
		 * this packet and the highest_seq without a gap?
		 */
		if (rbs_cb->highest_seq + 1 < TCP_SKB_CB(skb)->seq) {
			printk("RBS GAP CHECK found gab for meta_sk %p with "
			       "current packet %p and its seq %u and current "
			       "highest_seq %u\n",
			       meta_tp, skb, TCP_SKB_CB(skb)->seq,
			       rbs_cb->highest_seq);
		}

		/* we mention every gap only once, increase highest_seq? */
		if (rbs_cb->highest_seq > TCP_SKB_CB(skb)->end_seq) {
			// still the highest, nothing to do
		} else {
			rbs_cb->highest_seq = TCP_SKB_CB(skb)->end_seq;
		}
	}

	/*
	 * if the skb is null but there are still packets in one of the queues,
	 * print warning.
	 * Note that the queue might have changed during rule execution, but the
	 * state at the end is sufficent.
	 */
	if (mptcp_rbs_check_for_work_conservingness && !skb &&
	    (rbs_cb->queue_position || meta_tp->mpcb->reinject_queue.qlen)) {
		u32 number_of_subflows_with_cwnd =
		    get_number_of_available_subflows_with_cwnd(meta_tp);

		if (number_of_subflows_with_cwnd) {
			printk("RBS WORK CONSERVINESS CHECK found problem for "
			       "meta_sk %p with Q.TOP %p and RQ.COUNT %u and "
			       "number_of_evaluations %u and number of "
			       "available sbf %u with cwnd %u\n",
			       __func__, rbs_cb->queue_position,
			       meta_tp->mpcb->reinject_queue.qlen,
			       number_of_evaluations, number_of_subflows,
			       number_of_subflows_with_cwnd);
		}
	}
    
    if(skb) {
        rbs_cb->execution_bucket--;
        if(rbs_cb->execution_bucket == 0) {
            printk("%s: WARNING: Execution bucket exceeded for scheduler %s. Now aborting.", __func__, rbs_cb->scheduler->name);
        }
    }

	return skb;
}

void mptcp_rbs_sbf_bw_init(struct mptcp_rbs_sbf_cb *sbf_cb)
{
	sbf_cb->bw_out_bytes = 0;
	sbf_cb->bw_out_last_update_ns = 0;
	sbf_cb->bw_ack_bytes = 0;
	sbf_cb->bw_ack_last_update_ns = 0;
}

static void mptcp_rbs_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = tp->mpcb->meta_sk;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);

	if (!rbs_cb->open_actions)
		rbs_cb->open_actions =
		    kzalloc(sizeof(struct mptcp_rbs_actions), GFP_KERNEL);

	if (!rbs_cb->scheduler) {
		mptcp_rbs_debug("mptcp_rbs_init for sk %p with meta_sk %p\n",
				sk, meta_sk);
		rbs_cb->scheduler = default_scheduler;
		rbs_cb->variation = &default_scheduler->variations[0];
		++default_scheduler->usage;

		rbs_cb->highest_seq = meta_tp->snd_una;

		rbs_cb->execution_bucket = 1000; // intital bucket
		mptcp_debug("%s init highest seq with last una %u\n", __func__, rbs_cb->highest_seq);

		if (!meta_tp->nonagle)
			// during development, this is REALLY important, so
			// don't disable it
			printk("Warning: Nagle could cause performance "
			       "issues in combination with RBS\n");
	} else {
		mptcp_rbs_debug("mptcp_rbs_init for sk %p with meta_sk %p has "
				"already scheduler\n",
				sk, meta_sk);
	}

	if (meta_sk != sk) {
		mptcp_rbs_debug("mptcp_rbs_init for sbf %p with meta_sk %p\n",
				sk, meta_sk);
		mptcp_rbs_sbf_bw_init(
		    (struct mptcp_rbs_sbf_cb *) &tp->mptcp->mptcp_sched[0]);
	}

	mptcp_debug("%s for sk %p with meta_sk %p\n", __func__, sk, meta_sk);
}

static void mptcp_rbs_release(struct sock *sk)
{
	if (is_meta_sk(sk)) {
		struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(tcp_sk(sk));

		/* If the meta socket is released the scheduler is no longer
		 * used
		 */
		--mptcp_rbs_get_cb(tcp_sk(sk))->scheduler->usage;

		kfree(rbs_cb->open_actions);
	}

	printk("Releasing %p with is_meta=%d\n", sk, is_meta_sk(sk));
}

static void mptcp_rbs_recover_skb(struct sock *meta_sk, struct sock *subsk,
				  struct sk_buff *skb, bool reinject)
{
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);

	mptcp_rbs_debug("rbs scheduler recover with rejected skb %p on sbf "
			"%p with existing open action %p\n",
			skb, subsk, rbs_cb->open_actions);

	/* skb has highest prio, insert at the beginning */
	mptcp_rbs_action_new(rbs_cb->open_actions, true, ACTION_KIND_PUSH,
			     tcp_sk(subsk), skb, reinject);

	// TODO Should this really be the default CFG?
	// default_rule_set->recovered_count++;
}

/* type 0 = out, 1 = ack, 2 = ack on skb to get options */
static void mptcp_rbs_update_stats(struct sock *sk, const struct sk_buff *skb,
				   unsigned int bytes, unsigned int type)
{
	struct tcp_sock *tp = tcp_sk(sk);

	switch (type) {
		case 0: {
			struct sock *meta_sk = tp->mpcb->meta_sk;
			struct tcp_sock *meta_tp = tcp_sk(meta_sk);
			struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);
			rbs_cb->scheduler->total_bytes_sent += bytes;

			mptcp_debug("rbs adds %u bytes for sk %p on bw out\n", bytes, sk);
			mptcp_rbs_sbf_bw_send_add(tp, bytes);
			break;
		}
		case 1: {
			mptcp_debug("rbs adds %u bytes for sk %p on bw ack\n", bytes, sk);
			mptcp_rbs_sbf_bw_ack_add(tp, bytes);
			break;
		}
		case 2: {
			mptcp_rbs_sbf_delay_update(tp, skb);
			break;
		}
	}
}

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get_default(void)
{
	return default_scheduler;
}

void mptcp_rbs_scheduler_set_default(struct mptcp_rbs_scheduler *scheduler)
{
	default_scheduler = scheduler;
}

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get_registered(void)
{
	return schedulers;
}

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_find(const char *name)
{
	struct mptcp_rbs_scheduler *tmp = schedulers;

	while (tmp) {
		if (!strcmp(tmp->name, name))
			return tmp;
		tmp = tmp->next;
	}

	return NULL;
}

bool mptcp_rbs_scheduler_register(struct mptcp_rbs_scheduler *scheduler)
{
	struct mptcp_rbs_scheduler *tmp;

	/* Check if a scheduler with the same name is already registered */
	tmp = schedulers;
	while (tmp) {
		if (!strcmp(tmp->name, scheduler->name))
			return false;
		tmp = tmp->next;
	}

	scheduler->next = schedulers;
	schedulers = scheduler;
	return true;
}

void mptcp_rbs_scheduler_unregister(struct mptcp_rbs_scheduler *scheduler)
{
	struct mptcp_rbs_scheduler *cur;
	struct mptcp_rbs_scheduler *next;

	if (!schedulers)
		return;
	if (schedulers == scheduler) {
		schedulers = schedulers->next;
		return;
	}

	cur = schedulers;
	next = cur->next;
	while (next) {
		if (next == scheduler) {
			cur->next = scheduler->next;
			break;
		}

		cur = next;
		next = cur->next;
	}
}

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(tp);

	return rbs_cb->scheduler;
}

bool mptcp_rbs_scheduler_set(struct sock *sk, const char *name)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(tp);
	struct mptcp_rbs_scheduler *scheduler;

	if (name)
		scheduler = mptcp_rbs_scheduler_find(name);
	else
		scheduler = default_scheduler;

	if (!scheduler)
		return false;

	++scheduler->usage;
	--rbs_cb->scheduler->usage;
	rbs_cb->scheduler = scheduler;
	rbs_cb->variation = &scheduler->variations[0];
	return true;
}

static struct mptcp_sched_ops mptcp_sched_rbs = {
	.get_subflow = mptcp_rbs_get_available_subflow,
	.next_segment = mptcp_rbs_next_segment,
	.init = mptcp_rbs_init,
	.release = mptcp_rbs_release,
	.name = "rbs",
	.owner = THIS_MODULE,
	.recover_skb = mptcp_rbs_recover_skb,
	.update_stats = mptcp_rbs_update_stats,
};

static int __init rbs_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_rbs_cb) > MPTCP_SCHED_DATA_SIZE);
	BUILD_BUG_ON(sizeof(struct mptcp_rbs_sbf_cb) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sched_rbs))
		return -1;

	/* Load default scheduler */
	default_scheduler = mptcp_rbs_scheduler_parse(default_rules);
	BUG_ON(!default_scheduler);
	mptcp_rbs_scheduler_register(default_scheduler);

	/* Register proc for stats */
	mptcp_rbs_user_interface_init();

#ifdef CONFIG_MPTCP_RBSOPT
	/* Start optimize thread */
	kthread_run(&opt_thread_func, NULL, "mptcp_rbs_opt");
#endif

	return 0;
}

static void rbs_unregister(void)
{
	/* Release all schedulers */
	while (schedulers) {
		struct mptcp_rbs_scheduler *tmp = schedulers;
		schedulers = schedulers->next;
		mptcp_rbs_scheduler_free(tmp);
	}

	mptcp_unregister_scheduler(&mptcp_sched_rbs);
}

module_init(rbs_register);
module_exit(rbs_unregister);

MODULE_AUTHOR("Alexander Froemmgen, Tobias Erbshaeusser");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rule-based MPTCP Scheduler");
MODULE_VERSION("0.89");
