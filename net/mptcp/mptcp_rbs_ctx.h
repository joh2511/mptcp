#ifndef _MPTCP_RBS_CTX_H
#define _MPTCP_RBS_CTX_H

#include "mptcp_rbs_action.h"
#include "mptcp_rbs_var.h"
#include <net/mptcp.h>
 
#define MPTCP_RBS_REG_COUNT 6

/* Central control block information per meta sock */
struct mptcp_rbs_cb {
	struct mptcp_rbs_scheduler *scheduler;
	struct mptcp_rbs_scheduler_variation *variation;
	struct mptcp_rbs_actions *open_actions;
	unsigned int regs[MPTCP_RBS_REG_COUNT];
	struct sk_buff *queue_position;
	u8 skb_prop;
	u32 last_number_of_subflows;
	u32 calls_since_sbf_change;
	/* Execution counter for FOREACH loops. This count is used to detect if
	 * a loop is entered inside *_NEXT values
	 */
	u32 exec_count;
	u32 highest_seq;
    u32 execution_bucket; /* foreach pop and drop, it is increased by 5, foreach execution it is decreased by 1, if no bucket is left, switch to default scheduler! */
};

/* Central control block information per subflow */
struct mptcp_rbs_sbf_cb {
	/* average bw sent */
	u64 bw_out_last_update_ns;
	u64 bw_out_bytes;

	/* average bw acknowledged */
	u64 bw_ack_last_update_ns;
	u64 bw_ack_bytes;

	/* Delay measurement values */
	u32 delay_in;
	u32 delay_out;

        s64 user;

        /* total size = 8 * 6 bytes = 48 bytes */
};

struct mptcp_rbs_eval_ctx {
	struct sock *meta_sk;
	struct mptcp_cb *mpcb;
	struct mptcp_rbs_cb *rbs_cb;
	struct mptcp_rbs_var vars[MPTCP_RBS_MAX_VAR_COUNT];
	/* maybe we will have an int with flags in the future */
	bool side_effects;
};

/* Struct that is used to set register values */
struct mptcp_rbs_reg_value {
	unsigned int reg_num;
	unsigned int value;
};

static inline bool mptcp_rbs_is_sched_used(struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;

	return mpcb && mpcb->sched_ops &&
	       !strncmp(mpcb->sched_ops->name, "rbs", 3);
}

static inline struct mptcp_rbs_cb *mptcp_rbs_get_cb(struct tcp_sock *meta_tp)
{
	struct mptcp_cb *mpcb = meta_tp->mpcb;

	return (struct mptcp_rbs_cb *) &mpcb->mptcp_sched[0];
}

static inline struct mptcp_rbs_sbf_cb *mptcp_rbs_get_sbf_cb(
    struct tcp_sock *sbf)
{
	return (struct mptcp_rbs_sbf_cb *) &sbf->mptcp->mptcp_sched[0];
}

bool mptcp_rbs_reg_value_set(struct tcp_sock *meta_tp,
			     struct mptcp_rbs_reg_value *value);

#endif
