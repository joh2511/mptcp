#ifndef _MPTCP_RBS_SCHED_H
#define _MPTCP_RBS_SCHED_H

#include "mptcp_rbs_ctx.h" 

struct mptcp_rbs_scheduler;

extern bool mptcp_rbs_extended_msgs;

extern bool mptcp_ooo_opt;

extern u32 mptcp_ooo_number_matches;

extern bool ignoreSbfCwndConfig;

#define mptcp_rbs_debug(fmt, args...)                                          \
	do {                                                                   \
		if (mptcp_rbs_extended_msgs)                                   \
			mptcp_debug(fmt, ##args);                              \
	} while (0)

struct sk_buff *mptcp_rbs_next_segment(struct sock *meta_sk, int *reinject,
				       struct sock **subsk,
				       unsigned int *limit);

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get_default(void);

void mptcp_rbs_scheduler_set_default(struct mptcp_rbs_scheduler *scheduler);

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get_registered(void);

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_find(const char *name);

bool mptcp_rbs_scheduler_register(struct mptcp_rbs_scheduler *scheduler);

void mptcp_rbs_scheduler_unregister(struct mptcp_rbs_scheduler *scheduler);

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_get(struct sock *sk);

bool mptcp_rbs_scheduler_set(struct sock *sk, const char *name);

bool mptcp_rbs_sbf_is_available(struct tcp_sock* sbf);

#endif
