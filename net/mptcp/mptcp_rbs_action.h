#ifndef _MPTCP_RBS_ACTION_H
#define _MPTCP_RBS_ACTION_H

#include <linux/types.h>

struct mptcp_rbs_cb;
struct sk_buff;
struct tcp_sock;

enum mptcp_rbs_action_kind { ACTION_KIND_PUSH, ACTION_KIND_DROP };

/* Action during evaluation */
struct mptcp_rbs_action {
	struct mptcp_rbs_action *next;
	enum mptcp_rbs_action_kind kind;
	struct tcp_sock *sbf;
	struct sk_buff *skb;
	u32 end_seq;
	bool reinject;
};

#define STATIC_ACTIONS_NUM 10

/* Multiple actions */
struct mptcp_rbs_actions {
	struct mptcp_rbs_action static_actions[STATIC_ACTIONS_NUM];
	struct mptcp_rbs_action *first;
	struct mptcp_rbs_action *last;
};

#define FOREACH_ACTION(actions, kind_, sbf_, skb_, end_seq_, reinject_, cmds)  \
	do {                                                                   \
		while ((actions)->first) {                                     \
			struct mptcp_rbs_action *__cur = (actions)->first;     \
			kind_ = __cur->kind;                                   \
			sbf_ = __cur->sbf;                                     \
			skb_ = __cur->skb;                                     \
			end_seq_ = __cur->end_seq;                             \
			reinject_ = __cur->reinject;                           \
									       \
			(actions)->first = (actions)->first->next;             \
			if (!(actions)->first)                                 \
				(actions)->last = NULL;                        \
			if (__cur < &(actions)->static_actions[0] ||           \
			    __cur >                                            \
				&(actions)                                     \
				     ->static_actions[STATIC_ACTIONS_NUM - 1]) \
				kfree(__cur);                                  \
			else                                                   \
				__cur->skb = NULL;                             \
									       \
			cmds;                                                  \
		}                                                              \
	} while (0)

void mptcp_rbs_action_new(struct mptcp_rbs_actions *actions, bool high_priority,
			  enum mptcp_rbs_action_kind kind, struct tcp_sock *sbf,
			  struct sk_buff *skb, bool reinject);

#endif
