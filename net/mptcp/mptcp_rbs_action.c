#include "mptcp_rbs_action.h"
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <net/tcp.h>

void mptcp_rbs_action_new(struct mptcp_rbs_actions *actions, bool high_priority,
			  enum mptcp_rbs_action_kind kind, struct tcp_sock *sbf,
			  struct sk_buff *skb, bool reinject)
{
	int i;
	struct mptcp_rbs_action *action = NULL;

	/* Check if there is place in the static array */
	for (i = 0; i < STATIC_ACTIONS_NUM; ++i) {
		if (!actions->static_actions[i].skb) {
			action = &actions->static_actions[i];
			break;
		}
	}

	if (!action)
		action = kmalloc(sizeof(struct mptcp_rbs_action), GFP_ATOMIC);

	action->next = NULL;
	action->kind = kind;
	action->sbf = sbf;
	action->skb = skb;
	action->end_seq = TCP_SKB_CB(skb)->end_seq;
	action->reinject = reinject;

	if (high_priority) {
		if (actions->first)
			action->next = actions->first;
		else
			actions->last = action;
		actions->first = action;
	} else {
		if (actions->last)
			actions->last->next = action;
		else
			actions->first = action;
		actions->last = action;
	}
}
