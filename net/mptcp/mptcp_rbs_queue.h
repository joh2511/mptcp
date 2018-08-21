#ifndef _MPTCP_RBS_QUEUE_H
#define _MPTCP_RBS_QUEUE_H

#include <net/mptcp.h>

void mptcp_rbs_advance_send_head(struct sock *sk, struct sk_buff **skb);

unsigned int mptcp_rbs_q_size(struct sock *sk, struct sk_buff *queue_position);

unsigned int mptcp_rbs_print_queue(struct sock *sk, struct sk_buff *skb);

#endif
