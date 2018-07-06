#include "mptcp_rbs_queue.h"
#include <net/tcp.h>

/*
 * some helper for the queue structures
 */

void mptcp_rbs_advance_send_head(struct sock *sk, struct sk_buff **skb)
{
	if (tcp_skb_is_last(sk, *skb))
		*skb = NULL;
	else {
		/* we have to reset mptcp_rbs_in_queue as it will NOW be in QU */
		TCP_SKB_CB(*skb)->mptcp_rbs.flags_not_in_queue = 0;

		*skb = tcp_write_queue_next(sk, *skb);
	}
}

unsigned int mptcp_rbs_q_size(struct sock *sk, struct sk_buff *queue_position)
{
	struct sk_buff *initial_qp = queue_position;

	unsigned int i = 0;
	while (queue_position) {
		i++;

		if (tcp_skb_is_last(sk, queue_position)) {
			break;
		}
		queue_position = queue_position->next;

		if (i > 1000) {
			printk("## rbs_q_size for sk %p and queue position %p "
			       "with sk_write_queue %p of size %u aborted with "
			       "more than 1000 elements... might be an "
			       "infinite loop\n",
			       sk, initial_qp, &sk->sk_write_queue,
			       sk->sk_write_queue.qlen);

			break;
		}
	}
	return i;
}

/*
 * returns size
 */
unsigned int mptcp_rbs_print_queue(struct sock *sk, struct sk_buff *skb)
{
	unsigned int i = 0;

	for (i = 0; i < 10; i++) {
		if (!skb) {
			return i;
		}

		if (i < 10) {
			mptcp_debug("sk_buff queue %p seq %10u and end_seq "
				    "%10u and len %10u\n",
				    skb, TCP_SKB_CB(skb)->seq,
				    TCP_SKB_CB(skb)->end_seq, skb->len);
		}

		if (tcp_skb_is_last(sk, skb))
			return i + 1;

		skb = tcp_write_queue_next(sk, skb);
	}
	return i;
}
