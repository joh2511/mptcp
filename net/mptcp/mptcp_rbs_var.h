#ifndef _MPTCP_RBS_VAR_H
#define _MPTCP_RBS_VAR_H

#include "mptcp_rbs_type.h"
#include "mptcp_rbs_value.h"
#include <linux/types.h>

#define MPTCP_RBS_MAX_VAR_COUNT 24

/* Struct for a single variable */
struct mptcp_rbs_var {
	enum mptcp_rbs_type_kind type;
	bool is_lazy;
	union {
		s32 bool_value;
		s64 int_value;
		char *string_value;
		struct tcp_sock *sbf_value;
		struct tcp_sock **sbf_list_value;
		struct sk_buff *skb_value;
		struct sk_buff **skb_list_value;
		struct mptcp_rbs_value *lazy_value;
	};
};

/*
 * Releases a variable struct
 */
void mptcp_rbs_var_free(struct mptcp_rbs_var *self);

#endif
