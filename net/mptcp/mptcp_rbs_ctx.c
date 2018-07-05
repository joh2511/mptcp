#include "mptcp_rbs_ctx.h"

bool mptcp_rbs_reg_value_set(struct tcp_sock *meta_tp,
			     struct mptcp_rbs_reg_value *value)
{
	struct mptcp_rbs_cb *rbs_cb = mptcp_rbs_get_cb(meta_tp);

	if (value->reg_num >= MPTCP_RBS_REG_COUNT)
		return false;

	rbs_cb->regs[value->reg_num] = value->value;
	return true;
}
