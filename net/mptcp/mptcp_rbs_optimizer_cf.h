#ifndef _MPTCP_RBS_OPTIMIZER_CF_H
#define _MPTCP_RBS_OPTIMIZER_CF_H

struct mptcp_rbs_opt_ctx;

/**
 * Constant Folding:
 * Combines constant values
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_cf(struct mptcp_rbs_opt_ctx *ctx);

#endif
