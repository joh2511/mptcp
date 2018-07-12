#ifndef _MPTCP_RBS_OPTIMIZER_DCE_H
#define _MPTCP_RBS_OPTIMIZER_DCE_H

struct mptcp_rbs_opt_ctx;

/**
 * Dead Code Elimination:
 * Erases code that is never executed
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_dce(struct mptcp_rbs_opt_ctx *ctx);

#endif
