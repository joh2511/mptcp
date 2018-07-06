#ifndef _MPTCP_RBS_OPTIMIZER_VI_H
#define _MPTCP_RBS_OPTIMIZER_VI_H

struct mptcp_rbs_opt_ctx;

/**
 * Variable inlining:
 * Inlines the value of a variable directly where the variable is used
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_vi(struct mptcp_rbs_opt_ctx *ctx);

#endif
