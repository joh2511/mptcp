#ifndef _MPTCP_RBS_OPTIMIZER_LU_H
#define _MPTCP_RBS_OPTIMIZER_LU_H

struct mptcp_rbs_opt_ctx;

/**
 * Loop Unrolling:
 * Unrolls FOREACH loops over subflows if possible
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_lu(struct mptcp_rbs_opt_ctx *ctx);

#endif
