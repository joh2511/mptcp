#ifndef _MPTCP_RBS_OPTIMIZER_BM_H
#define _MPTCP_RBS_OPTIMIZER_BM_H

struct mptcp_rbs_opt_ctx;

/**
 * Block Merging:
 * Merges and removes empty blocks
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_bm(struct mptcp_rbs_opt_ctx *ctx);

#endif
