#ifndef _MPTCP_RBS_OPTIMIZER_CVE_H
#define _MPTCP_RBS_OPTIMIZER_CVE_H

struct mptcp_rbs_opt_ctx;

/**
 * Constant Value Evaluation:
 * Searches for constant values, evaluates them and stores the results inside
 * the values' info
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_cve(struct mptcp_rbs_opt_ctx *ctx);

#endif
