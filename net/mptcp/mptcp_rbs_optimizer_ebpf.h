#ifndef _MPTCP_RBS_OPTIMIZER_EBPF_H
#define _MPTCP_RBS_OPTIMIZER_EBPF_H

struct mptcp_rbs_opt_ctx;

/**
 * eBPF code generation:
 * Generates eBPF code and replaces the existing CFG with it
 * @ctx: The optimization context
 */
void mptcp_rbs_opt_ebpf(struct mptcp_rbs_opt_ctx *ctx);

#endif
