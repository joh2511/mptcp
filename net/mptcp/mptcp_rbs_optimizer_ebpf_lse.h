#ifndef _MPTCP_RBS_OPTIMIZER_EBPF_LSE_H
#define _MPTCP_RBS_OPTIMIZER_EBPF_LSE_H

struct bpf_prog;

/**
 * Removes unnecessary loads and stores inside an eBPF program
 * @prog: Pointer to the eBPF program
 */
void mptcp_rbs_optimize_ebpf_ld_sts(struct bpf_prog *prog);

#endif
