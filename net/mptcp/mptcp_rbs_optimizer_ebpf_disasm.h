#ifndef _MPTCP_RBS_OPTIMIZER_EBPF_DISASM_H
#define _MPTCP_RBS_OPTIMIZER_EBPF_DISASM_H

struct bpf_prog;

/**
 * Writes a string representation of an eBPF program to the given buffer
 * @prog: The eBPF program
 * @buffer: Pointer to the buffer where the string should be stored or NULL
 * Return: Number of written characters
 */
int mptcp_rbs_ebpf_dump(const struct bpf_prog *prog, char *buffer);

#endif
