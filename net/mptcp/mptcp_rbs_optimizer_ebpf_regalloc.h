#ifndef _MPTCP_RBS_OPTIMIZER_EBPF_REGALLOC_H
#define _MPTCP_RBS_OPTIMIZER_EBPF_REGALLOC_H

#include <linux/filter.h>
#include <uapi/linux/bpf.h>

#define MAX_ARGS 5
#define MAX_TEMPS ((MAX_BPF_STACK / 8) > 64 ? 64 : (MAX_BPF_STACK / 8))

/*
 *  Macros for common instructions
 */

/* Unconditional jumps, goto pc + off16 */
#define BPF_JMP_OFF(OFF)                                                       \
	((struct bpf_insn){.code = BPF_JMP | BPF_K,                            \
			   .dst_reg = 0,                                       \
			   .src_reg = 0,                                       \
			   .off = OFF,                                         \
			   .imm = 0 })

/** ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */
#define EBPF_ALU_REG(OP, DST, SRC)                                             \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_ALU64_REG(OP, 0, 0),                                   \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */
#define EBPF_ALU32_REG(OP, DST, SRC)                                           \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_ALU32_REG(OP, 0, 0),                                   \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */
#define EBPF_ALU_IMM(OP, DST, IMM)                                             \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_ALU64_IMM(OP, 0, IMM),                                 \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */
#define EBPF_ALU32_IMM(OP, DST, IMM)                                           \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_ALU32_IMM(OP, 0, IMM),                                 \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** Short form of mov, dst_reg = src_reg */
#define EBPF_MOV_REG(DST, SRC)                                                 \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_MOV64_REG(0, 0),                                       \
	    .read = {[0] = {.used = 0, .temp = 0 },                            \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** Short form of mov, dst_reg = src_reg where src is a "real" BPF register */
#define EBPF_MOV_RAW_REG(DST, SRC)                                             \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_MOV64_REG(0, SRC),                                     \
	    .read = {[0 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** Short form of mov, dst_reg = imm32 */
#define EBPF_MOV_IMM(DST, IMM)                                                 \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_MOV64_IMM(0, IMM),                                     \
	    .read = {[0 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** Memory load, dst_reg = *(uint *) (src_reg + off16) */
#define EBPF_LDX_MEM(SIZE, DST, SRC, OFF)                                      \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_LDX_MEM(SIZE, 0, 0, OFF),                              \
	    .read = {[0] = {.used = 0, .temp = 0 },                            \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 1, .temp = DST } })

/** Memory store, *(uint *) (dst_reg + off16) = src_reg */
#define EBPF_STX_MEM(SIZE, DST, SRC, OFF)                                      \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_STX_MEM(SIZE, 0, 0, OFF),                              \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/** Memory store, *(uint *) (dst_reg + off16) = imm32 */
#define EBPF_ST_MEM(SIZE, DST, OFF, IMM)                                       \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_ST_MEM(SIZE, 0, OFF, IMM),                             \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/**
 * Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc +
 * off16. Note that the jump target is given by the next/next_else fields of the
 * owning eBPF block
 */
#define EBPF_JMP_REG(OP, DST, SRC)                                             \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_JMP_REG(OP, 0, 0, 0),                                  \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1] = {.used = 1, .temp = SRC },                          \
		     [2 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/**
 * Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc +
 * off16. Note that the jump target is given by the next/next_else fields of the
 * owning eBPF block
 */
#define EBPF_JMP_IMM(OP, DST, IMM)                                             \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_JMP_IMM(OP, 0, IMM, 0),                                \
	    .read = {[0] = {.used = 1, .temp = DST },                          \
		     [1 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/**
 * Unconditional jumps, goto pc + off16. Note that the jump target is given by
 * the next/next_else fields of the owning eBPF block
 */
#define EBPF_JMP_OFF()                                                         \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_JMP_OFF(0),                                            \
	    .read = {[0 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/** Function call */
#define EBPF_CALL(FUNC, ARG1, ARG2, ARG3, ARG4, ARG5, RES)                     \
	EBPF_RAW_INSTR(BPF_EMIT_CALL(FUNC), ARG1, ARG2, ARG3, ARG4, ARG5, RES)

/** Program exit */
#define EBPF_EXIT()                                                            \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = BPF_EXIT_INSN(),                                           \
	    .read = {[0 ... 4] = {.used = 0, .temp = 0 } },                    \
	    .write = {.used = 0, .temp = 0 } })

/** Raw code statement block */
#define EBPF_RAW_INSTR(INSN, R1, R2, R3, R4, R5, W)                            \
	((struct mptcp_rbs_ebpf_instr){                                        \
	    .insn = INSN,                                                      \
	    .read = {[0] = {.used = R1 != -1, .temp = R1 },                    \
		     [1] = {.used = R2 != -1, .temp = R2 },                    \
		     [2] = {.used = R3 != -1, .temp = R3 },                    \
		     [3] = {.used = R4 != -1, .temp = R4 },                    \
		     [4] = {.used = R5 != -1, .temp = R5 } },                  \
	    .write = {.used = W != -1, .temp = W } })

struct bpf_prog;

/** Information about an used temporary */
struct mptcp_rbs_ebpf_instr_temp_info {
	u8 used : 1, temp : 7;
};

/** A single eBPF instruction using temporaries instead of "real" registers */
struct mptcp_rbs_ebpf_instr {
	struct bpf_insn insn;
	struct mptcp_rbs_ebpf_instr_temp_info read[MAX_ARGS];
	struct mptcp_rbs_ebpf_instr_temp_info write;
};

/** A single eBPF block */
struct mptcp_rbs_ebpf_block {
	/** Number of instructions in the block */
	int instr_count;
	/** Tag for various values during register allocation */
	void *tag;
	/** Array of instructions inside the block */
	struct mptcp_rbs_ebpf_instr *instrs;
	/**
	 * Pointer to the next block or NULL. This field describes the offset
	 * of a ja instruction
	 */
	struct mptcp_rbs_ebpf_block *next;
	/**
	 * Pointer to the next alternative block or NULL. This field describes
	 * the offset of all jump instructions with an offset except ja
	 */
	struct mptcp_rbs_ebpf_block *next_else;
};

/**
 * Performes the register allocation
 * @first_block: The first eBPF block
 * @used_temps: Number of used temporaries
 * @prog: eBPF program where the resulting code should be stored
 * @return: The eBPF program with the resulting code
 */
struct bpf_prog *mptcp_rbs_ebpf_alloc_regs(
    struct mptcp_rbs_ebpf_block *first_block, int used_temps,
    struct bpf_prog *prog);

/**
 * Releases a single eBPF block
 * @block: The eBPF block
 */
void mptcp_rbs_ebpf_block_free(struct mptcp_rbs_ebpf_block *block);

/**
 * Releases all eBPF blocks in a CFG
 * @first_block: The first eBPF block
 */
void mptcp_rbs_ebpf_blocks_free(struct mptcp_rbs_ebpf_block *first_block);

#endif
