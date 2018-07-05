#include "mptcp_rbs_optimizer_ebpf_disasm.h"
#include "mptcp_rbs_parser.h"
#include <linux/bpf.h>
#include <linux/filter.h>

int mptcp_rbs_ebpf_dump(const struct bpf_prog *prog, char *buffer)
{
	int len = 0;
	int i;

#define PRINT(fmt, ...) len += sprintf_null(&buffer, fmt, ##__VA_ARGS__)
#define PRINT_ALU(op)                                                          \
	if (BPF_SRC(instr->code))                                              \
		PRINT(op "%s r%d, r%d\n", cl == BPF_ALU ? "w" : "",            \
		      instr->dst_reg, instr->src_reg);                         \
	else                                                                   \
		PRINT(op "%s r%d, %d\n", cl == BPF_ALU ? "w" : "",             \
		      instr->dst_reg, instr->imm);
#define PRINT_JMP(op)                                                          \
	if (BPF_SRC(instr->code))                                              \
		PRINT(op " r%d, r%d, 0x%x\n", instr->dst_reg, instr->src_reg,  \
		      (i + instr->off + 1) * sizeof(struct bpf_insn));         \
	else                                                                   \
		PRINT(op " r%d, %d, 0x%x\n", instr->dst_reg, instr->imm,       \
		      (i + instr->off + 1) * sizeof(struct bpf_insn));
#define PRINT_LDX(op)                                                          \
	if (instr->off > 0)                                                    \
		PRINT(op " r%d, [r%d + %d]\n", instr->dst_reg, instr->src_reg, \
		      instr->off);                                             \
	else if (instr->off < 0)                                               \
		PRINT(op " r%d, [r%d - %d]\n", instr->dst_reg, instr->src_reg, \
		      instr->off * -1);                                        \
	else                                                                   \
		PRINT(op " r%d, [r%d]\n", instr->dst_reg, instr->src_reg);
#define PRINT_ST(op)                                                           \
	if (instr->off > 0)                                                    \
		PRINT(op " [r%d + %d], %d\n", instr->dst_reg, instr->off,      \
		      instr->imm);                                             \
	else if (instr->off < 0)                                               \
		PRINT(op " [r%d - %d], %d\n", instr->dst_reg, instr->off * -1, \
		      instr->imm);                                             \
	else                                                                   \
		PRINT(op " [r%d], %d\n", instr->dst_reg, instr->imm);
#define PRINT_STX(op)                                                          \
	if (instr->off > 0)                                                    \
		PRINT(op " [r%d + %d], r%d\n", instr->dst_reg, instr->off,     \
		      instr->src_reg);                                         \
	else if (instr->off < 0)                                               \
		PRINT(op " [r%d - %d], r%d\n", instr->dst_reg,                 \
		      instr->off * -1, instr->src_reg);                        \
	else                                                                   \
		PRINT(op " [r%d], r%d\n", instr->dst_reg, instr->src_reg);

	PRINT("eBPF\n\n");
	for (i = 0; i < prog->len; ++i) {
		const struct bpf_insn *instr = &prog->insnsi[i];
		int cl = BPF_CLASS(instr->code);

		PRINT("0x%06x  ", i * sizeof(struct bpf_insn));

		switch (cl) {
		case BPF_ALU:
		case BPF_ALU64: {
			switch (BPF_OP(instr->code)) {
			case BPF_ADD: {
				PRINT_ALU("add");
				break;
			}
			case BPF_SUB: {
				PRINT_ALU("sub");
				break;
			}
			case BPF_MUL: {
				PRINT_ALU("mul");
				break;
			}
			case BPF_DIV: {
				PRINT_ALU("div");
				break;
			}
			case BPF_OR: {
				PRINT_ALU("or");
				break;
			}
			case BPF_AND: {
				PRINT_ALU("and");
				break;
			}
			case BPF_LSH: {
				PRINT_ALU("lsh");
				break;
			}
			case BPF_RSH: {
				PRINT_ALU("rsh");
				break;
			}
			case BPF_NEG: {
				PRINT("neg%s r%d\n", cl == BPF_ALU ? "w" : "",
				      instr->dst_reg);
				break;
			}
			case BPF_MOD: {
				PRINT_ALU("mod");
				break;
			}
			case BPF_XOR: {
				PRINT_ALU("xor");
				break;
			}
			case BPF_MOV: {
				PRINT_ALU("mov");
				break;
			}
			case BPF_ARSH: {
				PRINT_ALU("arsh");
				break;
			}
			case BPF_END: {
				PRINT("%s%d r%d\n",
				      BPF_SRC(instr->code) ? "be" : "le",
				      instr->imm, instr->dst_reg);
				break;
			}
			default: {
				PRINT("???\n");
				break;
			}
			}
			break;
		}
		case BPF_JMP: {
			switch (BPF_OP(instr->code)) {
			case BPF_JA: {
				PRINT("ja 0x%x\n", (i + instr->off + 1) *
						       sizeof(struct bpf_insn));
				break;
			}
			case BPF_JEQ: {
				PRINT_JMP("jeq");
				break;
			}
			case BPF_JGT: {
				PRINT_JMP("jgt");
				break;
			}
			case BPF_JGE: {
				PRINT_JMP("jge");
				break;
			}
			case BPF_JSET: {
				PRINT_JMP("jset");
				break;
			}
			case BPF_JNE: {
				PRINT_JMP("jne");
				break;
			}
			case BPF_JSGT: {
				PRINT_JMP("jsgt");
				break;
			}
			case BPF_JSGE: {
				PRINT_JMP("jsge");
				break;
			}
			case BPF_CALL: {
				PRINT("call %d\n", instr->imm);
				break;
			}
			case BPF_EXIT: {
				PRINT("exit\n");
				break;
			}
			default: {
				PRINT("???\n");
				break;
			}
			}
			break;
		}
		case BPF_LD: {
			if (BPF_MODE(instr->code) == BPF_IMM &&
			    BPF_SIZE(instr->code) == BPF_DW &&
			    i + 1 < prog->len) {
				++i;
				PRINT("ld r%d, %lld\n", instr->dst_reg,
				      instr->imm |
					  (((s64) prog->insnsi[i].imm) << 32));
			} else
				PRINT("???\n");
			break;
		}
		case BPF_LDX: {
			if (BPF_MODE(instr->code) == BPF_MEM) {
				switch (BPF_SIZE(instr->code)) {
				case BPF_W: {
					PRINT_LDX("ldxw");
					break;
				}
				case BPF_H: {
					PRINT_LDX("ldxh");
					break;
				}
				case BPF_B: {
					PRINT_LDX("ldxb");
					break;
				}
				case BPF_DW: {
					PRINT_LDX("ldx");
					break;
				}
				default: {
					PRINT("???\n");
					break;
				}
				}
			} else
				PRINT("???\n");
			break;
		}
		case BPF_ST: {
			if (BPF_MODE(instr->code) == BPF_MEM) {
				switch (BPF_SIZE(instr->code)) {
				case BPF_W: {
					PRINT_ST("stw");
					break;
				}
				case BPF_H: {
					PRINT_ST("sth");
					break;
				}
				case BPF_B: {
					PRINT_ST("stb");
					break;
				}
				case BPF_DW: {
					PRINT_ST("st");
					break;
				}
				default: {
					PRINT("???\n");
					break;
				}
				}
			} else
				PRINT("???\n");
			break;
		}
		case BPF_STX: {
			switch (BPF_MODE(instr->code)) {
			case BPF_XADD: {
				switch (BPF_SIZE(instr->code)) {
				case BPF_W: {
					PRINT_STX("xaddw");
					break;
				}
				case BPF_DW: {
					PRINT_STX("xadd");
					break;
				}
				default: {
					PRINT("???\n");
					break;
				}
				}
				break;
			}
			case BPF_MEM: {
				switch (BPF_SIZE(instr->code)) {
				case BPF_W: {
					PRINT_STX("stxw");
					break;
				}
				case BPF_H: {
					PRINT_STX("stxh");
					break;
				}
				case BPF_B: {
					PRINT_STX("stxb");
					break;
				}
				case BPF_DW: {
					PRINT_STX("stx");
					break;
				}
				default: {
					PRINT("???\n");
					break;
				}
				}
				break;
			}
			default: {
				PRINT("???\n");
				break;
			}
			}

			break;
		}
		default: {
			PRINT("???\n");
			break;
		}
		}
	}

	return len;
}
