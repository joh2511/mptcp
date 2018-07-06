#include "mptcp_rbs_optimizer_ebpf_lse.h"
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/string.h>

struct instr_info {
	u8 visited : 1, is_jump_target : 1, deleted : 1;
	/* 0 = unused, 255 = multiple values */
	u8 reg_states[__MAX_BPF_REG];
};

#define VAR_STATE 255

static bool includes(const u8 *reg_states1, const u8 *reg_states2)
{
	int i;

	for (i = 0; i < __MAX_BPF_REG; ++i) {
		int reg_state1 = reg_states1[i];
		int reg_state2 = reg_states2[i];

		if (reg_state1 != reg_state2 && reg_state1 != VAR_STATE &&
		    reg_state2)
			return false;
	}

	return true;
}

static void unite(u8 *reg_states_dst, const u8 *reg_states_src)
{
	int i;

	for (i = 0; i < __MAX_BPF_REG; ++i) {
		int reg_state_dst = reg_states_dst[i];
		int reg_state_src = reg_states_src[i];

		if (reg_state_src && reg_state_dst != reg_state_src) {
			if (!reg_state_dst)
				reg_states_dst[i] = reg_state_src;
			else
				reg_states_dst[i] = VAR_STATE;
		}
	}
}

static void fill_infos(struct bpf_prog *prog, int pos, struct instr_info *infos,
		       const u8 *start_reg_states)
{
	u8 reg_states[__MAX_BPF_REG];
	if (start_reg_states)
		memcpy(reg_states, start_reg_states, sizeof(reg_states));
	else
		memset(reg_states, 0, sizeof(reg_states));

	for (; pos < prog->len; ++pos) {
		struct bpf_insn *insn = &prog->insnsi[pos];
		struct instr_info *info = &infos[pos];

		info->visited = true;
		unite(info->reg_states, reg_states);

		switch (BPF_CLASS(insn->code)) {
		case BPF_LD: {
			reg_states[insn->dst_reg] = VAR_STATE;
			break;
		}
		case BPF_LDX: {
			if (insn->src_reg == BPF_REG_10)
				reg_states[insn->dst_reg] =
				    insn->off / -((int) sizeof(u64)) + 1;
			else
				reg_states[insn->dst_reg] = VAR_STATE;
			break;
		}
		case BPF_ST:
		case BPF_STX: {
			if (insn->dst_reg == BPF_REG_10) {
				int i;
				int val = insn->off / -((int) sizeof(u64)) + 1;

				for (i = 0; i < __MAX_BPF_REG; ++i) {
					if (i != insn->src_reg &&
					    reg_states[i] == val)
						reg_states[i] = VAR_STATE;
				}

				if (BPF_CLASS(insn->code) == BPF_STX)
					reg_states[insn->src_reg] = val;
			}
			break;
		}
		case BPF_ALU:
		case BPF_ALU64: {
			/* If the 2. operand is a constant check for typical
			 * values that won't change the result
			 */
			if (!BPF_SRC(insn->code)) {
				switch (BPF_OP(insn->code)) {
				case BPF_ADD:
				case BPF_SUB:
				case BPF_OR:
				case BPF_LSH:
				case BPF_RSH:
				case BPF_XOR:
				case BPF_ARSH: {
					if (!insn->imm)
						continue;
					break;
				}
				case BPF_MUL:
				case BPF_DIV: {
					if (insn->imm == 1)
						continue;
					break;
				}
				case BPF_AND: {
					if (insn->imm == -1)
						continue;
					break;
				}
				}
			}

			if (BPF_SRC(insn->code) &&
			    BPF_OP(insn->code) == BPF_MOV)
				reg_states[insn->dst_reg] =
				    reg_states[insn->src_reg];
			else
				reg_states[insn->dst_reg] = VAR_STATE;
			break;
		}
		case BPF_JMP: {
			switch (BPF_OP(insn->code)) {
			case BPF_JA: {
				int target_pos = pos + insn->off + 1;
				struct instr_info *target_info =
				    &infos[target_pos];

				target_info->is_jump_target = true;

				if (target_info->visited &&
				    includes(target_info->reg_states,
					     reg_states))
					return;

				pos = target_pos - 1;
				break;
			}
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
			case BPF_JNE:
			case BPF_JSGT:
			case BPF_JSGE: {
				int target_pos = pos + insn->off + 1;
				struct instr_info *target_info =
				    &infos[target_pos];

				target_info->is_jump_target = true;

				if (!target_info->visited ||
				    !includes(target_info->reg_states,
					      reg_states))
					fill_infos(prog, target_pos, infos,
						   reg_states);

				break;
			}
			case BPF_CALL: {
				reg_states[BPF_REG_0] = VAR_STATE;
				reg_states[BPF_REG_1] = VAR_STATE;
				reg_states[BPF_REG_2] = VAR_STATE;
				reg_states[BPF_REG_3] = VAR_STATE;
				reg_states[BPF_REG_4] = VAR_STATE;
				reg_states[BPF_REG_5] = VAR_STATE;
				break;
			}
			case BPF_EXIT: {
				return;
			}
			}
			break;
		}
		}
	}
}

static void print_infos(const struct bpf_prog *prog,
			const struct instr_info *infos)
{
	int i;
	int j;

	for (i = 0; i < prog->len; ++i) {
		const struct instr_info *info = &infos[i];

		printk("0x%6x v=%d,jt=%d,d=%d", i * 8, info->visited,
		       info->is_jump_target, info->deleted);
		for (j = 0; j < __MAX_BPF_REG; ++j) {
			printk(",r%d=%d", j, info->reg_states[j]);
		}
		printk("\n");
	}
}

static void find_deletable(struct bpf_prog *prog, struct instr_info *infos)
{
	int pos;
	int count = 0;

	for (pos = 0; pos < prog->len; ++pos) {
		struct bpf_insn *insn = &prog->insnsi[pos];
		struct instr_info *info = &infos[pos];

		switch (BPF_CLASS(insn->code)) {
		case BPF_LDX: {
			if (insn->src_reg == BPF_REG_10 &&
			    info->reg_states[insn->dst_reg] ==
				insn->off / -((int) sizeof(u64)) + 1) {
				info->deleted = true;
				++count;
			}
			break;
		}
		case BPF_STX: {
			if (insn->dst_reg == BPF_REG_10 &&
			    info->reg_states[insn->src_reg] ==
				insn->off / -((int) sizeof(u64)) + 1) {
				info->deleted = true;
				++count;
			}
			break;
		}
		case BPF_ALU:
		case BPF_ALU64: {
			/* If the 2. operand is a constant check for typical
			 * values that won't change the result
			 */
			if (!BPF_SRC(insn->code)) {
				switch (BPF_OP(insn->code)) {
				case BPF_ADD:
				case BPF_SUB:
				case BPF_OR:
				case BPF_LSH:
				case BPF_RSH:
				case BPF_XOR:
				case BPF_ARSH: {
					if (!insn->imm) {
						info->deleted = true;
						++count;
					}
					break;
				}
				case BPF_MUL:
				case BPF_DIV: {
					if (insn->imm == 1) {
						info->deleted = true;
						++count;
					}
					break;
				}
				case BPF_AND: {
					if (insn->imm == -1) {
						info->deleted = true;
						++count;
					}
					break;
				}
				}
			} else if (BPF_OP(insn->code) == BPF_MOV) {
				if (info->reg_states[insn->dst_reg] ==
					info->reg_states[insn->src_reg] &&
				    info->reg_states[insn->dst_reg] !=
					VAR_STATE &&
				    info->reg_states[insn->src_reg]) {
					info->deleted = true;
					++count;
				}
			}

			break;
		}
		}
	}

	for (pos = 0; pos < prog->len; ++pos) {
		struct bpf_insn *insn = &prog->insnsi[pos];
		struct instr_info *info = &infos[pos];

		if (BPF_CLASS(insn->code) == BPF_JMP &&
		    BPF_OP(insn->code) >= BPF_JA &&
		    BPF_OP(insn->code) <= BPF_JSGE) {
			/* Find jump target that is not deleted and no
			 * unconditional jump
			 */
			int target_pos = pos + insn->off + 1;
			int pos2;
			bool found;

			while (true) {
				struct bpf_insn *insn2 =
				    &prog->insnsi[target_pos];

				if (BPF_CLASS(insn2->code) == BPF_JMP &&
				    BPF_OP(insn2->code) == BPF_JA)
					target_pos += insn2->off + 1;
				else if (infos[target_pos].deleted)
					++target_pos;
				else
					break;
			}

			/* If instruction jumps only to the following -> delete
			 */
			pos2 = min(pos + 1, target_pos);
			found = false;
			while (pos2 < max(pos + 1, target_pos)) {
				if (!infos[pos2].deleted) {
					found = true;
					break;
				}

				++pos2;
			}

			if (!found) {
				/* Jump not necessary */
				info->deleted = true;
				++count;
			}
		}
	}
}

static void delete_deletable(struct bpf_prog *prog, struct instr_info *infos)
{
	struct bpf_insn *new_insns;
	struct bpf_insn *new_insn;
	int pos;
	int len;

	new_insns = kmalloc(sizeof(struct bpf_insn) * prog->len, GFP_KERNEL);
	new_insn = new_insns;

	for (pos = 0; pos < prog->len; ++pos) {
		struct bpf_insn *insn = &prog->insnsi[pos];
		struct instr_info *info = &infos[pos];

		if (info->deleted)
			continue;

		*new_insn = *insn;
		if (BPF_CLASS(new_insn->code) == BPF_JMP) {
			/* Find jump target that is not deleted and no
			 * unconditional jump
			 */
			int target_pos = pos + new_insn->off + 1;
			int pos2;

			while (true) {
				insn = &prog->insnsi[target_pos];
				info = &infos[target_pos];

				if (BPF_CLASS(insn->code) == BPF_JMP &&
				    BPF_OP(insn->code) == BPF_JA)
					target_pos += insn->off + 1;
				else if (info->deleted)
					++target_pos;
				else
					break;
			}

			/* Fix jump offset */
			new_insn->off = target_pos - pos - 1;

			if (new_insn->off >= 0) {
				for (pos2 = pos + 1; pos2 < target_pos;
				     ++pos2) {
					if (infos[pos2].deleted)
						--new_insn->off;
				}
			} else {
				for (pos2 = pos - 1; pos2 > target_pos;
				     --pos2) {
					if (infos[pos2].deleted)
						++new_insn->off;
				}
			}
		}

		++new_insn;
	}

	len = new_insn - new_insns;
	bpf_prog_realloc(prog, bpf_prog_size(len), 0);
	memcpy(prog->insnsi, new_insns, len * sizeof(struct bpf_insn));
	prog->len = len;
	kfree(new_insns);
}

void mptcp_rbs_optimize_ebpf_ld_sts(struct bpf_prog *prog)
{
	struct instr_info *infos;

	infos = kzalloc(sizeof(struct instr_info) * prog->len, GFP_KERNEL);
	fill_infos(prog, 0, infos, NULL);
	find_deletable(prog, infos);
	delete_deletable(prog, infos);

	kfree(infos);
}
