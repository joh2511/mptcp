#include "mptcp_rbs_optimizer_ebpf_regalloc.h"
#include "mptcp_rbs_dynarray.h"
#include "mptcp_rbs_optimizer_ebpf_lse.h"
#include <linux/bpf.h>
#include <linux/string.h>

#define IS_OFF_JMP(insn)                                                       \
	(BPF_CLASS((insn)->code) == BPF_JMP && BPF_OP((insn)->code) <= BPF_JSGE)
#define TEMP_TO_BIT(temp) (1ull << (temp))
#define BIT_DIFF(a, b) ((a) & ~(b))

/*
 * eBPF block lists
 */

DECL_DA(block_list, struct mptcp_rbs_ebpf_block *);

#define INIT_BLOCK_LIST(list) INIT_DA(list)

#define FREE_BLOCK_LIST(list) FREE_DA(list)

#define ADD_BLOCK(list, block) ADD_DA_ITEM(list, block)

#define GET_BLOCK_LIST_LEN(list) GET_DA_LEN(list)

#define GET_BLOCK(list, index) GET_DA_ITEM(list, index)

#define FOREACH_BLOCK(list, var, cmds) FOREACH_DA_ITEM(list, var, cmds)

#define FOREACH_BLOCK_REV(list, var, cmds) FOREACH_DA_ITEM_REV(list, var, cmds)

/*
 * Critical edge block lists
 */

DECL_DA(edge_block_list, struct edge_block *);

#define INIT_EDGE_BLOCK_LIST(list) INIT_DA(list)

#define FREE_EDGE_BLOCK_LIST(list) FREE_DA(list)

#define ADD_EDGE_BLOCK(list, block) ADD_DA_ITEM(list, block)

#define GET_EDGE_BLOCK_LIST_LEN(list) GET_DA_LEN(list)

#define GET_EDGE_BLOCK(list, index) GET_DA_ITEM(list, index)

enum {
	/** Temporary was not written yet */
	TEMP_STATE_NONE,
	/** Temporary is spilled */
	TEMP_STATE_SPILLED,
	/** Temporary is in register */
	TEMP_STATE_REG
};

/** Macro to determine the offset on the stack where the temporary can be
 * spilled
 */
#define TEMP_STACK_OFF(temp) ((temp + 1) * -8)

/** The state of a temporary */
struct temp_state {
	/**
	 * State of the temporary (see TEMP_STATE_* and the register number it
	 * is in
	 */
	u8 state : 2, reg : 6;
};

/** A single live range. Organized in a linked list */
struct live_range {
	struct live_range *next;
	/**
	 * Start position of the range and a bit determining if the temporary is
	 * written at the position
	 */
	u32 def : 1, start : 31;
	/** End position of the range - 1 */
	u32 end;
};

/** Information about a temporary */
struct temp_info {
	/** Live interval of the temporary */
	struct live_range *live_interval;
	/** The previous active live range */
	struct live_range *prev_range;
};

/** Context for register allocation */
struct ctx {
	/** The eBPF program where the instructions should be stored */
	struct bpf_prog *prog;
	/** List with eBPF blocks in depth first order */
	struct block_list blocks;
	/** List with critical edge blocks */
	struct edge_block_list edge_blocks;
	/** The current block */
	struct mptcp_rbs_ebpf_block *block;
	/** Information of the current block */
	// struct block_info *block_info;
	/** Current eBPF instruction */
	struct mptcp_rbs_ebpf_instr *instr;
	/** The ARE_CONSISTENT set */
	u64 A;
	/** Position of current instruction */
	u32 pos;
	/** Information about temporaries */
	struct {
		/** Information about temporaries */
		struct temp_info *infos[MAX_TEMPS];
		/** State of temporaries */
		struct temp_state states[MAX_TEMPS];
		/** Number of used temporaries */
		u8 count;
	} temps;
	/**
	 * Array to map registers to the temporary that is currently placed in +
	 * 1. 0 means that no temporary is stored. R10 is reserved for the stack
	 * pointer
	 */
	u8 regs[MAX_BPF_REG - 1];
};

/** Block that is inserted by the allocator on a critical edge */
struct edge_block {
	/** Absolute position of the first instruction of the block */
	u32 insn_pos;
	/**
	 * Number of instructions in this block. This is important to calculate
	 * jump offsets
	 */
	u16 insn_count;
	/** Index of the block in the edge block list */
	u16 idx;
};

/** Per block information for register allocation */
struct block_info {
	/** List with predecessor blocks */
	struct block_list preds;
	/** USE set to calculate lifetimes */
	u64 use;
	/** DEF set to calculate lifetimes */
	u64 def;
	/** IN set for the data flow analysis */
	u64 in;
	/** OUT set for the data flow analysis */
	u64 out;
	/** Local copy of the ARE_CONSISTENT set */
	u64 A;
	/** The KILL set */
	u64 K;
	/** Absolute position of the first instruction of the block */
	u32 insn_pos;
	/**
	 * Number of instructions in this block. This is important to calculate
	 * jump offsets
	 */
	u16 insn_count;
	/** Index of the block in the list */
	u16 idx;
	/**
	 * Critical edge block of the else edge of this block. If edge_block.
	 * insn_count == 0 there is no critical edge block
	 */
	struct edge_block edge_block;
	/** Position of the first instruction of the block */
	u16 pos;
	/** true if jump is necessary on the end of the block */
	bool needs_jmp;
	/** Information about temporaries */
	struct {
		/** State of temporaries when the block is entered */
		struct temp_state entry_states[MAX_TEMPS];
		/** State of temporaries when the block is left */
		struct temp_state exit_states[MAX_TEMPS];
	} temps;
};

#define BLOCK_INFO(block) ((struct block_info *) (block)->tag)

/**
 * Traverses through eBPF blocks and stores them inside a list in depth first
 * order
 * @ctx: The allocator context
 * @block: The current block
 */
static void traverse(struct ctx *ctx, struct mptcp_rbs_ebpf_block *block)
{
	struct mptcp_rbs_ebpf_block *block2;
	struct block_info *info;
	u8 code;

	/* Check if the block is already in the list */
	FOREACH_BLOCK(&ctx->blocks, block2, if (block == block2) return );

	/* Check if every block has a jump instruction at the end */
	code = block->instrs[block->instr_count - 1].insn.code;
	BUG_ON(BPF_CLASS(code) != BPF_JMP);
	BUG_ON(BPF_OP(code) != BPF_JA && BPF_OP(code) != BPF_EXIT);

	info = kzalloc(sizeof(struct block_info), GFP_KERNEL);
	INIT_BLOCK_LIST(&info->preds);
	info->idx = GET_BLOCK_LIST_LEN(&ctx->blocks);
	info->pos = ctx->pos;
	block->tag = info;
	ADD_BLOCK(&ctx->blocks, block);

	ctx->pos += block->instr_count;

	if (block->next)
		traverse(ctx, block->next);
	if (block->next_else)
		traverse(ctx, block->next_else);
}

/**
 * Calculates the lifetimes of all used temporaries and stores them as struct
 * lifetime_block_info in the blocks' tag fields
 * @ctx: The allocator context
 */
static void calc_lifetimes(struct ctx *ctx)
{
	struct mptcp_rbs_ebpf_block *block;
	bool changes;

	/* Calculate USE and DEF sets */
	FOREACH_BLOCK(&ctx->blocks, block, {
		struct block_info *info = BLOCK_INFO(block);
		struct mptcp_rbs_ebpf_instr *cur;
		struct mptcp_rbs_ebpf_instr *end;

		cur = block->instrs;
		end = cur + block->instr_count;
		for (; cur != end; ++cur) {
			u64 read = 0;
			u64 write = 0;
			int i;

			for (i = 0; i < MAX_ARGS; ++i) {
				if (cur->read[i].used)
					read |= TEMP_TO_BIT(cur->read[i].temp);
			}
			if (cur->write.used)
				write = TEMP_TO_BIT(cur->write.temp);

			info->use |= ~info->def & read;
			info->def |= ~info->use & write;
		}
	});

	/* Iterate until no changes for IN(B) were found */
	do {
		changes = false;

		FOREACH_BLOCK_REV(&ctx->blocks, block, {
			struct block_info *info = BLOCK_INFO(block);
			u64 old_in = info->in;

			/* OUT(B) = U IN(S) where S elementof succ(B) */
			info->out =
			    block->next ? BLOCK_INFO(block->next)->in : 0;
			if (block->next_else)
				info->out |= BLOCK_INFO(block->next_else)->in;

			/* IN(B) = use(B) U (OUT(B) - def(B)) */
			info->in = info->use | BIT_DIFF(info->out, info->def);

			changes = changes || old_in != info->in;
		});
	} while (changes);
}

/**
 * Calculates the live ranges of all used temporaries and stores them in the
 * context
 * @ctx: The allocator context
 */
static void calc_liveranges(struct ctx *ctx)
{
	struct mptcp_rbs_ebpf_block *block;
	struct live_range *last_live_ranges[MAX_TEMPS];
	u32 pos;

	/* Calculate the normal life times first */
	calc_lifetimes(ctx);

	/* Calculate the live ranges */
	memset(last_live_ranges, 0, sizeof(last_live_ranges));
	pos = 0;
	FOREACH_BLOCK(&ctx->blocks, block, {
		struct block_info *info = BLOCK_INFO(block);
		struct mptcp_rbs_ebpf_instr *cur;
		struct mptcp_rbs_ebpf_instr *end;
		struct live_range *range;
		int i;

		/* Create live ranges without end position for live temporaries
		 * at block entry
		 */
		for (i = 0; i < ctx->temps.count; ++i) {
			if (info->in & TEMP_TO_BIT(i)) {
				range = kzalloc(sizeof(struct live_range),
						GFP_KERNEL);
				range->start = pos;
				if (last_live_ranges[i])
					last_live_ranges[i]->next = range;
				else
					ctx->temps.infos[i]->live_interval =
					    range;
				last_live_ranges[i] = range;
			}
		}

		cur = block->instrs;
		end = cur + block->instr_count;
		for (; cur != end; ++cur, ++pos) {
			for (i = 0; i < MAX_ARGS; ++i) {
				if (cur->read[i].used) {
					BUG_ON(!last_live_ranges[cur->read[i]
								     .temp]);

					last_live_ranges[cur->read[i].temp]
					    ->end = pos - 1;
				}
			}

			if (cur->write.used) {
				/* Check if there is already an open live range
				 */
				i = cur->write.temp;

				range = last_live_ranges[i];
				if (range && !range->end) {
					/* Reuse live range */
				} else {
					range =
					    kzalloc(sizeof(struct live_range),
						    GFP_KERNEL);
					if (last_live_ranges[i])
						last_live_ranges[i]->next =
						    range;
					else
						ctx->temps.infos[i]
						    ->live_interval = range;
					last_live_ranges[i] = range;
				}

				range->def = true;
				range->start = pos;
			}
		}

		/* Set the end positions of ranges for temporaries that are live
		 * at the end of the block
		 */
		for (i = 0; i < ctx->temps.count; ++i) {
			if (info->out & TEMP_TO_BIT(i)) {
				BUG_ON(!last_live_ranges[i]);

				last_live_ranges[i]->end = pos - 1;
			}
		}
	});
}

static void insert_insn(struct ctx *ctx, int idx, struct bpf_insn insn)
{
	if (bpf_prog_size(ctx->prog->len) == ctx->prog->pages * PAGE_SIZE) {
		ctx->prog = bpf_prog_realloc(
		    ctx->prog, bpf_prog_size(ctx->prog->len + 10), 0);
	}

	if (idx != ctx->prog->len)
		memmove(&ctx->prog->insnsi[idx + 1], &ctx->prog->insnsi[idx],
			(ctx->prog->len - idx) * sizeof(struct bpf_insn));
	ctx->prog->insnsi[idx] = insn;
	++ctx->prog->len;
}

static inline void add_insn(struct ctx *ctx, struct bpf_insn insn)
{
	insert_insn(ctx, ctx->prog->len, insn);
}

static struct live_range *find_next_range(struct ctx *ctx, int temp)
{
	struct live_range *prev_range = ctx->temps.infos[temp]->prev_range;
	struct live_range *range;

	if (prev_range)
		range = prev_range->next;
	else
		range = ctx->temps.infos[temp]->live_interval;

	while (range && range->end + 1 < ctx->pos) {
		prev_range = range;
		range = range->next;
	}

	ctx->temps.infos[temp]->prev_range = prev_range;
	return range;
}

/**
 * Spills a register if necessary
 * @ctx: The allocation context
 * @reg: The register to spill
 */
static void spill_reg(struct ctx *ctx, int reg)
{
	struct block_info *info = BLOCK_INFO(ctx->block);
	int temp = ((int) ctx->regs[reg]) - 1;
	struct live_range *range;
	bool store = true;

	if (temp == -1) {
		/* Register is empty */
		return;
	}

	/* If the register is clean omit the store */
	if (ctx->A & TEMP_TO_BIT(temp))
		store = false;
	else {
		/* If the temporary's value won't be used in the future omit the
		 * store
		 */
		if (!(info->out & TEMP_TO_BIT(temp))) {
			range = find_next_range(ctx, temp);

			if (!range ||
			    range->start >=
				info->pos + ctx->block->instr_count ||
			    (range->def && range->start >= ctx->pos))
				store = false;
		}
	}

	if (store) {
		add_insn(ctx, BPF_STX_MEM(BPF_DW, BPF_REG_FP, reg,
					  TEMP_STACK_OFF(temp)));
		++info->insn_count;
		ctx->A |= TEMP_TO_BIT(temp);
	}

	ctx->temps.states[temp].state = TEMP_STATE_SPILLED;
	ctx->regs[reg] = 0;
}

/**
 * Loads a temporary in a certain register. If its state != TEMP_STATE_NONE the
 * function will insert a load from the spill location
 * @ctx: The allocation context
 * @reg: Register that should contain the temporary
 * @temp: The temporary that should be loaded into the register
 */
static void load_in_reg(struct ctx *ctx, int reg, int temp)
{
	struct temp_state *state = &ctx->temps.states[temp];

	BUG_ON(state->state == TEMP_STATE_REG);

	/* Spill register if necessary */
	spill_reg(ctx, reg);

	if (state->state != TEMP_STATE_NONE) {
		add_insn(ctx, BPF_LDX_MEM(BPF_DW, reg, BPF_REG_FP,
					  TEMP_STACK_OFF(temp)));
		++BLOCK_INFO(ctx->block)->insn_count;
		ctx->A |= TEMP_TO_BIT(temp);
	} else
		ctx->A &= ~TEMP_TO_BIT(temp);

	/* Assign register to temporary */
	ctx->regs[reg] = temp + 1;
	state->state = TEMP_STATE_REG;
	state->reg = reg;
}

/**
 * The heuristic function of the allocator. This function decides which register
 * to allocate for a temporary
 * @ctx: The allocation context
 * @temp: The temporary the function should find a register for
 * @return: The register to allocate
 */
static int find_reg(struct ctx *ctx, int temp)
{
	struct mptcp_rbs_ebpf_instr *instr = ctx->instr;
	int start;
	int end;
	int reg;
	int temp2;
	struct live_range *range;
	int i;
	int prop_reg = -1;
	int prop_delta = -1;
	int prop_reg2 = -1;
	int prop_delta2 = -1;
	bool used;

	/* Check the callee saved registers first */
	start = BPF_REG_6;
	end = BPF_REG_9;

	while (true) {
		for (reg = start; reg <= end; ++reg) {
			temp2 = ((int) ctx->regs[reg]) - 1;

			if (temp2 == -1) {
				/* Register is free */
				return reg;
			}

			/* Check if register is already used by another operand
			 */
			used = false;
			for (i = 0; i < MAX_ARGS; ++i) {
				if (instr->read[i].used &&
				    instr->read[i].temp == temp2) {
					used = true;
					break;
				}
			}
			if (used)
				continue;

			/* Check live ranges */
			range = find_next_range(ctx, temp2);

			if (!range) {
				/* Best candidate found because the temporary
				 * won't be used again
				 */
				return reg;
			}
			if (range->start > ctx->pos) {
				/* Very good candidate found */
				int delta = range->start - ctx->pos;
				if (prop_delta < delta) {
					prop_reg = reg;
					prop_delta = range->start - ctx->pos;
				}
			} else {
				/* Candidate found */
				int delta = range->end - ctx->pos;
				if (prop_delta2 < delta) {
					prop_reg2 = reg;
					prop_delta2 = range->end - ctx->pos;
				}
			}
		}

		if (start == BPF_REG_0)
			break;

		/* Next check all other registers except R10 */
		start = BPF_REG_0;
		end = BPF_REG_5;
	}

	if (prop_reg != -1)
		return prop_reg;

	BUG_ON(prop_reg2 == -1);
	return prop_reg2;
}

/**
 * Generalized version of load_in_reg where the function decides the register.
 * This function ensures that other instruction operands are not spilled
 * @ctx: The allocation context
 * @temp: The temporary that should be loaded in a register
 */
static void load_in_any_reg(struct ctx *ctx, int temp)
{
	load_in_reg(ctx, find_reg(ctx, temp), temp);
}

/**
 * Allocates registers for the current call instruction
 * @ctx: The allocation context
 * @insn: The target instruction that will be added to the eBPF program
 */
static void alloc_call_instr_regs(struct ctx *ctx, struct bpf_insn *insn)
{
	struct block_info *info = BLOCK_INFO(ctx->block);
	struct mptcp_rbs_ebpf_instr *instr = ctx->instr;
	int temp;
	struct temp_state *state;
	int i;

	/* Parameters */
	for (i = 0; i < MAX_ARGS; ++i) {
		if (instr->read[i].used) {
			temp = instr->read[i].temp;
			state = &ctx->temps.states[temp];

			if (state->state == TEMP_STATE_REG) {
				if (state->reg != BPF_REG_ARG1 + i) {
					spill_reg(ctx, BPF_REG_ARG1 + i);

					/* Copy the value */
					add_insn(ctx,
						 BPF_MOV64_REG(BPF_REG_ARG1 + i,
							       state->reg));
					++info->insn_count;
					continue;
				}
			} else {
				/* Load the value and spill it to ensure
				 * that it is not lost during the call
				 */
				load_in_reg(ctx, BPF_REG_ARG1 + i, temp);
			}
		}

		spill_reg(ctx, BPF_REG_ARG1 + i);
	}

	/* Return value */
	if (instr->write.used) {
		temp = instr->write.temp;
		state = &ctx->temps.states[temp];

		if (state->state == TEMP_STATE_REG) {
			/* Discard register */
			ctx->regs[state->reg] = 0;
		}
		state->state = TEMP_STATE_NONE;

		load_in_reg(ctx, BPF_REG_0, temp);

		info->K |= TEMP_TO_BIT(temp);
	} else
		spill_reg(ctx, BPF_REG_0);
}

/**
 * Allocates registers for the current instruction
 * @ctx: The allocation context
 * @insn: The target instruction that will be added to the eBPF program
 */
static void alloc_instr_regs(struct ctx *ctx, struct bpf_insn *insn)
{
	struct block_info *info = BLOCK_INFO(ctx->block);
	struct mptcp_rbs_ebpf_instr *instr = ctx->instr;
	int temp;
	int temp2;
	struct temp_state *state;
	struct temp_state *state2;

	if (BPF_CLASS(insn->code) == BPF_JMP &&
	    BPF_OP(insn->code) == BPF_CALL) {
		alloc_call_instr_regs(ctx, insn);
		return;
	}

	if (instr->read[0].used) {
		temp = instr->read[0].temp;
		state = &ctx->temps.states[temp];

		if (instr->write.used && temp != instr->write.temp) {
			temp2 = instr->write.temp;
			state2 = &ctx->temps.states[temp2];

			/* Get any register for the written temporary */
			if (state2->state != TEMP_STATE_REG) {
				state2->state = TEMP_STATE_NONE;
				load_in_any_reg(ctx, temp2);
			}

			/* Load value of the read temporary to the written one
			 */
			if (state->state == TEMP_STATE_REG)
				add_insn(ctx, BPF_MOV64_REG(state2->reg,
							    state->reg));
			else
				add_insn(ctx,
					 BPF_LDX_MEM(BPF_DW, state2->reg,
						     BPF_REG_FP,
						     TEMP_STACK_OFF(temp)));
			++info->insn_count;

			insn->dst_reg = state2->reg;
		} else {
			if (state->state != TEMP_STATE_REG)
				load_in_any_reg(ctx, temp);

			insn->dst_reg = state->reg;
		}
	}

	if (instr->write.used) {
		temp = instr->write.temp;

		if (!instr->read[0].used) {
			state = &ctx->temps.states[temp];

			if (state->state != TEMP_STATE_REG)
				load_in_any_reg(ctx, temp);

			insn->dst_reg = state->reg;
		}

		ctx->A &= ~TEMP_TO_BIT(temp);
		info->K |= TEMP_TO_BIT(temp);
	}

	if (instr->read[1].used) {
		state = &ctx->temps.states[instr->read[1].temp];

		if (state->state != TEMP_STATE_REG)
			load_in_any_reg(ctx, instr->read[1].temp);

		insn->src_reg = state->reg;
	}
}

/**
 * Inserts a correction that was found during the resolution phase. This
 * function might insert critical edge blocks if necessary
 * @ctx: The allocation context
 * @p: The predecessor block of the edge where the correction should be inserted
 * @s: The successor block of the edge where the correction should be inserted
 * @insn: The instruction that should be inserted
 */
static void insert_correction(struct ctx *ctx, struct mptcp_rbs_ebpf_block *p,
			      struct mptcp_rbs_ebpf_block *s,
			      struct bpf_insn insn)
{
	struct block_info *info = BLOCK_INFO(p);
	struct block_info *info2 = BLOCK_INFO(s);
	int edge_list_len = GET_EDGE_BLOCK_LIST_LEN(&ctx->edge_blocks);
	int i;

	if (p->next_else == s) {
		/* Critical edge */
		struct edge_block *edge = &info->edge_block;

		BUG_ON(p->next == s);

		if (!edge->insn_count) {
			/* Create edge block */
			struct bpf_insn *cur;
			struct bpf_insn *end;

			edge->insn_pos = ctx->prog->len;
			edge->insn_count = 1;
			edge->idx = edge_list_len;
			ADD_EDGE_BLOCK(&ctx->edge_blocks, edge);
			add_insn(ctx, BPF_JMP_OFF(info2->idx));

			/* Find jump in s to p and replace it with jump to new
			 * edge block
			 */
			cur = &ctx->prog->insnsi[info->insn_pos +
						 info->insn_count - 1];
			end = cur - info->insn_count;

			for (; cur != end; --cur) {
				if (IS_OFF_JMP(cur) && cur->off == info2->idx) {
					cur->off =
					    GET_BLOCK_LIST_LEN(&ctx->blocks) +
					    edge->idx;
					break;
				}
			}
		} else {
			/* Correct following edge block positions */
			for (i = edge->idx + 1; i < edge_list_len; ++i) {
				++GET_EDGE_BLOCK(&ctx->edge_blocks, i)
				      ->insn_pos;
			}
		}

		insert_insn(ctx, edge->insn_pos + edge->insn_count - 1, insn);
		++edge->insn_count;
		return;
	}

	/* Correct following block and edge block positions */
	for (i = info->idx + 1; i < GET_BLOCK_LIST_LEN(&ctx->blocks); ++i) {
		++BLOCK_INFO(GET_BLOCK(&ctx->blocks, i))->insn_pos;
	}

	for (i = 0; i < edge_list_len; ++i) {
		++GET_EDGE_BLOCK(&ctx->edge_blocks, i)->insn_pos;
	}

	insert_insn(ctx, info->insn_pos + info->insn_count -
			     (info->needs_jmp ? 1 : 0),
		    insn);
	++info->insn_count;
}

/**
 * Performes the resolution phase
 * @ctx: The allocation context
 */
static void resolve(struct ctx *ctx)
{
	struct mptcp_rbs_ebpf_block *block;
	bool changes;

	/* Reset IN and OUT sets for resolution phase */
	FOREACH_BLOCK(&ctx->blocks, block, {
		struct block_info *info = BLOCK_INFO(block);
		info->in = 0;
		info->out = 0;
	});

	/* Perform the dataflow analysis */
	do {
		changes = false;

		FOREACH_BLOCK_REV(&ctx->blocks, block, {
			struct block_info *info = BLOCK_INFO(block);
			u64 old_in = info->in;

			/* OUT(B) = U IN(S) where S elementof succ(B) */
			info->out =
			    block->next ? BLOCK_INFO(block->next)->in : 0;
			if (block->next_else)
				info->out |= BLOCK_INFO(block->next_else)->in;

			/* IN(B) = ~K ^ A U (OUT(B) - K) */
			info->in =
			    (~info->K & info->A) | BIT_DIFF(info->out, info->K);

			changes = changes || old_in != info->in;
		});
	} while (changes);

	/* Search different temporary storages among edges */
	FOREACH_BLOCK(&ctx->blocks, block, {
		struct block_info *info = BLOCK_INFO(block);
		struct mptcp_rbs_ebpf_block *block2;

		FOREACH_BLOCK(&info->preds, block2, {
			struct block_info *info2 = BLOCK_INFO(block2);
			u64 s = info->in & ~info2->A;
			u64 stored_by_move;
			int i;

			/* 0. Fill ctx->regs with registers of block2 that are
			 * also in registers in block
			 */
			memset(&ctx->regs[0], 0, sizeof(ctx->regs));
			for (i = 0; i < ctx->temps.count; ++i) {
				struct temp_state *state =
				    &info->temps.entry_states[i];
				struct temp_state *state2 =
				    &info2->temps.exit_states[i];

				if (state2->state == TEMP_STATE_REG &&
				    state->state == TEMP_STATE_REG)
					ctx->regs[state2->reg] = i + 1;
			}

			/* 1. Insert necessary stores */
			for (i = 0; i < ctx->temps.count; ++i) {
				struct temp_state *state =
				    &info->temps.entry_states[i];
				struct temp_state *state2 =
				    &info2->temps.exit_states[i];

				if (state2->state == TEMP_STATE_REG &&
				    (state->state != TEMP_STATE_REG ||
				     s & TEMP_TO_BIT(i)) &&
				    !(info2->A & TEMP_TO_BIT(i))) {
					/* Insert store */
					insert_correction(
					    ctx, block2, block,
					    BPF_STX_MEM(BPF_DW, BPF_REG_FP,
							state2->reg,
							TEMP_STACK_OFF(i)));
				}
			}

			/* 2. Insert necessary moves */
			stored_by_move = 0;
			for (i = 0; i < ctx->temps.count; ++i) {
				struct temp_state *state =
				    &info->temps.entry_states[i];
				struct temp_state *state2 =
				    &info2->temps.exit_states[i];

				if (!(stored_by_move & TEMP_TO_BIT(i)) &&
				    state2->state == TEMP_STATE_REG &&
				    state->state == TEMP_STATE_REG &&
				    state->reg != state2->reg) {
					/* Insert move */
					int reg_temp =
					    ((int) ctx->regs[state->reg]) - 1;
					if (reg_temp != -1) {
						/* Other value in register */
						/* TODO We could use registers
						 * for swapping etc. For now we
						 * just store the value in
						 * memory
						 */
						if (!(info2->A &
						      TEMP_TO_BIT(reg_temp))) {
							insert_correction(
							    ctx, block2, block,
							    BPF_STX_MEM(
								BPF_DW,
								BPF_REG_FP,
								state->reg,
								TEMP_STACK_OFF(
								    reg_temp)));
						}
						stored_by_move |=
						    TEMP_TO_BIT(reg_temp);
					}

					insert_correction(
					    ctx, block2, block,
					    BPF_MOV64_REG(state->reg,
							  state2->reg));
					ctx->regs[state2->reg] = 0;
				}
			}

			/* 3. Insert necessary loads */
			for (i = 0; i < ctx->temps.count; ++i) {
				struct temp_state *state =
				    &info->temps.entry_states[i];
				struct temp_state *state2 =
				    &info2->temps.exit_states[i];

				if ((stored_by_move & TEMP_TO_BIT(i) ||
				     state2->state != TEMP_STATE_REG) &&
				    state->state == TEMP_STATE_REG) {
					/* Insert load */
					insert_correction(
					    ctx, block2, block,
					    BPF_LDX_MEM(BPF_DW, state->reg,
							BPF_REG_FP,
							TEMP_STACK_OFF(i)));
				}
			}
		});
	});
}

/**
 * Performs the actual register allocation as described in "Quality and Speed in
 * Linear-Scan Register Allocation" written by Omri Traub
 * @ctx: The allocation context
 */
static void alloc_regs(struct ctx *ctx)
{
	struct mptcp_rbs_ebpf_block **block_ptr;
	struct mptcp_rbs_ebpf_block **block_end;
	struct mptcp_rbs_ebpf_block *block;
	u32 insn_pos;

	/* Iterate over all instructions and allocate registers */
	ctx->pos = 0;
	insn_pos = 0;
	block_ptr = ctx->blocks.items;
	block_end = ctx->blocks.items + ctx->blocks.len;
	for (; block_ptr != block_end; ++block_ptr) {
		struct block_info *info;
		struct mptcp_rbs_ebpf_instr *end;
		struct bpf_insn insn;

		block = *block_ptr;
		ctx->block = block;
		info = BLOCK_INFO(block);

		/* Set position of block */
		info->insn_pos = insn_pos;

		/* Add block as predecessor */
		if (block->next)
			ADD_BLOCK(&BLOCK_INFO(block->next)->preds, block);
		if (block->next_else)
			ADD_BLOCK(&BLOCK_INFO(block->next_else)->preds, block);

		/* Remember the temporary states on entry */
		memcpy(&info->temps.entry_states, ctx->temps.states,
		       sizeof(ctx->temps.states));

		ctx->instr = block->instrs;
		end = ctx->instr + block->instr_count;
		for (; ctx->instr != end; ++ctx->instr, ++ctx->pos) {
			insn = ctx->instr->insn;
			alloc_instr_regs(ctx, &insn);

			/* Set jump offsets to the block indexes in the ordered
			 * list
			 */
			if (IS_OFF_JMP(&insn)) {
				if (BPF_OP(insn.code) == BPF_JA) {
					/* JA must be the last instruction in
					 * the block
					 */
					BUG_ON(ctx->instr + 1 != end);
					BUG_ON(!block->next);

					insn.off = BLOCK_INFO(block->next)->idx;

					/* Do not insert jumps if the next block
					 * follows directly
					 */
					info->needs_jmp =
					    block_ptr + 1 == block_end ||
					    *(block_ptr + 1) != block->next;
					if (!info->needs_jmp)
						continue;
				} else {
					/* Jumps except JA must be the second to
					 * last instructions
					 */
					BUG_ON(ctx->instr + 1 == end ||
					       ctx->instr + 2 != end);
					BUG_ON(!block->next_else);

					insn.off =
					    BLOCK_INFO(block->next_else)->idx;
				}
			}

			add_insn(ctx, insn);
			++info->insn_count;
		}

		/* Remember the temporary states on exit and store a local copy
		 * of A
		 */
		memcpy(&info->temps.exit_states, ctx->temps.states,
		       sizeof(ctx->temps.states));
		info->A = ctx->A;

		insn_pos += info->insn_count;
	}

	/* Resolution phase */
	resolve(ctx);
}

/**
 * Corrects jump instructions to point to the correct destination blocks
 * @ctx: The allocation context
 */
static void correct_jmps(struct ctx *ctx)
{
	struct bpf_insn *cur;
	struct bpf_insn *end;
	int block_count = GET_BLOCK_LIST_LEN(&ctx->blocks);
	u32 insn_pos;

	insn_pos = 0;
	cur = &ctx->prog->insnsi[0];
	end = cur + ctx->prog->len;
	for (; cur != end; ++cur, ++insn_pos) {
		if (IS_OFF_JMP(cur)) {
			u32 dst;

			if (cur->off >= block_count)
				dst = GET_EDGE_BLOCK(&ctx->edge_blocks,
						     cur->off - block_count)
					  ->insn_pos;
			else
				dst = BLOCK_INFO(
					  GET_BLOCK(&ctx->blocks, cur->off))
					  ->insn_pos;

			cur->off = dst - insn_pos - 1;
		}
	}
}

struct bpf_prog *mptcp_rbs_ebpf_alloc_regs(
    struct mptcp_rbs_ebpf_block *first_block, int used_temps,
    struct bpf_prog *prog)
{
	struct mptcp_rbs_ebpf_block *block;
	struct ctx ctx;
	int i;

	/* Initialize the context */
	memset(&ctx, 0, sizeof(struct ctx));
	INIT_BLOCK_LIST(&ctx.blocks);
	INIT_EDGE_BLOCK_LIST(&ctx.edge_blocks);

	for (i = 0; i < used_temps; ++i) {
		ctx.temps.infos[i] =
		    kzalloc(sizeof(struct temp_info), GFP_KERNEL);
	}
	ctx.temps.count = used_temps;

	/* Traverse CFG into list and set program size to total number of
	 * instructions
	 */
	traverse(&ctx, first_block);
	ctx.prog = bpf_prog_realloc(prog, bpf_prog_size(ctx.pos), 0);

	/* Calculate live ranges of temporaries */
	calc_liveranges(&ctx);

	/* Perform the actual register allocation */
	alloc_regs(&ctx);

	/* Correct offsets of jump instructions */
	correct_jmps(&ctx);

	/* Release the context and the blocks' tag fields */
	FOREACH_BLOCK(&ctx.blocks, block, {
		struct block_info *info = BLOCK_INFO(block);
		FREE_BLOCK_LIST(&info->preds);
		kfree(info);
	});
	FREE_BLOCK_LIST(&ctx.blocks);
	FREE_EDGE_BLOCK_LIST(&ctx.edge_blocks);
	for (i = 0; i < used_temps; ++i) {
		struct temp_info *info = ctx.temps.infos[i];

		while (info->live_interval) {
			struct live_range *range = info->live_interval;
			info->live_interval = range->next;
			kfree(range);
		}

		kfree(info);
	}

	mptcp_rbs_optimize_ebpf_ld_sts(ctx.prog);
	return ctx.prog;
}

void mptcp_rbs_ebpf_block_free(struct mptcp_rbs_ebpf_block *block)
{
	kfree(block->instrs);
	kfree(block);
}

static void simple_traverse(struct mptcp_rbs_ebpf_block *block,
			    struct block_list *list)
{
	struct mptcp_rbs_ebpf_block *block2;

	/* Check if the block is already in the list */
	FOREACH_BLOCK(list, block2, if (block == block2) return );
	ADD_BLOCK(list, block);

	if (block->next)
		simple_traverse(block->next, list);
	if (block->next_else)
		simple_traverse(block->next_else, list);
}

void mptcp_rbs_ebpf_blocks_free(struct mptcp_rbs_ebpf_block *first_block)
{
	struct block_list list;
	struct mptcp_rbs_ebpf_block *block;

	INIT_BLOCK_LIST(&list);
	simple_traverse(first_block, &list);

	FOREACH_BLOCK(&list, block, mptcp_rbs_ebpf_block_free(block));
	FREE_BLOCK_LIST(&list);
}
