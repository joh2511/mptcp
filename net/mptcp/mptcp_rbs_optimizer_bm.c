#include "mptcp_rbs_optimizer_bm.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"

#define SET_INCOMING(block, val) (block)->tag = (void *) (val)
#define GET_INCOMING(block) ((size_t)(block)->tag)
#define INC_INCOMING(block) ++*((size_t *) &(block)->tag)
#define DEC_INCOMING(block) --*((size_t *) &(block)->tag)

void mptcp_rbs_opt_bm(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_cfg_block *block;
	struct mptcp_rbs_cfg_block *next_block;
	bool modified;

	/* Fill tags of all blocks with number of incoming edges */
	INIT_BLOCK_LIST(&list);
	mptcp_rbs_cfg_block_traverse(ctx->variation->first_block, &list);
	FOREACH_BLOCK(&list, block, SET_INCOMING(block, 0));
	INC_INCOMING(ctx->variation->first_block);
	FOREACH_BLOCK(&list, block, {
		if (block->next)
			INC_INCOMING(block->next);
		if (block->next_else)
			INC_INCOMING(block->next_else);
	});

	/* This one is a fix point algorithm */
	do {
		modified = false;

		FOREACH_BLOCK(&list, block, {
			if (GET_INCOMING(block) == 0)
				continue;

			/* Remove condition if both paths point to the same
			 * block
			 */
			if (block->condition &&
			    block->next == block->next_else) {
				block->condition->free(block->condition);
				block->condition = NULL;
				block->next_else = NULL;
				if (block->next)
					DEC_INCOMING(block->next);
				modified = true;
				continue;
			}

			if (block->next && GET_INCOMING(block->next) == 1) {
				next_block = block->next;

				if (!block->condition) {
					/* Merge blocks */
					mptcp_rbs_cfg_block_append(
					    block, next_block->first_smt);
					block->condition =
					    next_block->condition;
					block->next = next_block->next;
					block->next_else =
					    next_block->next_else;

					next_block->first_smt = NULL;
					next_block->condition = NULL;
					next_block->next = NULL;
					next_block->next_else = NULL;
					DEC_INCOMING(next_block);
					modified = true;
					continue;
				} else if (!next_block->first_smt &&
					   !next_block->condition) {
					/* Remove next block */
					block->next = next_block->next;
					DEC_INCOMING(next_block);
					modified = true;
					continue;
				}
			}

			if (block->next_else &&
			    GET_INCOMING(block->next_else) == 1) {
				next_block = block->next_else;

				if (!next_block->first_smt &&
				    !next_block->condition) {
					/* Remove next else block */
					block->next_else = next_block->next;
					DEC_INCOMING(next_block);
					modified = true;
					continue;
				}
			}
		});
	} while (modified);

	FOREACH_BLOCK(&list, block, if (GET_INCOMING(block) == 0)
					mptcp_rbs_cfg_block_free(block));
	FREE_BLOCK_LIST(&list);
}
