#include "mptcp_rbs_optimizer_lu.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"

static struct mptcp_rbs_smt_var *find_next(
    struct mptcp_rbs_cfg_block *block, struct mptcp_rbs_cfg_block_list *list,
    struct mptcp_rbs_cfg_block_list *done_list,
    struct mptcp_rbs_cfg_block **found_block)
{
	struct mptcp_rbs_cfg_block *block2;
	struct mptcp_rbs_smt_var *var_smt;
	struct mptcp_rbs_smt *smt;
	bool already_done = false;

	/* Check if the block was already visited */
	FOREACH_BLOCK(list, block2, if (block == block2) return NULL);
	ADD_BLOCK(list, block);

	/* Check if this block holds a NEXT value that was already processed */
	FOREACH_BLOCK(done_list, block2, if (block == block2) {
		already_done = true;
		break;
	});

	if (!already_done) {
		smt = block->first_smt;
		while (smt) {
			if (smt->kind == SMT_KIND_VAR) {
				var_smt = (struct mptcp_rbs_smt_var *) smt;

				if (var_smt->value->kind ==
					VALUE_KIND_SBFLIST_NEXT &&
				    ((struct mptcp_rbs_value_sbf_list_next *)
					 var_smt->value)
					    ->list->kind ==
					VALUE_KIND_SBFLIST_VAR) {
					ADD_BLOCK(done_list, block);
					*found_block = block;
					return var_smt;
				}
			}

			smt = smt->next;
		}
	}

	if (block->next) {
		var_smt = find_next(block->next, list, done_list, found_block);
		if (var_smt)
			return var_smt;
	}

	if (block->next_else) {
		var_smt =
		    find_next(block->next_else, list, done_list, found_block);
		if (var_smt)
			return var_smt;
	}

	return NULL;
}

struct clone_ctx {
	int var_number;
	int list_var_number;
	int i;
};

static struct mptcp_rbs_value *clone_user(void *user_ctx,
					  const struct mptcp_rbs_value *value)
{
	struct clone_ctx *ctx = user_ctx;
	const struct mptcp_rbs_value_sbf_var *var_value;

	if (value->kind != VALUE_KIND_SBF_VAR)
		return NULL;

	var_value = (const struct mptcp_rbs_value_sbf_var *) value;
	if (var_value->var_number != ctx->var_number)
		return NULL;

	return (struct mptcp_rbs_value *) mptcp_rbs_value_sbf_list_get_new(
	    (struct mptcp_rbs_value_sbf_list *)
		mptcp_rbs_value_sbf_list_var_new(ctx->list_var_number),
	    (struct mptcp_rbs_value_int *) mptcp_rbs_value_constint_new(
		ctx->i));
}

static void clone_smts(struct mptcp_rbs_cfg_block *block,
		       const struct mptcp_rbs_smt *smt_template, int var_number,
		       int list_var_number, int i)
{
	struct clone_ctx clone_ctx;

	clone_ctx.var_number = var_number;
	clone_ctx.list_var_number = list_var_number;
	clone_ctx.i = i;

	while (smt_template) {
		struct mptcp_rbs_smt *clone;

		clone =
		    mptcp_rbs_smt_clone(smt_template, &clone_ctx, clone_user);

		mptcp_rbs_cfg_block_append(block, clone);
		smt_template = smt_template->next;
	}
}

static void unroll(struct mptcp_rbs_opt_ctx *ctx,
		   struct mptcp_rbs_smt_var *var_smt,
		   struct mptcp_rbs_cfg_block *block)
{
	int list_var_number;
	struct mptcp_rbs_smt *smt_template;
	struct mptcp_rbs_cfg_block *next_block = block->next;
	int i;

	list_var_number =
	    ((struct mptcp_rbs_value_sbf_list_var
		  *) ((struct mptcp_rbs_value_sbf_list_next *) var_smt->value)
		 ->list)
		->var_number;
	smt_template = next_block->first_smt;
	next_block->first_smt = NULL;

	for (i = 0; i < ctx->variation->sbf_num; ++i) {
		clone_smts(next_block, smt_template, var_smt->var_number,
			   list_var_number, i);
	}
	smt_template->free(smt_template);

	block->condition->free(block->condition);
	block->condition = NULL;
	block->next->next = block->next_else;
	block->next_else = NULL;
}

static bool find_loop(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_cfg_block_list *done_list)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_smt_var *var_smt;
	struct mptcp_rbs_cfg_block *block;

	INIT_BLOCK_LIST(&list);
	var_smt =
	    find_next(ctx->variation->first_block, &list, done_list, &block);

	if (var_smt && block->condition &&
	    block->condition->kind == VALUE_KIND_IS_NOT_NULL) {
		struct mptcp_rbs_value_is_not_null *cond =
		    (struct mptcp_rbs_value_is_not_null *) block->condition;

		if (cond->operand->kind == VALUE_KIND_SBF_VAR &&
		    ((struct mptcp_rbs_value_sbf_var *) cond->operand)
			    ->var_number == var_smt->var_number) {
			/* TODO Support unrolling of ifs etc.
			   clone blocks until goto to loop block is found

			   - Search for block with goto = loop block and
			   remember it
			   - Set the tag to a special value and the goto to NULL
			   - Find the tag in the cloned ones and set the goto
			*/

			/* Check if the loop is short enough to be
			 * unrolled */
			if (block->next && block->next->next == block) {
				/* Can be unrolled */
				unroll(ctx, var_smt, block);
			}
		}
	}

	FREE_BLOCK_LIST(&list);
	return var_smt != NULL;
}

void mptcp_rbs_opt_lu(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;

	if (!ctx->variation->sbf_num) {
		/* Loop unrolling is only possible with a fixed number of
		 * subflows
		 */
		return;
	}

	INIT_BLOCK_LIST(&list);
	while (find_loop(ctx, &list)) {
		/* Do nothing */
	}
	FREE_BLOCK_LIST(&list);
}
