#include "mptcp_rbs_optimizer_dce.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"

#define IS_NULL(info) ((info) && (info)->is_const && (info)->const_value == -1)

static void opt_smt(struct mptcp_rbs_opt_ctx *ctx,
		    struct mptcp_rbs_smt ***smt_ptr)
{
	struct mptcp_rbs_smt *smt = **smt_ptr;
	struct mptcp_rbs_opt_value_info *info;
	struct mptcp_rbs_opt_value_info *info2;

	switch (smt->kind) {
	case SMT_KIND_DROP: {
		struct mptcp_rbs_smt_drop *drop_smt =
		    (struct mptcp_rbs_smt_drop *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) drop_smt->skb);
		if (!IS_NULL(info)) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_PRINT: {
		struct mptcp_rbs_smt_print *print_smt =
		    (struct mptcp_rbs_smt_print *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) print_smt->msg);
		if (print_smt->arg)
			info2 = mptcp_rbs_opt_find_value_info(
			    ctx, (struct mptcp_rbs_value *) print_smt->arg);
		else
			info2 = NULL;

		if (!IS_NULL(info) && !IS_NULL(info2)) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_PUSH: {
		struct mptcp_rbs_smt_push *push_smt =
		    (struct mptcp_rbs_smt_push *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) push_smt->sbf);
		info2 = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) push_smt->skb);

		if (!IS_NULL(info) && !IS_NULL(info2)) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_SET: {
		struct mptcp_rbs_smt_set *set_smt =
		    (struct mptcp_rbs_smt_set *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) set_smt->value);

		if (!IS_NULL(info)) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_SET_USER: {
		struct mptcp_rbs_smt_set_user *set_user_smt =
		    (struct mptcp_rbs_smt_set_user *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) set_user_smt->value);

		if (!IS_NULL(info)) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_VAR: {
		struct mptcp_rbs_smt_var *var_smt =
		    (struct mptcp_rbs_smt_var *) smt;
		struct mptcp_rbs_opt_var_info *var_info;

		var_info = &ctx->var_infos[var_smt->var_number];
		if (!var_info || !var_info->smt || var_info->usage) {
			*smt_ptr = &smt->next;
			return;
		}

		break;
	}
	case SMT_KIND_VOID: {
		/* Since VOID is only for measurements we are allowed to remove
		 * it
		 */
		break;
	}
	case SMT_KIND_EBPF: {
		/* Cannot optimize */
		return;
	}
	}

	/* Remove the statement */
	**smt_ptr = smt->next;
	smt->free(smt);
}

static void opt_block(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_cfg_block *block)
{
	struct mptcp_rbs_smt **smt;
	struct mptcp_rbs_opt_value_info *info;

	smt = &block->first_smt;
	while (smt && *smt) {
		opt_smt(ctx, &smt);
	}

	if (block->condition) {
		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) block->condition);

		if (info && info->is_const) {
			if (info->const_value != 1)
				block->next = block->next_else;

			block->next_else = NULL;
			block->condition->free(block->condition);
			block->condition = NULL;
		}
	}
}

void mptcp_rbs_opt_dce(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_cfg_block_list list2;
	struct mptcp_rbs_cfg_block *block;
	struct mptcp_rbs_cfg_block *block2;
	bool found;

	INIT_BLOCK_LIST(&list);
	INIT_BLOCK_LIST(&list2);

	/* Fill list with blocks */
	mptcp_rbs_cfg_block_traverse(ctx->variation->first_block, &list);

	/* Remove NULL statements and constant ifs */
	FOREACH_BLOCK(&list, block, opt_block(ctx, block));

	/* Free unused blocks */
	mptcp_rbs_cfg_block_traverse(ctx->variation->first_block, &list2);
	FOREACH_BLOCK(&list, block, {
		found = false;
		FOREACH_BLOCK(&list2, block2, if (block == block2) {
			found = true;
			break;
		});
		if (!found)
			mptcp_rbs_cfg_block_free(block);
	});

	FREE_BLOCK_LIST(&list);
	FREE_BLOCK_LIST(&list2);
}

// TODO RBS Compact variables if some were removed
