#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"
#include <linux/slab.h>

void mptcp_rbs_cfg_block_traverse(struct mptcp_rbs_cfg_block *block,
				  struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block2;

	/* Check if the block was already visited */
	FOREACH_BLOCK(list, block2, if (block == block2) return );
	ADD_BLOCK(list, block);

	if (block->next)
		mptcp_rbs_cfg_block_traverse(block->next, list);
	if (block->next_else)
		mptcp_rbs_cfg_block_traverse(block->next_else, list);
}

void mptcp_rbs_cfg_block_append(struct mptcp_rbs_cfg_block *block,
				struct mptcp_rbs_smt *first_smt)
{
	struct mptcp_rbs_smt *smt;

	if (!block->first_smt)
		block->first_smt = first_smt;
	else {
		smt = block->first_smt;

		while (smt->next) {
			smt = smt->next;
		}

		smt->next = first_smt;
	}
}

void mptcp_rbs_cfg_block_free(struct mptcp_rbs_cfg_block *block)
{
	if (block->first_smt)
		mptcp_rbs_smts_free(block->first_smt);
	MPTCP_RBS_VALUE_FREE(block->condition);
	kfree(block);
}

static void mptcp_rbs_cfg_free_helper(struct mptcp_rbs_cfg_block *block,
				      struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block2;

	/* Check if the block is already in the list */
	FOREACH_BLOCK(list, block2, if (block == block2) return );
	ADD_BLOCK(list, block);

	if (block->next)
		mptcp_rbs_cfg_free_helper(block->next, list);
	if (block->next_else)
		mptcp_rbs_cfg_free_helper(block->next_else, list);
}

void mptcp_rbs_cfg_blocks_free(struct mptcp_rbs_cfg_block *first_block)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_cfg_block *block;

	INIT_BLOCK_LIST(&list);
	mptcp_rbs_cfg_free_helper(first_block, &list);

	FOREACH_BLOCK(&list, block, mptcp_rbs_cfg_block_free(block));
	FREE_BLOCK_LIST(&list);
}

struct mptcp_rbs_cfg_block *mptcp_rbs_cfg_block_clone(
    const struct mptcp_rbs_cfg_block *block, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_cfg_block *clone;
	struct mptcp_rbs_smt *smt = block->first_smt;
	struct mptcp_rbs_smt *last_clone_smt = NULL;

	clone = kmalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_ATOMIC);
	*clone = *block;

	clone->first_smt = NULL;
	while (smt) {
		struct mptcp_rbs_smt *clone_smt =
		    mptcp_rbs_smt_clone(smt, user_ctx, user_func);
		smt = smt->next;

		if (last_clone_smt)
			last_clone_smt->next = clone_smt;
		else
			clone->first_smt = clone_smt;
		last_clone_smt = clone_smt;
	}

	clone->next = NULL;
	clone->next_else = NULL;
	if (clone->condition)
		clone->condition =
		    (struct mptcp_rbs_value_bool *) mptcp_rbs_value_clone(
			(struct mptcp_rbs_value *) clone->condition, user_ctx,
			user_func);

	return clone;
}

static struct mptcp_rbs_cfg_block *mptcp_rbs_cfg_blocks_clone_helper(
    const struct mptcp_rbs_cfg_block *block, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func,
    struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *clone;

	/* Check if the block was already cloned */
	FOREACH_BLOCK(list, clone, if (block == clone->tag) return clone);

	clone = mptcp_rbs_cfg_block_clone(block, user_ctx, user_func);
	clone->tag = (struct mptcp_rbs_cfg_block *) block;
	ADD_BLOCK(list, clone);

	if (block->next)
		clone->next = mptcp_rbs_cfg_blocks_clone_helper(
		    block->next, user_ctx, user_func, list);
	if (block->next_else)
		clone->next_else = mptcp_rbs_cfg_blocks_clone_helper(
		    block->next_else, user_ctx, user_func, list);

	return clone;
}

struct mptcp_rbs_cfg_block *mptcp_rbs_cfg_blocks_clone(
    const struct mptcp_rbs_cfg_block *first_block, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	/* The list contains the new created blocks with their tags set to the
	 * old ones. This is important to allow concurrent copying
	 */
	struct mptcp_rbs_cfg_block *clone;
	struct mptcp_rbs_cfg_block *block;
	struct mptcp_rbs_cfg_block_list list;

	INIT_BLOCK_LIST(&list);
	clone = mptcp_rbs_cfg_blocks_clone_helper(first_block, user_ctx,
						  user_func, &list);
	FOREACH_BLOCK(&list, block, block->tag = NULL);
	FREE_BLOCK_LIST(&list);
	return clone;
}

static int print_null_block(char **buffer,
			    struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block;

	/* Check if the block was already printed */
	FOREACH_BLOCK(list, block, if (block == NULL) return 0);
	ADD_BLOCK(list, NULL);

	return sprintf_null(buffer, "%p:\n  RETURN;\n\n", NULL);
}

static int mptcp_rbs_cfg_block_print(const struct mptcp_rbs_cfg_block *block,
				     char **buffer,
				     struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block2;
	int len;
	int tmp_len;
	const struct mptcp_rbs_smt *smt = block->first_smt;

	/* Check if the block was already printed */
	FOREACH_BLOCK(list, block2, if (block == block2) return 0);
	ADD_BLOCK(list, (struct mptcp_rbs_cfg_block *) block);

	len = sprintf_null(buffer, "%p:\n", block);

	while (smt) {
		len += sprintf_null(buffer, "  ");
		tmp_len = mptcp_rbs_smt_print(smt, *buffer);
		len += tmp_len;
		if (buffer && *buffer)
			*buffer += tmp_len;
		len += sprintf_null(buffer, "\n");
		smt = smt->next;
	}

	if (block->condition) {
		len += sprintf_null(buffer, "  IF ");
		tmp_len = mptcp_rbs_value_print(
		    (const struct mptcp_rbs_value *) block->condition, *buffer);
		len += tmp_len;
		if (buffer && *buffer)
			*buffer += tmp_len;
		len += sprintf_null(buffer, " GOTO %p ELSE GOTO %p;\n\n",
				    block->next, block->next_else);

		if (block->next)
			len += mptcp_rbs_cfg_block_print(block->next, buffer,
							 list);
		else
			len += print_null_block(buffer, list);

		if (block->next_else)
			len += mptcp_rbs_cfg_block_print(block->next_else,
							 buffer, list);
		else
			len += print_null_block(buffer, list);
	} else if (block->next) {
		len += sprintf_null(buffer, "  GOTO %p;\n\n", block->next);
		len += mptcp_rbs_cfg_block_print(block->next, buffer, list);
	} else
		len += sprintf_null(buffer, "  RETURN;\n\n");

	return len;
}

int mptcp_rbs_cfg_blocks_print(const struct mptcp_rbs_cfg_block *first_block,
			       char *buffer)
{
	struct mptcp_rbs_cfg_block_list list;
	int len;

	INIT_BLOCK_LIST(&list);
	len = mptcp_rbs_cfg_block_print(first_block, &buffer, &list);
	FREE_BLOCK_LIST(&list);
	return len;
}
