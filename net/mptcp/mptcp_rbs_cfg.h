#ifndef _MPTCP_RBS_CFG_H
#define _MPTCP_RBS_CFG_H

#include "mptcp_rbs_dynarray.h"

/*
 * Struct for a single block inside the control flow graph.
 * Blocks are singly linked to save memory and remove the necessity to handle
 * lists of multiple previous blocks. Back pointers would only be useful for
 * optimizations at creation time but useless for the rest of the time.
 */
struct mptcp_rbs_cfg_block {
	/* The next block or NULL if the execution ends after this block */
	struct mptcp_rbs_cfg_block *next;
	/*
	 * The alternative next block if the block ends with an if instruction
	 * or NULL
	 */
	struct mptcp_rbs_cfg_block *next_else;
	/* Condition if the block ends with an if instruction or NULL */
	struct mptcp_rbs_value_bool *condition;
	/*
	 * This field can be used for any purpose i.e. to store information
	 * during optimization
	 */
	void *tag;
	/* First statement in the block */
	struct mptcp_rbs_smt *first_smt;
};

/*
 * Block lists
 */

DECL_DA(mptcp_rbs_cfg_block_list, struct mptcp_rbs_cfg_block *);

#define INIT_BLOCK_LIST(list) INIT_DA(list)

#define FREE_BLOCK_LIST(list) FREE_DA(list)

#define ADD_BLOCK(list, block) ADD_DA_ITEM(list, block)

#define FOREACH_BLOCK(list, var, cmds) FOREACH_DA_ITEM(list, var, cmds)

/*
 * Traverses over all blocks and adds them to the list
 */
void mptcp_rbs_cfg_block_traverse(struct mptcp_rbs_cfg_block *block,
				  struct mptcp_rbs_cfg_block_list *list);

/*
 * Appends statements at the end of the block
 */
void mptcp_rbs_cfg_block_append(struct mptcp_rbs_cfg_block *block,
				struct mptcp_rbs_smt *first_smt);

/*
 * Releases the passed control flow graph block and all its statements
 */
void mptcp_rbs_cfg_block_free(struct mptcp_rbs_cfg_block *block);

/*
 * Releases the passed control flow graph block and all its successors
 */
void mptcp_rbs_cfg_blocks_free(struct mptcp_rbs_cfg_block *first_block);

#ifndef MPTCP_RBS_CLONE_USER_FUNC_DEFINED
#define MPTCP_RBS_CLONE_USER_FUNC_DEFINED
typedef struct mptcp_rbs_value *(*mptcp_rbs_value_clone_user_func)(
    void *user_ctx, const struct mptcp_rbs_value *value);
#endif

/*
 * Creates a copy of a block and all its statements
 * @block: The block to copy
 * @user_ctx: User context for the user function or NULL
 * @user_func: Function that is executed for each value or NULL. If this
 * function returns a value other than NULL the current value is replaced with
 * it instead of cloned
 * Return: The new instance
 */
struct mptcp_rbs_cfg_block *mptcp_rbs_cfg_block_clone(
    const struct mptcp_rbs_cfg_block *block, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/*
 * Creates a copy of a block, all its statements and all following blocks
 * @first_block: The first block to copy
 * @user_ctx: User context for the user function or NULL
 * @user_func: Function that is executed for each value or NULL. If this
 * function returns a value other than NULL the current value is replaced with
 * it instead of cloned
 * Return: The new instance
 */
struct mptcp_rbs_cfg_block *mptcp_rbs_cfg_blocks_clone(
    const struct mptcp_rbs_cfg_block *first_block, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/*
 * Writes a string representation of a control flow graph block and all its
 * successors to the given buffer
 * @first_block: Pointer to the CFG block
 * @buffer: Pointer to the buffer where the string should be stored or NULL
 * Return: Number of written characters
 */
int mptcp_rbs_cfg_blocks_print(const struct mptcp_rbs_cfg_block *first_block,
			       char *buffer);

#endif
