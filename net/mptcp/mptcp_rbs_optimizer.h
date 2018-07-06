#ifndef _MPTCP_RBS_OPTIMIZER_H
#define _MPTCP_RBS_OPTIMIZER_H

#include "mptcp_rbs_var.h"

struct mptcp_rbs_scheduler_variation;
struct mptcp_rbs_value;

/**
 * Information struct for values that contents are preserved over
 * optimizations
 */
struct mptcp_rbs_opt_value_info {
	struct mptcp_rbs_opt_value_info *next;
	struct mptcp_rbs_value *value;

	/** Determines if the value is constant */
	bool is_const;
	/**
	 * The evaluated value if the value is constant.
	 *  -1 for NULL
	 *  Booleans are encoded as 0 (false) and 1 (true)
	 *  Integers are encoded normally
	 *  Strings, subflows and sockbuffers cannot be stored
	 *  The number of items can be stored for lists
	 */
	s64 const_value;
};

/**
 * Information struct for variables that contents are preserved over
 * optimizations
 */
struct mptcp_rbs_opt_var_info {
	/** Declaration statement of the variable */
	struct mptcp_rbs_smt_var *smt;
	/** Number of usages of the variable */
	int usage;
};

/**
 * Context for optimization passes that contents are preserved over
 * optimizations
 */
struct mptcp_rbs_opt_ctx {
	struct mptcp_rbs_scheduler_variation *variation;
	/**
	 * Singly linked list to "map" values to their information because they
	 * lack a tag field. For simplicity this is a list instead of a hash map
	 */
	struct mptcp_rbs_opt_value_info *value_infos;
	/**
	 * Array that is used to connect variable indexes with their var
	 * statements and the number of usages of the variable
	 */
	struct mptcp_rbs_opt_var_info var_infos[MPTCP_RBS_MAX_VAR_COUNT];
};

/**
 * Searches for the corresponding value information
 * @ctx: The optimization context
 * @value: The value
 * Return: The information of the value or NULL
 */
struct mptcp_rbs_opt_value_info *mptcp_rbs_opt_find_value_info(
    struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_value *value);

/**
 * Searches for the corresponding value information. If none was found a new
 * information struct is created for this value
 * @ctx: The optimization context
 * @value: The value
 * Return: The information of the value
 */
struct mptcp_rbs_opt_value_info *mptcp_rbs_opt_get_value_info(
    struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_value *value);

/**
 * Optimizes the given scheduler variation inplace. If terminate is set during
 * optimization this function terminates
 * @variation: The scheduler variation that should be optimized
 * @terminate: Pointer to a value that aborts the optimization process if set to
 * true
 * @sbf_num: Fixed number of subflows the optimizer should optimize for or 0
 * @ebpf: Determines if eBPF code should be generated if possible
 */
void mptcp_rbs_optimize(struct mptcp_rbs_scheduler_variation *variation,
			bool *terminate, int sbf_num, bool ebpf);

#endif
