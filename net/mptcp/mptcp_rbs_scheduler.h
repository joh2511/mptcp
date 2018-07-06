#ifndef _MPTCP_RBS_SCHEDULER_H
#define _MPTCP_RBS_SCHEDULER_H

#include <linux/types.h>

struct mptcp_rbs_cfg_block;

#define MPTCP_RBS_VARIATION_COUNT 8

/* Struct for RBS scheduler variations that are created by the optimizer */
struct mptcp_rbs_scheduler_variation {
	/* The first block of the CFG or NULL if the variation is not used yet
	 */
	struct mptcp_rbs_cfg_block *first_block;
	/* Number of total used variables */
	u8 used_vars;
	/* Determines for how many subflows this variation is optimized. Might
	 * be 0 if the variation is not optimized for subflows
	 */
	u8 sbf_num;

#ifdef CONFIG_MPTCP_RBSMEASURE
	/* Number of executions */
	u64 exec_count;
	/* Total execution time */
	u64 total_time;
#endif
};

/* Struct for RBS schedulers */
struct mptcp_rbs_scheduler {
	/* The next scheduler or NULL */
	struct mptcp_rbs_scheduler *next;
	/* Name of the scheduler */
	char *name;
	/* Array with different variations of the scheduler. The first entry is
	 * not optimized for a certain number of subflows
	 */
	struct mptcp_rbs_scheduler_variation
	    variations[MPTCP_RBS_VARIATION_COUNT];
	/* Number of usages */
	int usage;
	/* Determines if the scheduler should be deleted */
	bool del;

#ifdef CONFIG_MPTCP_RBSMEASURE
	u64 total_count_noa_no_skb;
	u64 total_time_noa_no_skb;

	u64 total_count_oa_skb;
	u64 total_time_oa_skb;

	u64 total_count_noa_skb;
	u64 total_time_noa_skb;

	u64 total_exec_count_no_skb;
	u64 total_exec_time_no_skb;

	u64 total_exec_count_skb;
	u64 total_exec_time_skb;
#endif
	/* Total bytes pushed by the scheduler. Used to analyse the
         * overhead of redundancy.
         */
        u64 total_bytes_sent;
};

void mptcp_rbs_scheduler_variation_free(
    struct mptcp_rbs_scheduler_variation *variation);

void mptcp_rbs_scheduler_free(struct mptcp_rbs_scheduler *scheduler);

int mptcp_rbs_scheduler_print(const struct mptcp_rbs_scheduler *scheduler,
			      int variation, char *buffer);

#endif
