#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_parser.h"
#include <linux/slab.h>

void mptcp_rbs_scheduler_variation_free(
    struct mptcp_rbs_scheduler_variation *variation)
{
	if (variation->first_block)
		mptcp_rbs_cfg_blocks_free(variation->first_block);
}

void mptcp_rbs_scheduler_free(struct mptcp_rbs_scheduler *scheduler)
{
	int i;
 
	for (i = 0; i < MPTCP_RBS_VARIATION_COUNT; ++i) {
		if (!scheduler->variations[i].first_block)
			break;

		mptcp_rbs_scheduler_variation_free(&scheduler->variations[i]);
	}

	kfree(scheduler->name);
	kfree(scheduler);
}

int mptcp_rbs_scheduler_print(const struct mptcp_rbs_scheduler *scheduler,
			      int variation, char *buffer)
{
	int len;

	BUG_ON(variation < 0 || variation >= MPTCP_RBS_VARIATION_COUNT);
	BUG_ON(!scheduler->variations[variation].first_block);

	len = sprintf_null(&buffer, "SCHEDULER %s;\n\n", scheduler->name);
	len += mptcp_rbs_cfg_blocks_print(
	    scheduler->variations[variation].first_block, buffer);

	return len;
}
