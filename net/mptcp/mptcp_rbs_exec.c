#include "mptcp_rbs_exec.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"

void mptcp_rbs_exec(struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_scheduler_variation *variation =
	    ctx->rbs_cb->variation;
	struct mptcp_rbs_cfg_block *block = variation->first_block;
	int i;

#ifdef CONFIG_MPTCP_RBSMEASURE
	u64 time = __native_read_tsc();
#endif

	while (block) {
		struct mptcp_rbs_smt *smt = block->first_smt;
		struct mptcp_rbs_value_bool *cond = block->condition;

		while (smt) {
			smt->execute(smt, ctx);
			smt = smt->next;
		}

		if (cond) {
			s32 b = cond->execute(cond, ctx);
			if (b <= 0) {
				/*
				 * Else should be executed if the condition
				 * evaluates to false or to null
				 */
				block = block->next_else;
				continue;
			}
		}

		block = block->next;
	}

#ifdef CONFIG_MPTCP_RBSMEASURE
	variation->exec_count += 1;
	variation->total_time += __native_read_tsc() - time;
#endif

	/* Release allocated variables */
	for (i = 0; i < variation->used_vars; ++i) {
		mptcp_rbs_var_free(&ctx->vars[i]);
	}
}
