#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer_bm.h"
#include "mptcp_rbs_optimizer_cf.h"
#include "mptcp_rbs_optimizer_cve.h"
#include "mptcp_rbs_optimizer_dce.h"
#include "mptcp_rbs_optimizer_ebpf.h"
#include "mptcp_rbs_optimizer_lu.h"
#include "mptcp_rbs_optimizer_vi.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_value.h"
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

struct mptcp_rbs_opt_value_info *mptcp_rbs_opt_find_value_info(
    struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_value *value)
{
	struct mptcp_rbs_opt_value_info *info = ctx->value_infos;

	while (info) {
		if (info->value == value)
			return info;

		info = info->next;
	}

	return NULL;
}

struct mptcp_rbs_opt_value_info *mptcp_rbs_opt_get_value_info(
    struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_value *value)
{
	struct mptcp_rbs_opt_value_info *info =
	    mptcp_rbs_opt_find_value_info(ctx, value);

	if (!info) {
		info = kzalloc(sizeof(struct mptcp_rbs_opt_value_info),
			       GFP_KERNEL);
		info->next = ctx->value_infos;
		info->value = value;
		ctx->value_infos = info;
	}

	return info;
}

typedef void (*optimization_func)(struct mptcp_rbs_opt_ctx *);

/** Array with optimizations that are executed in order */
static const optimization_func pipeline[] = {
	/* mptcp_rbs_opt_lu, */ mptcp_rbs_opt_cve, mptcp_rbs_opt_vi,
	mptcp_rbs_opt_dce, mptcp_rbs_opt_cf,  mptcp_rbs_opt_bm
};

void mptcp_rbs_optimize(struct mptcp_rbs_scheduler_variation *variation,
			bool *terminate, int sbf_num, bool ebpf)
{
	int i;
	struct mptcp_rbs_opt_ctx ctx;

	/* Fill the context */
	memset(&ctx, 0, sizeof(struct mptcp_rbs_opt_ctx));
	ctx.variation = variation;
	ctx.variation->sbf_num = sbf_num;

	/* Apply optimizations in pipeline */
	for (i = 0; i < ARRAY_SIZE(pipeline) && !*terminate; ++i) {
		pipeline[i](&ctx);
	}

	/* Release the context */
	while (ctx.value_infos) {
		struct mptcp_rbs_opt_value_info *info = ctx.value_infos;
		ctx.value_infos = ctx.value_infos->next;
		kfree(info);
	}

	if (!*terminate && sbf_num && ebpf) {
		/* Generate eBPF code */
		mptcp_rbs_opt_ebpf(&ctx);
	}
}
