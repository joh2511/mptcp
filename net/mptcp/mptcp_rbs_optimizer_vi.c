#include "mptcp_rbs_optimizer_vi.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"

static void opt_value(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_value **value_ptr)
{
	struct mptcp_rbs_value *value = *value_ptr;

#define APPLY_ON_BIN(val)                                                      \
	opt_value(ctx, (struct mptcp_rbs_value **) &(val)->left_operand);      \
	opt_value(ctx, (struct mptcp_rbs_value **) &(val)->right_operand);     \
	break;

	switch (value->kind) {
	case VALUE_KIND_CONSTINT:
	case VALUE_KIND_CONSTSTRING:
	case VALUE_KIND_NULL:
		break;
	case VALUE_KIND_BOOL_VAR:
	case VALUE_KIND_INT_VAR:
	case VALUE_KIND_STRING_VAR:
	case VALUE_KIND_SBF_VAR:
	case VALUE_KIND_SKB_VAR:
	case VALUE_KIND_SKBLIST_VAR: {
		/* Right now we only support inlining of SUBFLOWS list values */
		break;
	}
	case VALUE_KIND_SBFLIST_VAR: {
		int var_index =
		    ((struct mptcp_rbs_value_sbf_list_var *) value)->var_number;
		struct mptcp_rbs_opt_var_info *info =
		    &ctx->var_infos[var_index];

		if (info->smt &&
		    info->smt->value->kind == VALUE_KIND_SUBFLOWS) {
			*value_ptr =
			    mptcp_rbs_value_clone(info->smt->value, NULL, NULL);
			value->free(value);
			--info->usage;
		}

		break;
	}
	case VALUE_KIND_NOT: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_not *) value)
				   ->operand);
		break;
	}
	case VALUE_KIND_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_equal *) value)
	}
	case VALUE_KIND_UNEQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_unequal *) value)
	}
	case VALUE_KIND_LESS: {
		APPLY_ON_BIN((struct mptcp_rbs_value_less *) value)
	}
	case VALUE_KIND_LESS_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_less_equal *) value)
	}
	case VALUE_KIND_GREATER: {
		APPLY_ON_BIN((struct mptcp_rbs_value_greater *) value)
	}
	case VALUE_KIND_GREATER_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_greater_equal *) value)
	}
	case VALUE_KIND_AND: {
		APPLY_ON_BIN((struct mptcp_rbs_value_and *) value)
	}
	case VALUE_KIND_OR: {
		APPLY_ON_BIN((struct mptcp_rbs_value_or *) value)
	}
	case VALUE_KIND_ADD: {
		APPLY_ON_BIN((struct mptcp_rbs_value_add *) value)
	}
	case VALUE_KIND_SUBTRACT: {
		APPLY_ON_BIN((struct mptcp_rbs_value_subtract *) value)
	}
	case VALUE_KIND_MULTIPLY: {
		APPLY_ON_BIN((struct mptcp_rbs_value_multiply *) value)
	}
	case VALUE_KIND_DIVIDE: {
		APPLY_ON_BIN((struct mptcp_rbs_value_divide *) value)
	}
	case VALUE_KIND_REMAINDER: {
		APPLY_ON_BIN((struct mptcp_rbs_value_remainder *) value)
	}
	case VALUE_KIND_IS_NULL: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_is_null *) value)
				   ->operand);
		break;
	}
	case VALUE_KIND_IS_NOT_NULL: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_is_not_null *) value)
				   ->operand);
		break;
	}
	case VALUE_KIND_REG:
	case VALUE_KIND_Q:
	case VALUE_KIND_QU:
	case VALUE_KIND_RQ:
	case VALUE_KIND_CURRENT_TIME_MS:
	case VALUE_KIND_RANDOM:
	case VALUE_KIND_SBFLIST_FILTER_SBF:
	case VALUE_KIND_SKBLIST_FILTER_SKB:
	case VALUE_KIND_SUBFLOWS: {
		/* Cannot use variables */
		break;
	}
	case VALUE_KIND_SBF_RTT: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_rtt *) value)
				   ->sbf);
		break;
	}
	case VALUE_KIND_SBF_IS_BACKUP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_is_backup *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_CWND: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_cwnd *) value)
				   ->sbf);
		break;
	}
	case VALUE_KIND_SBF_SKBS_IN_FLIGHT: {
		opt_value(
		    ctx,
		    (struct mptcp_rbs_value **) &(
			(struct mptcp_rbs_value_sbf_skbs_in_flight *) value)
			->sbf);
		break;
	}
	case VALUE_KIND_SBF_LOST_SKBS: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_lost_skbs *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_HAS_WINDOW_FOR: {
		opt_value(
		    ctx,
		    (struct mptcp_rbs_value **) &(
			(struct mptcp_rbs_value_sbf_has_window_for *) value)
			->sbf);
		opt_value(
		    ctx,
		    (struct mptcp_rbs_value **) &(
			(struct mptcp_rbs_value_sbf_has_window_for *) value)
			->skb);
		break;
	}
	case VALUE_KIND_SBF_ID: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_id *) value)
				   ->sbf);
		break;
	}
	case VALUE_KIND_SBF_DELAY_IN: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_delay_in *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_DELAY_OUT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_delay_out *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_BW_OUT_SEND: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_bw_out_send *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_BW_OUT_ACK: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_bw_out_ack *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_SSTHRESH: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_ssthresh *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_THROTTLED: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_throttled *) value)
			      ->sbf);
		break;
	}
	case VALUE_KIND_SBF_LOSSY: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_lossy *) value)
				   ->sbf);
		break;
	}
	case VALUE_KIND_SBFLIST_NEXT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_next *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SBFLIST_EMPTY: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_empty *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SBFLIST_FILTER: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_filter *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_filter *) value)
			      ->cond);
		break;
	}
	case VALUE_KIND_SBFLIST_MAX: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_max *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_max *) value)
			      ->cond);
		break;
	}
	case VALUE_KIND_SBFLIST_MIN: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_min *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_min *) value)
			      ->cond);
		break;
	}
	case VALUE_KIND_SBFLIST_GET: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_get *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_get *) value)
			      ->index);
		break;
	}
	case VALUE_KIND_SBFLIST_COUNT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_count *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SBFLIST_SUM: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_sum *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_sum *) value)
			      ->cond);
		break;
	}
	case VALUE_KIND_SKB_SENT_ON: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_sent_on *) value)
				   ->skb);
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_sent_on *) value)
				   ->sbf);
		break;
	}
	case VALUE_KIND_SKB_SENT_ON_ALL: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_sent_on *) value)
				   ->skb);
		break;
	}
	case VALUE_KIND_SKB_USER: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_user *) value)
				   ->skb);
		break;
	}
	case VALUE_KIND_SKBLIST_NEXT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_next *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SKBLIST_EMPTY: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_empty *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SKBLIST_POP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_pop *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SKBLIST_FILTER: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_filter *) value)
			      ->list);
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_filter *) value)
			      ->cond);
		break;
	}
	case VALUE_KIND_SKBLIST_COUNT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_count *) value)
			      ->list);
		break;
	}
	case VALUE_KIND_SKBLIST_TOP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_top *) value)
			      ->list);
		break;
	}
	default:
		break;
	}
}

static void opt_smt(struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_smt *smt)
{
	switch (smt->kind) {
	case SMT_KIND_DROP: {
		struct mptcp_rbs_smt_drop *drop_smt =
		    (struct mptcp_rbs_smt_drop *) smt;

		opt_value(ctx, (struct mptcp_rbs_value **) &drop_smt->skb);
		break;
	}
	case SMT_KIND_PRINT: {
		struct mptcp_rbs_smt_print *print_smt =
		    (struct mptcp_rbs_smt_print *) smt;

		opt_value(ctx, (struct mptcp_rbs_value **) &print_smt->msg);
		if (print_smt->arg)
			opt_value(ctx, &print_smt->arg);
		break;
	}
	case SMT_KIND_PUSH: {
		struct mptcp_rbs_smt_push *push_smt =
		    (struct mptcp_rbs_smt_push *) smt;

		opt_value(ctx, (struct mptcp_rbs_value **) &push_smt->sbf);
		opt_value(ctx, (struct mptcp_rbs_value **) &push_smt->skb);
		break;
	}
	case SMT_KIND_SET: {
		struct mptcp_rbs_smt_set *set_smt =
		    (struct mptcp_rbs_smt_set *) smt;

		opt_value(ctx, (struct mptcp_rbs_value **) &set_smt->value);
		break;
	}
	case SMT_KIND_SET_USER: {
		struct mptcp_rbs_smt_set_user *set_user_smt =
		    (struct mptcp_rbs_smt_set_user *) smt;

		opt_value(ctx, (struct mptcp_rbs_value **) &set_user_smt->value);
		break;
	}
	case SMT_KIND_VAR: {
		struct mptcp_rbs_smt_var *var_smt =
		    (struct mptcp_rbs_smt_var *) smt;

		ctx->var_infos[var_smt->var_number].smt = var_smt;
		opt_value(ctx, &var_smt->value);
		break;
	}
	case SMT_KIND_VOID: {
		struct mptcp_rbs_smt_void *void_smt =
		    (struct mptcp_rbs_smt_void *) smt;

		if (void_smt->value)
			opt_value(ctx, &void_smt->value);
		break;
	}
	case SMT_KIND_EBPF: {
		/* Cannot optimize */
		break;
	}
	}
}

static void opt_block(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_cfg_block *block,
		      struct mptcp_rbs_cfg_block_list *list)
{
	struct mptcp_rbs_cfg_block *block2;
	struct mptcp_rbs_smt *smt;

	/* Check if the block was already visited */
	FOREACH_BLOCK(list, block2, if (block == block2) return );
	ADD_BLOCK(list, block);

	smt = block->first_smt;
	while (smt) {
		opt_smt(ctx, smt);
		smt = smt->next;
	}

	if (block->condition)
		opt_value(ctx, (struct mptcp_rbs_value **) &block->condition);
	if (block->next)
		opt_block(ctx, block->next, list);
	if (block->next_else)
		opt_block(ctx, block->next_else, list);
}

void mptcp_rbs_opt_vi(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;

	INIT_BLOCK_LIST(&list);
	opt_block(ctx, ctx->variation->first_block, &list);
	FREE_BLOCK_LIST(&list);
}
