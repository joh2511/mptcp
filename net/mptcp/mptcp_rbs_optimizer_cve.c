#include "mptcp_rbs_optimizer_cve.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"
#include <linux/string.h>

static void find_var_smts_in_block(struct mptcp_rbs_opt_ctx *ctx,
				   struct mptcp_rbs_cfg_block *block)
{
	struct mptcp_rbs_smt *smt;
	struct mptcp_rbs_smt_var *var_smt;

	smt = block->first_smt;
	while (smt) {
		if (smt->kind == SMT_KIND_VAR) {
			var_smt = (struct mptcp_rbs_smt_var *) smt;

			ctx->var_infos[var_smt->var_number].smt = var_smt;
		}

		smt = smt->next;
	}
}

static struct mptcp_rbs_opt_value_info *opt_value(struct mptcp_rbs_opt_ctx *ctx,
						  struct mptcp_rbs_value *value)
{
	struct mptcp_rbs_opt_value_info *info = NULL;

#define APPLY_ON_BIN(val, op)                                                  \
	struct mptcp_rbs_opt_value_info *left_info;                            \
	struct mptcp_rbs_opt_value_info *right_info;                           \
	left_info =                                                            \
	    opt_value(ctx, (struct mptcp_rbs_value *) (val)->left_operand);    \
	right_info =                                                           \
	    opt_value(ctx, (struct mptcp_rbs_value *) (val)->right_operand);   \
									       \
	if (left_info && left_info->is_const) {                                \
		if (left_info->const_value == -1) {                            \
			info = mptcp_rbs_opt_get_value_info(ctx, value);       \
			info->is_const = true;                                 \
			info->const_value = -1;                                \
		} else if (right_info && right_info->is_const) {               \
			info = mptcp_rbs_opt_get_value_info(ctx, value);       \
			info->is_const = true;                                 \
			if (right_info->const_value == -1)                     \
				info->const_value = -1;                        \
			else                                                   \
				op;                                            \
		}                                                              \
	} else if (right_info && right_info->is_const &&                       \
		   right_info->const_value == -1) {                            \
		info = mptcp_rbs_opt_get_value_info(ctx, value);               \
		info->is_const = true;                                         \
		info->const_value = -1;                                        \
	}                                                                      \
									       \
	return info;

	switch (value->kind) {
	case VALUE_KIND_CONSTINT: {
		info = mptcp_rbs_opt_get_value_info(ctx, value);
		info->is_const = true;
		info->const_value =
		    ((struct mptcp_rbs_value_constint *) value)->value;
		return info;
	}
	case VALUE_KIND_CONSTSTRING: {
		info = mptcp_rbs_opt_get_value_info(ctx, value);
		info->is_const = true;
		info->const_value = 0;
		return info;
	}
	case VALUE_KIND_NULL: {
		info = mptcp_rbs_opt_get_value_info(ctx, value);
		info->is_const = true;
		info->const_value = -1;
		return info;
	}
	case VALUE_KIND_BOOL_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_INT_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_STRING_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SBF_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SKB_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_VAR: {
		struct mptcp_rbs_opt_var_info *var_info;
		struct mptcp_rbs_opt_value_info *var_value_info;

		var_info =
		    &ctx->var_infos[((struct mptcp_rbs_value_int_var *) value)
					->var_number];
		++var_info->usage;
		var_value_info =
		    mptcp_rbs_opt_find_value_info(ctx, var_info->smt->value);

		if (var_value_info && var_value_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = var_value_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_NOT: {
		struct mptcp_rbs_opt_value_info *operand_info;
		operand_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value *) ((struct mptcp_rbs_value_not *)
						    value)
			->operand);

		if (operand_info && operand_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			if (operand_info->const_value == -1)
				info->const_value = -1;
			else
				info->const_value = !operand_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_equal *) value,
			     info->const_value = left_info->const_value ==
						 right_info->const_value)
	}
	case VALUE_KIND_UNEQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_unequal *) value,
			     info->const_value = left_info->const_value !=
						 right_info->const_value)
	}
	case VALUE_KIND_LESS: {
		APPLY_ON_BIN((struct mptcp_rbs_value_less *) value,
			     info->const_value = left_info->const_value <
						 right_info->const_value)
	}
	case VALUE_KIND_LESS_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_less_equal *) value,
			     info->const_value = left_info->const_value <=
						 right_info->const_value)
	}
	case VALUE_KIND_GREATER: {
		APPLY_ON_BIN((struct mptcp_rbs_value_greater *) value,
			     info->const_value = left_info->const_value >
						 right_info->const_value)
	}
	case VALUE_KIND_GREATER_EQUAL: {
		APPLY_ON_BIN((struct mptcp_rbs_value_greater_equal *) value,
			     info->const_value = left_info->const_value >=
						 right_info->const_value)
	}
	case VALUE_KIND_AND: {
		struct mptcp_rbs_opt_value_info *left_info;
		struct mptcp_rbs_opt_value_info *right_info;
		left_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value *) ((struct mptcp_rbs_value_and *)
						    value)
			->left_operand);
		right_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value *) ((struct mptcp_rbs_value_and *)
						    value)
			->right_operand);

		if (left_info && left_info->is_const) {
			if (left_info->const_value <= 0) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = 0;
			} else if (right_info && right_info->is_const) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value =
				    right_info->const_value == 1;
			}
		} else if (right_info && right_info->is_const &&
			   right_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_OR: {
		struct mptcp_rbs_opt_value_info *left_info;
		struct mptcp_rbs_opt_value_info *right_info;
		left_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value *) ((struct mptcp_rbs_value_and *)
						    value)
			->left_operand);
		right_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value *) ((struct mptcp_rbs_value_and *)
						    value)
			->right_operand);

		if (left_info && left_info->is_const) {
			if (left_info->const_value == 1) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = 1;
			} else if (right_info && right_info->is_const) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value =
				    right_info->const_value == 1;
			}
		} else if (right_info && right_info->is_const &&
			   right_info->const_value == 1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = 1;
		}

		return info;
	}
	case VALUE_KIND_ADD: {
		APPLY_ON_BIN((struct mptcp_rbs_value_add *) value, {
			unsigned int result =
			    left_info->const_value + right_info->const_value;
			info->const_value = result;
		})
	}
	case VALUE_KIND_SUBTRACT: {
		APPLY_ON_BIN((struct mptcp_rbs_value_subtract *) value, {
			unsigned int result =
			    left_info->const_value - right_info->const_value;
			info->const_value = result;
		})
	}
	case VALUE_KIND_MULTIPLY: {
		APPLY_ON_BIN((struct mptcp_rbs_value_multiply *) value, {
			unsigned int result =
			    left_info->const_value * right_info->const_value;
			info->const_value = result;
		})
	}
	case VALUE_KIND_DIVIDE: {
		APPLY_ON_BIN((struct mptcp_rbs_value_divide *) value, {
			if (!right_info->const_value)
				info->const_value = -1;
			else {
				unsigned int result = left_info->const_value /
						      right_info->const_value;
				info->const_value = result;
			}
		})
	}
	case VALUE_KIND_REMAINDER: {
		APPLY_ON_BIN((struct mptcp_rbs_value_remainder *) value, {
			if (!right_info->const_value)
				info->const_value = -1;
			else {
				unsigned int result = left_info->const_value %
						      right_info->const_value;
				info->const_value = result;
			}
		})
	}
	case VALUE_KIND_IS_NULL: {
		struct mptcp_rbs_opt_value_info *operand_info;
		operand_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_is_null *) value)
			     ->operand);

		if (operand_info && operand_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = operand_info->const_value == -1;
		} else if (((struct mptcp_rbs_value_is_null *) value)
			       ->operand->kind == VALUE_KIND_REG) {
			/* Registers can never hold NULL */
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_IS_NOT_NULL: {
		struct mptcp_rbs_opt_value_info *operand_info;
		operand_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_is_not_null *) value)
			     ->operand);

		if (operand_info && operand_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = operand_info->const_value != -1;
		} else if (((struct mptcp_rbs_value_is_not_null *) value)
			       ->operand->kind == VALUE_KIND_REG) {
			/* Registers can never hold NULL */
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = 1;
		}

		return info;
	}
	case VALUE_KIND_REG:
	case VALUE_KIND_Q:
	case VALUE_KIND_QU:
	case VALUE_KIND_RQ:
	case VALUE_KIND_CURRENT_TIME_MS:
	case VALUE_KIND_RANDOM:
	case VALUE_KIND_SBFLIST_FILTER_SBF:
	case VALUE_KIND_SKBLIST_FILTER_SKB: {
		/* Cannot be constant */
		return NULL;
	}
	case VALUE_KIND_SUBFLOWS: {
		if (!ctx->variation->sbf_num)
			return NULL;

		info = mptcp_rbs_opt_get_value_info(ctx, value);
		info->is_const = true;
		info->const_value = ctx->variation->sbf_num;

		return info;
	}
	case VALUE_KIND_SBF_RTT: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_rtt *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_IS_BACKUP: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_is_backup *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_CWND: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_cwnd *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_SKBS_IN_FLIGHT: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_skbs_in_flight *)
				      value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_LOST_SKBS: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_lost_skbs *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_HAS_WINDOW_FOR: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		struct mptcp_rbs_opt_value_info *skb_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_has_window_for *)
				      value)
			     ->sbf);
		skb_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_has_window_for *)
				      value)
			     ->skb);

		if ((sbf_info && sbf_info->is_const &&
		     sbf_info->const_value == -1) ||
		    (skb_info && skb_info->is_const &&
		     skb_info->const_value == -1)) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_ID: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_id *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_DELAY_IN: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_delay_in *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_DELAY_OUT: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_delay_out *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_BW_OUT_SEND: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_bw_out_send *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_BW_OUT_ACK: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_bw_out_ack *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_SSTHRESH: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_ssthresh *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_THROTTLED: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_throttled *) value)
			->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBF_LOSSY: {
		struct mptcp_rbs_opt_value_info *sbf_info;
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_lossy *) value)
			     ->sbf);

		if (sbf_info && sbf_info->is_const &&
		    sbf_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_NEXT: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		sbf_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_next *) value)
			->list);

		if (sbf_list_info && sbf_list_info->is_const &&
		    sbf_list_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_EMPTY: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		sbf_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_empty *) value)
			->list);

		if (sbf_list_info && sbf_list_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			if (sbf_list_info->const_value == -1)
				info->const_value = -1;
			else if (!sbf_list_info->const_value)
				info->const_value = 1;
			else
				info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_FILTER: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		struct mptcp_rbs_opt_value_info *cond_info;
		sbf_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_filter *) value)
			->list);
		cond_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_filter *) value)
			->cond);

		if (sbf_list_info && sbf_list_info->is_const) {
			if (sbf_list_info->const_value == -1) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = -1;
			} else if (cond_info && cond_info->is_const) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				if (cond_info->const_value == -1)
					info->const_value = -1;
				else if (!cond_info->const_value)
					info->const_value = 0;
				else
					info->const_value =
					    sbf_list_info->const_value;
			}
		} else if (cond_info && cond_info->is_const &&
			   cond_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			if (cond_info->const_value == -1)
				info->const_value = -1;
			else
				info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_MAX: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		struct mptcp_rbs_opt_value_info *cond_info;
		sbf_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_max *) value)
			     ->list);
		cond_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_max *) value)
			     ->cond);

		if ((sbf_list_info && sbf_list_info->is_const &&
		     sbf_list_info->const_value == -1) ||
		    (cond_info && cond_info->is_const &&
		     cond_info->const_value == -1)) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_MIN: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		struct mptcp_rbs_opt_value_info *cond_info;
		sbf_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_min *) value)
			     ->list);
		cond_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_min *) value)
			     ->cond);

		if ((sbf_list_info && sbf_list_info->is_const &&
		     sbf_list_info->const_value == -1) ||
		    (cond_info && cond_info->is_const &&
		     cond_info->const_value == -1)) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_GET: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		struct mptcp_rbs_opt_value_info *index_info;
		sbf_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_get *) value)
			     ->list);
		index_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_get *) value)
			     ->index);

		if (sbf_list_info && sbf_list_info->is_const) {
			if (sbf_list_info->const_value == -1 ||
			    (index_info && index_info->is_const &&
			     index_info->const_value >=
				 sbf_list_info->const_value)) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = -1;
			}
		} else if (index_info && index_info->is_const) {
			if (index_info->const_value == -1 ||
			    (ctx->variation->sbf_num &&
			     index_info->const_value >=
				 ctx->variation->sbf_num)) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = -1;
			}
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_COUNT: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		sbf_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_count *) value)
			->list);

		if (sbf_list_info && sbf_list_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = sbf_list_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SBFLIST_SUM: {
		struct mptcp_rbs_opt_value_info *sbf_list_info;
		struct mptcp_rbs_opt_value_info *cond_info;
		sbf_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_sum *) value)
			     ->list);
		cond_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_sbf_list_sum *) value)
			     ->cond);

		if ((sbf_list_info && sbf_list_info->is_const &&
		     sbf_list_info->const_value == -1) ||
		    (cond_info && cond_info->is_const &&
		     cond_info->const_value == -1)) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKB_SENT_ON: {
		struct mptcp_rbs_opt_value_info *skb_info;
		struct mptcp_rbs_opt_value_info *sbf_info;
		skb_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_sent_on *) value)
			     ->skb);
		sbf_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_sent_on *) value)
			     ->sbf);

		if ((skb_info && skb_info->is_const &&
		     skb_info->const_value == -1) ||
		    (sbf_info && sbf_info->is_const &&
		     sbf_info->const_value == -1)) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKB_SENT_ON_ALL: {
		struct mptcp_rbs_opt_value_info *skb_info;
		skb_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_sent_on *) value)
			     ->skb);

		if (skb_info && skb_info->is_const &&
		    skb_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKB_USER: {
		struct mptcp_rbs_opt_value_info *skb_info;
		skb_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_user *) value)
			     ->skb);

		if (skb_info && skb_info->is_const &&
		    skb_info->const_value == -1) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_NEXT: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		skb_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_skb_list_next *) value)
			->list);

		if (skb_list_info && skb_list_info->is_const &&
		    skb_list_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_EMPTY: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		skb_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_skb_list_empty *) value)
			->list);

		if (skb_list_info && skb_list_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			if (skb_list_info->const_value == -1)
				info->const_value = -1;
			else if (!skb_list_info->const_value)
				info->const_value = 1;
			else
				info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_POP: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		skb_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_list_pop *) value)
			     ->list);

		if (skb_list_info && skb_list_info->is_const &&
		    skb_list_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_FILTER: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		struct mptcp_rbs_opt_value_info *cond_info;
		skb_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_filter *) value)
			->list);
		cond_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_sbf_list_filter *) value)
			->cond);

		if (skb_list_info && skb_list_info->is_const) {
			if (skb_list_info->const_value == -1) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				info->const_value = -1;
			} else if (cond_info && cond_info->is_const) {
				info = mptcp_rbs_opt_get_value_info(ctx, value);
				info->is_const = true;
				if (cond_info->const_value == -1)
					info->const_value = -1;
				else if (!cond_info->const_value)
					info->const_value = 0;
				else
					info->const_value =
					    skb_list_info->const_value;
			}
		} else if (cond_info && cond_info->is_const &&
			   cond_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			if (cond_info->const_value == -1)
				info->const_value = -1;
			else
				info->const_value = 0;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_COUNT: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		skb_list_info = opt_value(
		    ctx,
		    (struct mptcp_rbs_value
			 *) ((struct mptcp_rbs_value_skb_list_count *) value)
			->list);

		if (skb_list_info && skb_list_info->is_const) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = skb_list_info->const_value;
		}

		return info;
	}
	case VALUE_KIND_SKBLIST_TOP: {
		struct mptcp_rbs_opt_value_info *skb_list_info;
		skb_list_info = opt_value(
		    ctx, (struct mptcp_rbs_value
			      *) ((struct mptcp_rbs_value_skb_list_top *) value)
			     ->list);

		if (skb_list_info && skb_list_info->is_const &&
		    skb_list_info->const_value <= 0) {
			info = mptcp_rbs_opt_get_value_info(ctx, value);
			info->is_const = true;
			info->const_value = -1;
		}

		return info;
	}
	default:
		return NULL;
	}
}

static void opt_smt(struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_smt *smt)
{
	switch (smt->kind) {
	case SMT_KIND_DROP: {
		struct mptcp_rbs_smt_drop *drop_smt =
		    (struct mptcp_rbs_smt_drop *) smt;

		opt_value(ctx, (struct mptcp_rbs_value *) drop_smt->skb);
		break;
	}
	case SMT_KIND_PRINT: {
		struct mptcp_rbs_smt_print *print_smt =
		    (struct mptcp_rbs_smt_print *) smt;

		opt_value(ctx, (struct mptcp_rbs_value *) print_smt->msg);
		if (print_smt->arg)
			opt_value(ctx, print_smt->arg);
		break;
	}
	case SMT_KIND_PUSH: {
		struct mptcp_rbs_smt_push *push_smt =
		    (struct mptcp_rbs_smt_push *) smt;

		opt_value(ctx, (struct mptcp_rbs_value *) push_smt->sbf);
		opt_value(ctx, (struct mptcp_rbs_value *) push_smt->skb);
		break;
	}
	case SMT_KIND_SET: {
		struct mptcp_rbs_smt_set *set_smt =
		    (struct mptcp_rbs_smt_set *) smt;

		opt_value(ctx, (struct mptcp_rbs_value *) set_smt->value);
		break;
	}
	case SMT_KIND_SET_USER: {
		struct mptcp_rbs_smt_set_user *set_user_smt =
		    (struct mptcp_rbs_smt_set_user *) smt;

		opt_value(ctx, (struct mptcp_rbs_value *) set_user_smt->value);
		break;
	}
	case SMT_KIND_VAR: {
		struct mptcp_rbs_smt_var *var_smt =
		    (struct mptcp_rbs_smt_var *) smt;

		opt_value(ctx, var_smt->value);
		break;
	}
	case SMT_KIND_VOID: {
		struct mptcp_rbs_smt_void *void_smt =
		    (struct mptcp_rbs_smt_void *) smt;

		if (void_smt->value)
			opt_value(ctx, void_smt->value);
		break;
	}
	case SMT_KIND_EBPF: {
		/* Cannot optimize */
		break;
	}
	}
}

static void opt_block(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_cfg_block *block)
{
	struct mptcp_rbs_smt *smt;

	smt = block->first_smt;
	while (smt) {
		opt_smt(ctx, smt);
		smt = smt->next;
	}

	if (block->condition)
		opt_value(ctx, (struct mptcp_rbs_value *) block->condition);
}

void mptcp_rbs_opt_cve(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;
	struct mptcp_rbs_cfg_block *block;

	/* Clear variable information */
	memset(ctx->var_infos, 0, sizeof(ctx->var_infos));

	INIT_BLOCK_LIST(&list);
	mptcp_rbs_cfg_block_traverse(ctx->variation->first_block, &list);

	/* Find var statements */
	FOREACH_BLOCK(&list, block, find_var_smts_in_block(ctx, block));

	/* Calculate constant values */
	FOREACH_BLOCK(&list, block, opt_block(ctx, block));
	FREE_BLOCK_LIST(&list);
}
