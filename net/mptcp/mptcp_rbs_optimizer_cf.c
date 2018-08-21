#include "mptcp_rbs_optimizer_cf.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_optimizer.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value.h"

#define IS_NULL(info) ((info) && (info)->is_const && (info)->const_value == -1)

/* Since we cannot directly represent true or false in
 * the language we have to use a comparison
 */
#define TRUE                                                                   \
	((struct mptcp_rbs_value *) mptcp_rbs_value_equal_new(                 \
	    (struct mptcp_rbs_value_int *) mptcp_rbs_value_constint_new(0),    \
	    (struct mptcp_rbs_value_int *) mptcp_rbs_value_constint_new(0)))

#define FALSE                                                                  \
	((struct mptcp_rbs_value *) mptcp_rbs_value_unequal_new(               \
	    (struct mptcp_rbs_value_int *) mptcp_rbs_value_constint_new(0),    \
	    (struct mptcp_rbs_value_int *) mptcp_rbs_value_constint_new(0)))

static void opt_value(struct mptcp_rbs_opt_ctx *ctx,
		      struct mptcp_rbs_value **value_ptr)
{
	struct mptcp_rbs_value *value = *value_ptr;
	struct mptcp_rbs_opt_value_info *info;

	/* Note: We can ignore constant NULL values here because they are
	 * propagated up to the root and as result this function is not called
	 */

	switch (value->kind) {
	case VALUE_KIND_CONSTINT:
	case VALUE_KIND_CONSTSTRING:
	case VALUE_KIND_NULL: {
		/* Cannot be optimized any further */
		return;
	}
	case VALUE_KIND_BOOL_VAR:
	case VALUE_KIND_INT_VAR:
	case VALUE_KIND_STRING_VAR:
	case VALUE_KIND_SBF_VAR:
	case VALUE_KIND_SBFLIST_VAR:
	case VALUE_KIND_SKB_VAR:
	case VALUE_KIND_SKBLIST_VAR: {
		/* Variables are inlined in an extra pass */
		return;
	}
	case VALUE_KIND_NOT: {
		struct mptcp_rbs_value_not *not_value =
		    (struct mptcp_rbs_value_not *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			not_value->free(not_value);
		} else
			opt_value(
			    ctx,
			    (struct mptcp_rbs_value **) &not_value->operand);

		return;
	}
	case VALUE_KIND_EQUAL: {
		struct mptcp_rbs_value_equal *equal_value =
		    (struct mptcp_rbs_value_equal *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			equal_value->free(equal_value);
		} else {
			opt_value(ctx, (struct mptcp_rbs_value **) &equal_value
					   ->left_operand);
			opt_value(ctx, (struct mptcp_rbs_value **) &equal_value
					   ->right_operand);
		}

		return;
	}
	case VALUE_KIND_UNEQUAL: {
		struct mptcp_rbs_value_unequal *unequal_value =
		    (struct mptcp_rbs_value_unequal *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			unequal_value->free(unequal_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &unequal_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &unequal_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_LESS: {
		struct mptcp_rbs_value_less *less_value =
		    (struct mptcp_rbs_value_less *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			less_value->free(less_value);
		} else {
			opt_value(ctx, (struct mptcp_rbs_value **) &less_value
					   ->left_operand);
			opt_value(ctx, (struct mptcp_rbs_value **) &less_value
					   ->right_operand);
		}

		return;
	}
	case VALUE_KIND_LESS_EQUAL: {
		struct mptcp_rbs_value_less_equal *less_equal_value =
		    (struct mptcp_rbs_value_less_equal *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			less_equal_value->free(less_equal_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &less_equal_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &less_equal_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_GREATER: {
		struct mptcp_rbs_value_greater *greater_value =
		    (struct mptcp_rbs_value_greater *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			greater_value->free(greater_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &greater_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &greater_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_GREATER_EQUAL: {
		struct mptcp_rbs_value_greater_equal *greater_equal_value =
		    (struct mptcp_rbs_value_greater_equal *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			greater_equal_value->free(greater_equal_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value *
				       *) &greater_equal_value->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value *
				       *) &greater_equal_value->right_operand);
		}

		return;
	}
	case VALUE_KIND_AND: {
		struct mptcp_rbs_value_and *and_value =
		    (struct mptcp_rbs_value_and *) value;
		struct mptcp_rbs_opt_value_info *left_info;
		struct mptcp_rbs_opt_value_info *right_info;

		info = mptcp_rbs_opt_find_value_info(ctx, value);
		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			and_value->free(and_value);
			return;
		}

		left_info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) and_value->left_operand);
		right_info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) and_value->right_operand);

		if (left_info && left_info->is_const &&
		    left_info->const_value == 1) {
			struct mptcp_rbs_value_bool *right_operand =
			    and_value->right_operand;

			and_value->right_operand = NULL;
			and_value->free(and_value);

			*value_ptr = (struct mptcp_rbs_value *) right_operand;
		} else if (right_info && right_info->is_const &&
			   right_info->const_value == 1) {
			struct mptcp_rbs_value_bool *left_operand =
			    and_value->left_operand;

			and_value->left_operand = NULL;
			and_value->free(and_value);

			*value_ptr = (struct mptcp_rbs_value *) left_operand;
		}

		return;
	}
	case VALUE_KIND_OR: {
		struct mptcp_rbs_value_or *or_value =
		    (struct mptcp_rbs_value_or *) value;
		struct mptcp_rbs_opt_value_info *left_info;
		struct mptcp_rbs_opt_value_info *right_info;

		info = mptcp_rbs_opt_find_value_info(ctx, value);
		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			or_value->free(or_value);
			return;
		}

		left_info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) or_value->left_operand);
		right_info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) or_value->right_operand);

		if (left_info && left_info->is_const &&
		    left_info->const_value == 0) {
			struct mptcp_rbs_value_bool *right_operand =
			    or_value->right_operand;

			or_value->right_operand = NULL;
			or_value->free(or_value);

			*value_ptr = (struct mptcp_rbs_value *) right_operand;
		} else if (right_info && right_info->is_const &&
			   right_info->const_value == 0) {
			struct mptcp_rbs_value_bool *left_operand =
			    or_value->left_operand;

			or_value->left_operand = NULL;
			or_value->free(or_value);

			*value_ptr = (struct mptcp_rbs_value *) left_operand;
		}

		return;
	}
	case VALUE_KIND_ADD: {
		struct mptcp_rbs_value_add *add_value =
		    (struct mptcp_rbs_value_add *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(info->const_value);

			add_value->free(add_value);
		} else {
			opt_value(ctx, (struct mptcp_rbs_value **) &add_value
					   ->left_operand);
			opt_value(ctx, (struct mptcp_rbs_value **) &add_value
					   ->right_operand);
		}

		return;
	}
	case VALUE_KIND_SUBTRACT: {
		struct mptcp_rbs_value_subtract *subtract_value =
		    (struct mptcp_rbs_value_subtract *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(info->const_value);

			subtract_value->free(subtract_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &subtract_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &subtract_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_MULTIPLY: {
		struct mptcp_rbs_value_multiply *multiply_value =
		    (struct mptcp_rbs_value_multiply *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(info->const_value);

			multiply_value->free(multiply_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &multiply_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &multiply_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_DIVIDE: {
		struct mptcp_rbs_value_divide *divide_value =
		    (struct mptcp_rbs_value_divide *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(info->const_value);

			divide_value->free(divide_value);
		} else {
			opt_value(ctx, (struct mptcp_rbs_value **) &divide_value
					   ->left_operand);
			opt_value(ctx, (struct mptcp_rbs_value **) &divide_value
					   ->right_operand);
		}

		return;
	}
	case VALUE_KIND_REMAINDER: {
		struct mptcp_rbs_value_remainder *remainder_value =
		    (struct mptcp_rbs_value_remainder *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(info->const_value);

			remainder_value->free(remainder_value);
		} else {
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &remainder_value
				      ->left_operand);
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &remainder_value
				      ->right_operand);
		}

		return;
	}
	case VALUE_KIND_IS_NULL: {
		struct mptcp_rbs_value_is_null *is_null_value =
		    (struct mptcp_rbs_value_is_null *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			is_null_value->free(is_null_value);
		} else
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &is_null_value
				      ->operand);

		return;
	}
	case VALUE_KIND_IS_NOT_NULL: {
		struct mptcp_rbs_value_is_not_null *is_not_null_value =
		    (struct mptcp_rbs_value_is_not_null *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			is_not_null_value->free(is_not_null_value);
		} else
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &is_not_null_value
				      ->operand);

		return;
	}
	case VALUE_KIND_REG:
	case VALUE_KIND_Q:
	case VALUE_KIND_QU:
	case VALUE_KIND_RQ:
	case VALUE_KIND_SUBFLOWS:
	case VALUE_KIND_CURRENT_TIME_MS:
	case VALUE_KIND_RANDOM:
	case VALUE_KIND_SBFLIST_FILTER_SBF:
	case VALUE_KIND_SKBLIST_FILTER_SKB: {
		/* Cannot be constant */
		return;
	}
	case VALUE_KIND_SBF_RTT: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_rtt *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_RTT_MS: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_rtt_ms *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_RTT_VAR: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_rtt_var *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_USER: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_user *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_QUEUED: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_queued *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_IS_BACKUP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_is_backup *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_CWND: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_cwnd *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_SKBS_IN_FLIGHT: {
		opt_value(
		    ctx,
		    (struct mptcp_rbs_value **) &(
			(struct mptcp_rbs_value_sbf_skbs_in_flight *) value)
			->sbf);
		return;
	}
	case VALUE_KIND_SBF_LOST_SKBS: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_lost_skbs *) value)
			      ->sbf);
		return;
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
		return;
	}
	case VALUE_KIND_SBF_ID: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_id *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBF_DELAY_IN: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_delay_in *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_DELAY_OUT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_delay_out *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_BW_OUT_SEND: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_bw_out_send *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_BW_OUT_ACK: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_bw_out_ack *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_SSTHRESH: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_ssthresh *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_THROTTLED: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_throttled *) value)
			      ->sbf);
		return;
	}
	case VALUE_KIND_SBF_LOSSY: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_sbf_lossy *) value)
				   ->sbf);
		return;
	}
	case VALUE_KIND_SBFLIST_NEXT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_next *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SBFLIST_EMPTY: {
		struct mptcp_rbs_value_sbf_list_empty *empty_value =
		    (struct mptcp_rbs_value_sbf_list_empty *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			empty_value->free(empty_value);
		} else
			opt_value(
			    ctx,
			    (struct mptcp_rbs_value **) &empty_value->list);

		return;
	}
	case VALUE_KIND_SBFLIST_FILTER: {
		struct mptcp_rbs_value_sbf_list_filter *filter_value =
		    (struct mptcp_rbs_value_sbf_list_filter *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &filter_value->list);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) filter_value->cond);

		if (info && info->is_const && info->const_value == 1) {
			struct mptcp_rbs_value_sbf_list *list =
			    filter_value->list;

			filter_value->list = NULL;
			filter_value->free(filter_value);

			*value_ptr = (struct mptcp_rbs_value *) list;
		} else
			opt_value(
			    ctx,
			    (struct mptcp_rbs_value **) &filter_value->cond);

		return;
	}
	case VALUE_KIND_SBFLIST_MAX: {
		struct mptcp_rbs_value_sbf_list_max *max_value =
		    (struct mptcp_rbs_value_sbf_list_max *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &max_value->list);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) max_value->cond);

		if (info && info->is_const) {
			/* Just take the first subflow */
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_sbf_list_get_new(
				max_value->list,
				(struct mptcp_rbs_value_int *)
				    mptcp_rbs_value_constint_new(0));

			max_value->list = NULL;
			max_value->free(max_value);
		}

		return;
	}
	case VALUE_KIND_SBFLIST_MIN: {
		struct mptcp_rbs_value_sbf_list_min *min_value =
		    (struct mptcp_rbs_value_sbf_list_min *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &min_value->list);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) min_value->cond);

		if (info && info->is_const) {
			/* Just take the first subflow */
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_sbf_list_get_new(
				min_value->list,
				(struct mptcp_rbs_value_int *)
				    mptcp_rbs_value_constint_new(0));

			min_value->list = NULL;
			min_value->free(min_value);
		}

		return;
	}
	case VALUE_KIND_SBFLIST_GET: {
		struct mptcp_rbs_value_sbf_list_get *get_value =
		    (struct mptcp_rbs_value_sbf_list_get *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &get_value->list);
		opt_value(ctx, (struct mptcp_rbs_value **) &get_value->index);
		return;
	}
	case VALUE_KIND_SBFLIST_COUNT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_sbf_list_count *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SBFLIST_SUM: {
		struct mptcp_rbs_value_sbf_list_sum *sum_value =
		    (struct mptcp_rbs_value_sbf_list_sum *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &sum_value->list);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) sum_value->cond);

		if (info && info->is_const && info->const_value == 0) {
			/* Just 0 */
			*value_ptr = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_constint_new(0);

			sum_value->free(sum_value);
		}

		return;
	}
	case VALUE_KIND_SKB_SENT_ON: {
		struct mptcp_rbs_value_skb_sent_on *sent_on_value =
		    (struct mptcp_rbs_value_skb_sent_on *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &sent_on_value->sbf);
		opt_value(ctx, (struct mptcp_rbs_value **) &sent_on_value->skb);
		return;
	}
	case VALUE_KIND_SKB_SENT_ON_ALL: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_sent_on_all *) value)
			      ->skb);
		return;
	}
	case VALUE_KIND_SKB_USER: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_user *) value)
				   ->skb);
		return;
	}
	case VALUE_KIND_SKB_SEQ: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_seq *) value)
				   ->skb);
		return;
	}
	case VALUE_KIND_SKB_PSH: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_psh *) value)
				   ->skb);
		return;
	}
	case VALUE_KIND_SKB_LENGTH: {
		opt_value(ctx, (struct mptcp_rbs_value **) &(
				   (struct mptcp_rbs_value_skb_length *) value)
				   ->skb);
		return;
	}
	case VALUE_KIND_SKBLIST_NEXT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_next *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SKBLIST_EMPTY: {
		struct mptcp_rbs_value_skb_list_empty *empty_value =
		    (struct mptcp_rbs_value_skb_list_empty *) value;

		info = mptcp_rbs_opt_find_value_info(ctx, value);

		if (info && info->is_const) {
			if (info->const_value == 1)
				*value_ptr = TRUE;
			else
				*value_ptr = FALSE;

			empty_value->free(empty_value);
		} else
			opt_value(
			    ctx,
			    (struct mptcp_rbs_value **) &empty_value->list);

		return;
	}
	case VALUE_KIND_SKBLIST_POP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_pop *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SKBLIST_FILTER: {
		struct mptcp_rbs_value_skb_list_filter *filter_value =
		    (struct mptcp_rbs_value_skb_list_filter *) value;

		opt_value(ctx, (struct mptcp_rbs_value **) &filter_value->list);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) filter_value->cond);

		if (info && info->is_const && info->const_value == 1) {
			struct mptcp_rbs_value_skb_list *list =
			    filter_value->list;

			filter_value->list = NULL;
			filter_value->free(filter_value);

			*value_ptr = (struct mptcp_rbs_value *) list;
		} else
			opt_value(
			    ctx,
			    (struct mptcp_rbs_value **) &filter_value->cond);

		return;
	}
	case VALUE_KIND_SKBLIST_COUNT: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_count *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SKBLIST_TOP: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_top *) value)
			      ->list);
		return;
	}
	case VALUE_KIND_SKBLIST_GET: {
		opt_value(ctx,
			  (struct mptcp_rbs_value **) &(
			      (struct mptcp_rbs_value_skb_list_get *) value)
			      ->list);
		return;
	}
	}
}

static void opt_smt(struct mptcp_rbs_opt_ctx *ctx, struct mptcp_rbs_smt *smt)
{
	struct mptcp_rbs_opt_value_info *info;

	switch (smt->kind) {
	case SMT_KIND_DROP: {
		struct mptcp_rbs_smt_drop *drop_smt =
		    (struct mptcp_rbs_smt_drop *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) drop_smt->skb);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &drop_smt->skb);

		return;
	}
	case SMT_KIND_PRINT: {
		struct mptcp_rbs_smt_print *print_smt =
		    (struct mptcp_rbs_smt_print *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) print_smt->msg);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &print_smt->msg);

		if (print_smt->arg) {
			info = mptcp_rbs_opt_find_value_info(
			    ctx, (struct mptcp_rbs_value *) print_smt->arg);
			if (!IS_NULL(info))
				opt_value(ctx, &print_smt->arg);
		}

		return;
	}
	case SMT_KIND_PUSH: {
		struct mptcp_rbs_smt_push *push_smt =
		    (struct mptcp_rbs_smt_push *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) push_smt->sbf);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &push_smt->sbf);

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) push_smt->skb);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &push_smt->skb);

		return;
	}
	case SMT_KIND_SET: {
		struct mptcp_rbs_smt_set *set_smt =
		    (struct mptcp_rbs_smt_set *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) set_smt->value);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &set_smt->value);

		return;
	}
	case SMT_KIND_SET_USER: {
		struct mptcp_rbs_smt_set_user *set_user_smt =
		    (struct mptcp_rbs_smt_set_user *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) set_user_smt->value);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &set_user_smt->value);

		return;
	}
	case SMT_KIND_VAR: {
		struct mptcp_rbs_smt_var *var_smt =
		    (struct mptcp_rbs_smt_var *) smt;

		info = mptcp_rbs_opt_find_value_info(
		    ctx, (struct mptcp_rbs_value *) var_smt->value);
		if (!IS_NULL(info))
			opt_value(ctx,
				  (struct mptcp_rbs_value **) &var_smt->value);

		return;
	}
	case SMT_KIND_VOID: {
		struct mptcp_rbs_smt_void *void_smt =
		    (struct mptcp_rbs_smt_void *) smt;

		if (void_smt->value) {
			info = mptcp_rbs_opt_find_value_info(
			    ctx, (struct mptcp_rbs_value *) void_smt->value);
			if (!IS_NULL(info))
				opt_value(ctx,
					  (struct mptcp_rbs_value **) &void_smt
					      ->value);
		}

		return;
	}
	case SMT_KIND_EBPF: {
		/* Cannot optimize */
		return;
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

void mptcp_rbs_opt_cf(struct mptcp_rbs_opt_ctx *ctx)
{
	struct mptcp_rbs_cfg_block_list list;

	INIT_BLOCK_LIST(&list);
	opt_block(ctx, ctx->variation->first_block, &list);
	FREE_BLOCK_LIST(&list);
}
