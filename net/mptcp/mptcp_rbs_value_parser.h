#ifndef _MPTCP_RBS_VALUE_PARSER_H
#define _MPTCP_RBS_VALUE_PARSER_H

#include "mptcp_rbs_dynarray.h"
#include "mptcp_rbs_lexer.h"
#include "mptcp_rbs_value.h"
#include <linux/slab.h>
#include <linux/string.h>

/*
 * Clones a string by allocating memory and copying the content
 */
static char *strclone(const char *str)
{
	int len;
	char *result;

	if (!str)
		return NULL;

	len = strlen(str);
	result = kzalloc(len + 1, GFP_KERNEL);
	memcpy(result, str, len);
	return result;
}

/*
 * Type to manage variables
 */
struct var {
	char *name;
	int var_number;
	enum mptcp_rbs_type_kind type;
	union {
		bool reinject;
		enum mptcp_rbs_value_kind underlying_queue_kind;
	};
};

static struct var *var_new(char *name, int var_number,
			   enum mptcp_rbs_type_kind type, bool *reinject,
			   enum mptcp_rbs_value_kind *underlying_queue_kind)
{
	struct var *var;

	var = kzalloc(sizeof(struct var), GFP_KERNEL);
	var->name = strclone(name);
	var->var_number = var_number;
	var->type = type;
	if (reinject)
		var->reinject = *reinject;
	else if (underlying_queue_kind)
		var->underlying_queue_kind = *underlying_queue_kind;

	return var;
}

static void var_free(struct var *var)
{
	kfree(var->name);
	kfree(var);
}

/*
 * Variable lists
 */

DECL_DA(var_list, struct var *);

#define INIT_VAR_LIST(list) INIT_DA(list)

#define FREE_VAR_LIST(list) FREE_DA(list)

#define ADD_VAR(list, var) ADD_DA_ITEM(list, var)

#define FOREACH_VAR(list, var_, cmds) FOREACH_DA_ITEM(list, var_, cmds)

/*
 * Variable list stacks
 */

DECL_DA(var_list_stack, struct var_list *);

#define INIT_VAR_LIST_STACK(stack) INIT_DA(stack)

#define FREE_VAR_LIST_STACK(stack) FREE_DA(stack)

#define PUSH_VAR_LIST(stack, list) ADD_DA_ITEM(stack, list)

#define POP_VAR_LIST(stack) DELETE_DA_ITEM(stack, GET_DA_LEN(stack) - 1)

#define GET_VAR_LIST_STACK_TOP(stack) GET_DA_ITEM(stack, GET_DA_LEN(stack) - 1)

#define FOREACH_STACK_VAR(stack, var, cmds)                                    \
	do {                                                                   \
		struct var_list *__list;                                       \
		FOREACH_DA_ITEM_REV(stack, __list,                             \
				    FOREACH_VAR(__list, var, cmds));           \
	} while (0)

/*
 * Type and functions to manage a stack of replacements. Replacements can be
 * registered by values to replace identifiers in sub values with values. This
 * is useful for values like FILTER(s => ...)
 */

typedef struct mptcp_rbs_value *(*new_repl_value_func)(void *tag);

struct repl {
	char *name;
	new_repl_value_func new_value;
	void *tag;
};

/*
 * Replacement stacks
 */

DECL_DA(repl_stack, struct repl *);

#define INIT_REPL_STACK(stack) INIT_DA(stack)

#define FREE_REPL_STACK(stack) FREE_DA(stack)

#define PUSH_REPL(stack, repl) ADD_DA_ITEM(stack, repl)

#define POP_REPL(stack) DELETE_DA_ITEM(stack, GET_DA_LEN(stack) - 1)

#define FOREACH_REPL(stack, var, cmds) FOREACH_DA_ITEM_REV(stack, var, cmds)

struct parse_ctx {
	char const *str;
	int position;
	int line;
	int line_position;
	struct repl_stack repls;
	struct var_list_stack var_stack;
	/* Index of the next free variable */
	int var_index;
	enum mptcp_rbs_value_kind underlying_queue_kind;
};

static bool expect_token(struct parse_ctx *ctx, enum mptcp_rbs_token_kind kind,
			 struct mptcp_rbs_token *token);
static bool lookahead_token(struct parse_ctx *ctx,
			    struct mptcp_rbs_token *token);
static struct mptcp_rbs_value_bool *parse_value_bool(struct parse_ctx *ctx);
static struct mptcp_rbs_value_int *parse_value_int(struct parse_ctx *ctx);
static struct mptcp_rbs_value_string *parse_value_string(struct parse_ctx *ctx);
static struct mptcp_rbs_value_sbf *parse_value_sbf(struct parse_ctx *ctx);
static struct mptcp_rbs_value_skb *parse_value_skb(struct parse_ctx *ctx);

/*
 * Q sockbuffer list value
 */

static struct mptcp_rbs_value_q *mptcp_rbs_value_q_parse(struct parse_ctx *ctx)
{
	ctx->underlying_queue_kind = VALUE_KIND_Q;
	return mptcp_rbs_value_q_new();
}

/*
 * QU sockbuffer list value
 */

static struct mptcp_rbs_value_qu *mptcp_rbs_value_qu_parse(
    struct parse_ctx *ctx)
{
	ctx->underlying_queue_kind = VALUE_KIND_QU;
	return mptcp_rbs_value_qu_new();
}

/*
 * RQ sockbuffer list value
 */

static struct mptcp_rbs_value_rq *mptcp_rbs_value_rq_parse(
    struct parse_ctx *ctx)
{
	ctx->underlying_queue_kind = VALUE_KIND_RQ;
	return mptcp_rbs_value_rq_new();
}

/*
 * <subflow>.RTT integer value
 */

static struct mptcp_rbs_value_sbf_rtt *mptcp_rbs_value_sbf_rtt_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_rtt_new(sbf);
}

/*
 * <subflow>.RTT_MS integer value
 */

static struct mptcp_rbs_value_sbf_rtt_ms *mptcp_rbs_value_sbf_rtt_ms_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_rtt_ms_new(sbf);
}

/*
 * <subflow>.RTT_VAR integer value
 */

static struct mptcp_rbs_value_sbf_rtt_var *mptcp_rbs_value_sbf_rtt_var_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_rtt_var_new(sbf);
}

/*
 * <subflow>.USER integer value
 */

static struct mptcp_rbs_value_sbf_user *mptcp_rbs_value_sbf_user_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_user_new(sbf);
}

/*
 * <subflow>.IS_BACKUP boolean value
 */

static struct mptcp_rbs_value_sbf_is_backup *
mptcp_rbs_value_sbf_is_backup_parse(struct parse_ctx *ctx,
				    struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_is_backup_new(sbf);
}

/*
 * <subflow>.CWND integer value
 */

static struct mptcp_rbs_value_sbf_cwnd *mptcp_rbs_value_sbf_cwnd_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_cwnd_new(sbf);
}

/*
 * <subflow>.QUEUED integer value
 */

static struct mptcp_rbs_value_sbf_queued *mptcp_rbs_value_sbf_queued_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_queued_new(sbf);
}

/*
 * <subflow>.SKBS_IN_FLIGHT integer value
 */

static struct mptcp_rbs_value_sbf_skbs_in_flight *
mptcp_rbs_value_sbf_skbs_in_flight_parse(struct parse_ctx *ctx,
					 struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_skbs_in_flight_new(sbf);
}

/*
 * <subflow>.LOST_SKBS integer value
 */

static struct mptcp_rbs_value_sbf_lost_skbs *
mptcp_rbs_value_sbf_lost_skbs_parse(struct parse_ctx *ctx,
				    struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_lost_skbs_new(sbf);
}

/*
 * <subflow>.HAS_WINDOW_FOR boolean value
 */

static struct mptcp_rbs_value_sbf_has_window_for *
mptcp_rbs_value_sbf_has_window_for_parse(struct parse_ctx *ctx,
					 struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_skb *skb;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Sockbuffer value must follow */
	skb = parse_value_skb(ctx);
	if (!skb)
		return NULL;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		skb->free(skb);
		return NULL;
	}

	return mptcp_rbs_value_sbf_has_window_for_new(sbf, skb);
}

/*
 * <subflow>.ID integer value
 */

static struct mptcp_rbs_value_sbf_id *mptcp_rbs_value_sbf_id_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_id_new(sbf);
}

/*
 * <subflow>.DELAY_IN integer value
 */

static struct mptcp_rbs_value_sbf_delay_in *mptcp_rbs_value_sbf_delay_in_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_delay_in_new(sbf);
}

/*
 * <subflow>.DELAY_OUT integer value
 */

static struct mptcp_rbs_value_sbf_delay_out *
mptcp_rbs_value_sbf_delay_out_parse(struct parse_ctx *ctx,
				    struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_delay_out_new(sbf);
}

/*
 * <subflow>.BW_OUT_SEND integer value
 */

static struct mptcp_rbs_value_sbf_bw_out_send *
mptcp_rbs_value_sbf_bw_out_send_parse(struct parse_ctx *ctx,
				      struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_bw_out_send_new(sbf);
}

/*
 * <subflow>.BW_OUT_ACK integer value
 */

static struct mptcp_rbs_value_sbf_bw_out_ack *
mptcp_rbs_value_sbf_bw_out_ack_parse(struct parse_ctx *ctx,
				     struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_bw_out_ack_new(sbf);
}

/*
 * <subflow>.SSTHRESH integer value
 */

static struct mptcp_rbs_value_sbf_ssthresh *mptcp_rbs_value_sbf_ssthresh_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_ssthresh_new(sbf);
}

/*
 * <subflow>.THROTTLED boolean value
 */

static struct mptcp_rbs_value_sbf_throttled *
mptcp_rbs_value_sbf_throttled_parse(struct parse_ctx *ctx,
				    struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_throttled_new(sbf);
}

/*
 * <subflow>.LOSSY boolean value
 */

static struct mptcp_rbs_value_sbf_lossy *mptcp_rbs_value_sbf_lossy_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf *sbf)
{
	return mptcp_rbs_value_sbf_lossy_new(sbf);
}

/*
 * SUBFLOWS subflow list value
 */

static struct mptcp_rbs_value_subflows *mptcp_rbs_value_subflows_parse(
    struct parse_ctx *ctx)
{
	return mptcp_rbs_value_subflows_new();
}

/*
 * CURRENT_TIME_MS integer value
 */

static struct mptcp_rbs_value_current_time_ms *
mptcp_rbs_value_current_time_ms_parse(struct parse_ctx *ctx)
{
	return mptcp_rbs_value_current_time_ms_new();
}

/*
 * RANDOM integer value
 */

static struct mptcp_rbs_value_random *mptcp_rbs_value_random_parse(
    struct parse_ctx *ctx)
{
	return mptcp_rbs_value_random_new();
}

/*
 * <subflow list>.EMPTY boolean value
 */

static struct mptcp_rbs_value_sbf_list_empty *
mptcp_rbs_value_sbf_list_empty_parse(struct parse_ctx *ctx,
				     struct mptcp_rbs_value_sbf_list *list)
{
	return mptcp_rbs_value_sbf_list_empty_new(list);
}

/*
 * <subflow list>.FILTER subflow list value
 */

static struct mptcp_rbs_value_sbf_list_filter *
mptcp_rbs_value_sbf_list_filter_parse(struct parse_ctx *ctx,
				      struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	struct mptcp_rbs_value_sbf_list_filter *value;
	struct repl repl;
	struct mptcp_rbs_value_bool *cond;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return NULL;

	/* => must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return NULL;
	if (!expect_token(ctx, TOKEN_KIND_GREATER, &token))
		return NULL;

	/* Install replacement */
	value = mptcp_rbs_value_sbf_list_filter_new();
	repl.name = ident_token.string;
	repl.new_value =
	    (new_repl_value_func) mptcp_rbs_value_sbf_list_filter_sbf_new;
	repl.tag = &value->cur;
	PUSH_REPL(&ctx->repls, &repl);

	/* Boolean value must follow */
	cond = parse_value_bool(ctx);
	POP_REPL(&ctx->repls);
	if (!cond) {
		mptcp_rbs_value_sbf_list_filter_free(value);
		return NULL;
	}
	value->cond = cond;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return NULL;
	}
	value->list = list;

	return value;
}

/*
 * Special value holding the actual subflow for FILTER subflow list value
 */

static struct mptcp_rbs_value_sbf_list_filter_sbf *
mptcp_rbs_value_sbf_list_filter_sbf_parse(struct parse_ctx *ctx)
{
	/* This should never be called because this value cannot be parsed */
	BUG_ON(true);
	return NULL;
}

/*
 * <subflow list>.MAX subflow value
 */

static struct mptcp_rbs_value_sbf_list_max *mptcp_rbs_value_sbf_list_max_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	struct mptcp_rbs_value_sbf_list_max *value;
	struct repl repl;
	struct mptcp_rbs_value_int *cond;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return NULL;

	/* => must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return NULL;
	if (!expect_token(ctx, TOKEN_KIND_GREATER, &token))
		return NULL;

	/* Install replacement */
	value = mptcp_rbs_value_sbf_list_max_new();
	repl.name = ident_token.string;
	repl.new_value =
	    (new_repl_value_func) mptcp_rbs_value_sbf_list_filter_sbf_new;
	repl.tag = &value->cur;
	PUSH_REPL(&ctx->repls, &repl);

	/* Integer value must follow */
	cond = parse_value_int(ctx);
	POP_REPL(&ctx->repls);
	if (!cond) {
		mptcp_rbs_value_sbf_list_max_free(value);
		return NULL;
	}
	value->cond = cond;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return NULL;
	}
	value->list = list;

	return value;
}

/*
 * <subflow list>.MIN subflow value
 */

static struct mptcp_rbs_value_sbf_list_min *mptcp_rbs_value_sbf_list_min_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	struct mptcp_rbs_value_sbf_list_min *value;
	struct repl repl;
	struct mptcp_rbs_value_int *cond;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return NULL;

	/* => must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return NULL;
	if (!expect_token(ctx, TOKEN_KIND_GREATER, &token))
		return NULL;

	/* Install replacement */
	value = mptcp_rbs_value_sbf_list_min_new();
	repl.name = ident_token.string;
	repl.new_value =
	    (new_repl_value_func) mptcp_rbs_value_sbf_list_filter_sbf_new;
	repl.tag = &value->cur;
	PUSH_REPL(&ctx->repls, &repl);

	/* Integer value must follow */
	cond = parse_value_int(ctx);
	POP_REPL(&ctx->repls);
	if (!cond) {
		mptcp_rbs_value_sbf_list_min_free(value);
		return NULL;
	}
	value->cond = cond;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return NULL;
	}
	value->list = list;

	return value;
}

/*
 * <subflow list>.GET subflow value
 */

static struct mptcp_rbs_value_sbf_list_get *mptcp_rbs_value_sbf_list_get_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_int *index;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Integer value must follow */
	index = parse_value_int(ctx);
	if (!index)
		return NULL;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		index->free(index);
		return NULL;
	}

	return mptcp_rbs_value_sbf_list_get_new(list, index);
}

/*
 * <subflow list>.COUNT integer value
 */

static struct mptcp_rbs_value_sbf_list_count *
mptcp_rbs_value_sbf_list_count_parse(struct parse_ctx *ctx,
				     struct mptcp_rbs_value_sbf_list *list)
{
	return mptcp_rbs_value_sbf_list_count_new(list);
}

/*
 * <subflow list>.SUM integer value
 */

static struct mptcp_rbs_value_sbf_list_sum *mptcp_rbs_value_sbf_list_sum_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	struct mptcp_rbs_value_sbf_list_sum *value;
	struct repl repl;
	struct mptcp_rbs_value_int *cond;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return NULL;

	/* => must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return NULL;
	if (!expect_token(ctx, TOKEN_KIND_GREATER, &token))
		return NULL;

	/* Install replacement */
	value = mptcp_rbs_value_sbf_list_sum_new();
	repl.name = ident_token.string;
	repl.new_value =
	    (new_repl_value_func) mptcp_rbs_value_sbf_list_filter_sbf_new;
	repl.tag = &value->cur;
	PUSH_REPL(&ctx->repls, &repl);

	/* Integer value must follow */
	cond = parse_value_int(ctx);
	POP_REPL(&ctx->repls);
	if (!cond) {
		mptcp_rbs_value_sbf_list_sum_free(value);
		return NULL;
	}
	value->cond = cond;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return NULL;
	}
	value->list = list;

	return value;
}

/*
 * <sockbuffer>.SENT_ON boolean value
 */

static struct mptcp_rbs_value_skb_sent_on *mptcp_rbs_value_skb_sent_on_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_sbf *sbf;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Subflow value must follow */
	sbf = parse_value_sbf(ctx);
	if (!sbf)
		return NULL;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		sbf->free(sbf);
		return NULL;
	}

	return mptcp_rbs_value_skb_sent_on_new(skb, sbf);
}

/*
 * <sockbuffer>.SENT_ON_ALL boolean value
 */

static struct mptcp_rbs_value_skb_sent_on_all *
mptcp_rbs_value_skb_sent_on_all_parse(struct parse_ctx *ctx,
				      struct mptcp_rbs_value_skb *skb)
{
	return mptcp_rbs_value_skb_sent_on_all_new(skb);
}

/*
 * <sockbuffer>.USER integer value
 */

static struct mptcp_rbs_value_skb_user *mptcp_rbs_value_skb_user_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb *skb)
{
	return mptcp_rbs_value_skb_user_new(skb);
}

/*
 * <sockbuffer>.SEQ integer value
 */

static struct mptcp_rbs_value_skb_seq *mptcp_rbs_value_skb_seq_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb *skb)
{
	return mptcp_rbs_value_skb_seq_new(skb);
}

/*
 * <sockbuffer>.PSH integer value
 */

static struct mptcp_rbs_value_skb_psh *mptcp_rbs_value_skb_psh_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb *skb)
{
	return mptcp_rbs_value_skb_psh_new(skb);
}

/*
 * <sockbuffer>.LENGTH integer value
 */

static struct mptcp_rbs_value_skb_length *mptcp_rbs_value_skb_length_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb *skb)
{
	return mptcp_rbs_value_skb_length_new(skb);
}

/*
 * <sockbuffer list>.EMPTY boolean value
 */

static struct mptcp_rbs_value_skb_list_empty *
mptcp_rbs_value_skb_list_empty_parse(struct parse_ctx *ctx,
				     struct mptcp_rbs_value_skb_list *list)
{
	return mptcp_rbs_value_skb_list_empty_new(list);
}

/*
 * <sockbuffer list>.POP() sockbuffer value
 */

static struct mptcp_rbs_value_skb_list_pop *mptcp_rbs_value_skb_list_pop_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_token token;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token))
		return NULL;

	return mptcp_rbs_value_skb_list_pop_new(list);
}

/*
 * <sockbuffer list>.FILTER sockbuffer list value
 */

static struct mptcp_rbs_value_skb_list_filter *
mptcp_rbs_value_skb_list_filter_parse(struct parse_ctx *ctx,
				      struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	struct mptcp_rbs_value_skb_list_filter *value;
	struct repl repl;
	struct mptcp_rbs_value_bool *cond;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return NULL;

	/* => must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return NULL;
	if (!expect_token(ctx, TOKEN_KIND_GREATER, &token))
		return NULL;

	/* Install replacement */
	value = mptcp_rbs_value_skb_list_filter_new();
	value->progress.reinject = list->underlying_queue_kind == VALUE_KIND_RQ;
	repl.name = ident_token.string;
	repl.new_value =
	    (new_repl_value_func) mptcp_rbs_value_skb_list_filter_skb_new;
	repl.tag = &value->progress;
	PUSH_REPL(&ctx->repls, &repl);

	/* Boolean value must follow */
	cond = parse_value_bool(ctx);
	POP_REPL(&ctx->repls);
	if (!cond) {
		mptcp_rbs_value_skb_list_filter_free(value);
		return NULL;
	}
	value->cond = cond;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return NULL;
	}
	value->list = list;
	value->underlying_queue_kind = list->underlying_queue_kind;

	return value;
}

/*
 * Special value holding the actual sockbuffer for FILTER sockbuffer list value
 */

static struct mptcp_rbs_value_skb_list_filter_skb *
mptcp_rbs_value_skb_list_filter_skb_parse(struct parse_ctx *ctx)
{
	/* This should never be called because this value cannot be parsed */
	BUG_ON(true);
	return NULL;
}

/*
 * <sockbuffer list>.COUNT integer value
 */

static struct mptcp_rbs_value_skb_list_count *
mptcp_rbs_value_skb_list_count_parse(struct parse_ctx *ctx,
				     struct mptcp_rbs_value_skb_list *list)
{
	return mptcp_rbs_value_skb_list_count_new(list);
}

/*
 * <sockbuffer list>.TOP sockbuffer value
 */

static struct mptcp_rbs_value_skb_list_top *mptcp_rbs_value_skb_list_top_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb_list *list)
{
	return mptcp_rbs_value_skb_list_top_new(list);
}

/*
 * <sockbuffer list>.GET sockbuffer value
 */

static struct mptcp_rbs_value_skb_list_get *mptcp_rbs_value_skb_list_get_parse(
    struct parse_ctx *ctx, struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_int *index;

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return NULL;

	/* Integer value must follow */
	index = parse_value_int(ctx);
	if (!index)
		return NULL;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		index->free(index);
		return NULL;
	}

	return mptcp_rbs_value_skb_list_get_new(list, index);
}

#endif
