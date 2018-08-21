#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_cfg.h"
#include "mptcp_rbs_ctx.h"
#include "mptcp_rbs_scheduler.h"
#include "mptcp_rbs_smt.h"
#include "mptcp_rbs_value_parser.h"

/* Macro to get the name of the parse function of a value */
#define PARSE_FUNC(STRUCT) STRUCT##_parse

/* Macro to ignore a value */
#define APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)

/* Macro to parse custom values without owner */
#define APPLY_PARSE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                       \
	if (!strcmp(str, STR)) {                                               \
		struct STRUCT *value = PARSE_FUNC(STRUCT)(ctx);                \
		if (!value)                                                    \
			return NULL;                                           \
		return (struct mptcp_rbs_value *) value;                       \
	}

/* Macro to parse custom values with a subflow owner */
#define APPLY_PARSE_SBF_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                   \
	if (!strcmp(str, STR)) {                                               \
		struct STRUCT *value2 = PARSE_FUNC(STRUCT)(                    \
		    ctx, (struct mptcp_rbs_value_sbf *) value);                \
		if (!value2) {                                                 \
			value->free(value);                                    \
			return NULL;                                           \
		}                                                              \
		value = (struct mptcp_rbs_value *) value2;                     \
		break;                                                         \
	}

/* Macro to parse custom values with a subflow list owner */
#define APPLY_PARSE_SBF_LIST_VALUE(ENUM, STR, STRUCT, RETURNTYPE)              \
	if (!strcmp(str, STR)) {                                               \
		struct STRUCT *value2 = PARSE_FUNC(STRUCT)(                    \
		    ctx, (struct mptcp_rbs_value_sbf_list *) value);           \
		if (!value2) {                                                 \
			value->free(value);                                    \
			return NULL;                                           \
		}                                                              \
		value = (struct mptcp_rbs_value *) value2;                     \
		break;                                                         \
	}

/* Macro to parse custom values with a sockbuffer owner */
#define APPLY_PARSE_SKB_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                   \
	if (!strcmp(str, STR)) {                                               \
		struct STRUCT *value2 = PARSE_FUNC(STRUCT)(                    \
		    ctx, (struct mptcp_rbs_value_skb *) value);                \
		if (!value2) {                                                 \
			value->free(value);                                    \
			return NULL;                                           \
		}                                                              \
		value = (struct mptcp_rbs_value *) value2;                     \
		break;                                                         \
	}

/* Macro to parse custom values with a sockbuffer list owner */
#define APPLY_PARSE_SKB_LIST_VALUE(ENUM, STR, STRUCT, RETURNTYPE)              \
	if (!strcmp(str, STR)) {                                               \
		struct STRUCT *value2 = PARSE_FUNC(STRUCT)(                    \
		    ctx, (struct mptcp_rbs_value_skb_list *) value);           \
		if (!value2) {                                                 \
			value->free(value);                                    \
			return NULL;                                           \
		}                                                              \
		value = (struct mptcp_rbs_value *) value2;                     \
		break;                                                         \
	}

static bool expect_token(struct parse_ctx *ctx, enum mptcp_rbs_token_kind kind,
			 struct mptcp_rbs_token *token)
{
	if (!mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				      &ctx->line_position, token)) {
		printk("%s\n", mptcp_rbs_get_last_error());
		return false;
	}

	if (token->kind != kind) {
		char s1[TOKEN_BUFFER_LEN];
		char s2[TOKEN_BUFFER_LEN];

		memset(s1, 0, TOKEN_BUFFER_LEN);
		memset(s2, 0, TOKEN_BUFFER_LEN);

		mptcp_rbs_token_kind_to_string(kind, s1);
		mptcp_rbs_token_to_string(token, s2);

		printk("%d: Token %s expected but %s found\n", token->position,
		       s1, s2);
		return false;
	}

	return true;
}

static bool lookahead_token(struct parse_ctx *ctx,
			    struct mptcp_rbs_token *token)
{
	return mptcp_rbs_get_next_token_lookahead(
	    ctx->str, ctx->position, ctx->line, ctx->line_position, token);
}

int sprintf_null(char **buf, const char *fmt, ...)
{
	int n;

	va_list args;
	va_start(args, fmt);

	if (buf && *buf) {
		n = vsprintf(*buf, fmt, args);
		*buf += n;
	} else
		n = vsnprintf(NULL, 0, fmt, args);

	va_end(args);

	return n;
}

static struct mptcp_rbs_value *parse_value(struct parse_ctx *ctx,
					   int *value_position);

static struct mptcp_rbs_value *parse_value_base(struct parse_ctx *ctx,
						int *value_position)
{
	struct mptcp_rbs_token token;

	if (!mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				      &ctx->line_position, &token)) {
		printk("%s\n", mptcp_rbs_get_last_error());
		return NULL;
	}

	*value_position = token.position;

	switch (token.kind) {
	case TOKEN_KIND_NUMBER:
		return (struct mptcp_rbs_value *) mptcp_rbs_value_constint_new(
		    token.number);
	case TOKEN_KIND_STRING:
		return (struct mptcp_rbs_value *)
		    mptcp_rbs_value_conststring_new(strclone(token.string));
	case TOKEN_KIND_NULL:
		return (struct mptcp_rbs_value *) mptcp_rbs_value_null_new();
	case TOKEN_KIND_IDENT: {
		const char *str = token.string;
		struct repl *repl;
		struct var *var;

		/* Might be register */
		if (str[0] == 'R' && str[1] >= '0' && str[1] <= '9' &&
		    str[2] == 0) {
			if (str[1] < '1' ||
			    str[1] > ('0' + MPTCP_RBS_REG_COUNT)) {
				printk("%d: Register name %s is invalid\n",
				       token.position, token.string);
				return NULL;
			}

			return (struct mptcp_rbs_value *)
			    mptcp_rbs_value_reg_new(str[1] - '1');
		}

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_PARSE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST

		/* Might be replacement */
		FOREACH_REPL(&ctx->repls, repl, if (!strcmp(str, repl->name)) {
			return repl->new_value(repl->tag);
		});

		/* Might be variable */
		FOREACH_STACK_VAR(
		    &ctx->var_stack, var, if (!strcmp(str, var->name)) {
			    switch (var->type) {
			    case TYPE_KIND_NULL:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_null_new();
			    case TYPE_KIND_BOOL:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_bool_var_new(
					    var->var_number);
			    case TYPE_KIND_INT:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_int_var_new(
					    var->var_number);
			    case TYPE_KIND_STRING:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_string_var_new(
					    var->var_number);
			    case TYPE_KIND_SBF:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_sbf_var_new(
					    var->var_number);
			    case TYPE_KIND_SBFLIST:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_sbf_list_var_new(
					    var->var_number);
			    case TYPE_KIND_SKB:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_skb_var_new(
					    var->var_number, var->reinject);
			    case TYPE_KIND_SKBLIST:
				    return (struct mptcp_rbs_value *)
					mptcp_rbs_value_skb_list_var_new(
					    var->var_number,
					    var->underlying_queue_kind);
			    }
		    });

		/* Not found */
		printk("%d:%d (%d): Unknown function/property %s\n", token.line,
		       token.line_position, token.position, str);
		return NULL;
	}
	case TOKEN_KIND_OPEN_BRACKET: {
		struct mptcp_rbs_value *inner =
		    parse_value(ctx, value_position);
		if (!inner)
			return NULL;

		*value_position = token.position;

		/* ) must follow */
		if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
			inner->free(inner);
			return NULL;
		}

		return inner;
	}
	default: {
		char s1[TOKEN_BUFFER_LEN];

		memset(s1, 0, TOKEN_BUFFER_LEN);
		mptcp_rbs_token_to_string(&token, s1);

		printk("%d: Value expected but %s found\n", token.position, s1);
		return NULL;
	}
	}
}

static struct mptcp_rbs_value *parse_value_dot(struct parse_ctx *ctx,
					       int *value_position)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value *value;

	if (!lookahead_token(ctx, &token)) {
		printk("%s\n", mptcp_rbs_get_last_error());
		return NULL;
	}

	value = parse_value_base(ctx, value_position);
	if (!value)
		return NULL;

	while (true) {
		/* . might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			value->free(value);
			return NULL;
		}

		if (token.kind != TOKEN_KIND_DOT)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		/* Identifier, SET_USER or PUSH must follow */
		if (!lookahead_token(ctx, &token)) {
			value->free(value);
			return NULL;
		}

		if (token.kind == TOKEN_KIND_PUSH || token.kind == TOKEN_KIND_SET_USER) {
			if (mptcp_rbs_value_get_type(value->kind) !=
			    TYPE_KIND_SBF) {
				printk(
				    "%d: Unknown function/property %s for %s\n",
				    token.position, token.string,
				    mptcp_rbs_type_get_name(
					mptcp_rbs_value_get_type(value->kind)));
				value->free(value);
				return NULL;
			}

			return value;
		}

		if (!expect_token(ctx, TOKEN_KIND_IDENT, &token)) {
			value->free(value);
			return NULL;
		}

		switch (mptcp_rbs_value_get_type(value->kind)) {
		case TYPE_KIND_SBF: {
			const char *str = token.string;

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_PARSE_SBF_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
			MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST

			/* Not found */
			printk("%d: Unknown function/property %s for subflow\n",
			       token.position, str);
			value->free(value);
			return NULL;
		}
		case TYPE_KIND_SBFLIST: {
			const char *str = token.string;

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_PARSE_SBF_LIST_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
			MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST

			/* Not found */
			printk("%d:%d (%d): Unknown function/property %s for "
			       "subflow "
			       "list\n",
			       token.line, token.line_position, token.position,
			       str);
			value->free(value);
			return NULL;
		}
		case TYPE_KIND_SKB: {
			const char *str = token.string;

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_PARSE_SKB_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
			MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST

			/* Not found */
			printk(
			    "%d: Unknown function/property %s for sockbuffer\n",
			    token.position, str);
			value->free(value);
			return NULL;
		}
		case TYPE_KIND_SKBLIST: {
			const char *str = token.string;

#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_IGNORE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_PARSE_SKB_LIST_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
			MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST

			/* Not found */
			printk("%d: Unknown function/property %s for "
			       "sockbuffer list\n",
			       token.position, str);
			value->free(value);
			return NULL;
		}
		default: {
			printk("%d: Unknown function/property %s for %s\n",
			       token.position, token.string,
			       mptcp_rbs_type_get_name(
				   mptcp_rbs_value_get_type(value->kind)));
			value->free(value);
			return NULL;
		}
		}
	}

	return value;
}

static struct mptcp_rbs_value *parse_value_not(struct parse_ctx *ctx,
					       int *value_position)
{
	struct mptcp_rbs_value *inner;
	struct mptcp_rbs_token token;
	bool negate;

	/* ! might follow */
	if (!lookahead_token(ctx, &token)) {
		printk("%s\n", mptcp_rbs_get_last_error());
		return NULL;
	}

	negate = token.kind == TOKEN_KIND_NOT;
	if (negate)
		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

	inner = parse_value_dot(ctx, value_position);
	if (!inner)
		return NULL;

	if (negate) {
		enum mptcp_rbs_type_kind type =
		    mptcp_rbs_value_get_type(inner->kind);

		if (type != TYPE_KIND_BOOL) {
			printk("%d: ! operator cannot be applied on %s\n",
			       token.position, mptcp_rbs_type_get_name(type));
			inner->free(inner);
			return NULL;
		}

		return (struct mptcp_rbs_value *) mptcp_rbs_value_not_new(
		    (struct mptcp_rbs_value_bool *) inner);
	}

	return inner;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
static struct mptcp_rbs_value *parse_value_multiply(struct parse_ctx *ctx,
						    int *value_position)
{
	struct mptcp_rbs_value *left_value;
	struct mptcp_rbs_value *right_value;
	enum mptcp_rbs_type_kind left_type;
	enum mptcp_rbs_type_kind right_type;
	int right_value_position;
	struct mptcp_rbs_token token;

	left_value = parse_value_not(ctx, value_position);
	if (!left_value)
		return NULL;

	while (true) {
		/* *, / or % might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			left_value->free(left_value);
			return NULL;
		}
		if (token.kind != TOKEN_KIND_MUL &&
		    token.kind != TOKEN_KIND_DIV &&
		    token.kind != TOKEN_KIND_REM)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		right_value = parse_value_not(ctx, &right_value_position);
		if (!right_value) {
			left_value->free(left_value);
			return NULL;
		}

		left_type = mptcp_rbs_value_get_type(left_value->kind);
		right_type = mptcp_rbs_value_get_type(right_value->kind);

		if (left_type != TYPE_KIND_INT || right_type != TYPE_KIND_INT) {
			switch (token.kind) {
			case TOKEN_KIND_MUL: {
				printk("%d: * operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				break;
			}
			case TOKEN_KIND_DIV: {
				printk("%d: / operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				break;
			}
			case TOKEN_KIND_REM: {
				printk("%d: %% operator cannot be applied on "
				       "%s and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				break;
			}
			}

			left_value->free(left_value);
			right_value->free(right_value);
			return NULL;
		}

		switch (token.kind) {
		case TOKEN_KIND_MUL: {
			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_multiply_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_DIV: {
			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_divide_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_REM: {
			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_remainder_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		}
	}

	return left_value;
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
static struct mptcp_rbs_value *parse_value_add(struct parse_ctx *ctx,
					       int *value_position)
{
	struct mptcp_rbs_value *left_value;
	struct mptcp_rbs_value *right_value;
	enum mptcp_rbs_type_kind left_type;
	enum mptcp_rbs_type_kind right_type;
	int right_value_position;
	struct mptcp_rbs_token token;

	left_value = parse_value_multiply(ctx, value_position);
	if (!left_value)
		return NULL;

	while (true) {
		/* + or - might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			left_value->free(left_value);
			return NULL;
		}
		if (token.kind != TOKEN_KIND_ADD &&
		    token.kind != TOKEN_KIND_SUB)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		right_value = parse_value_multiply(ctx, &right_value_position);
		if (!right_value) {
			left_value->free(left_value);
			return NULL;
		}

		left_type = mptcp_rbs_value_get_type(left_value->kind);
		right_type = mptcp_rbs_value_get_type(right_value->kind);

		if (left_type != TYPE_KIND_INT || right_type != TYPE_KIND_INT) {
			switch (token.kind) {
			case TOKEN_KIND_ADD: {
				printk("%d: + operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				break;
			}
			case TOKEN_KIND_SUB: {
				printk("%d: - operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				break;
			}
			}

			left_value->free(left_value);
			right_value->free(right_value);
			return NULL;
		}

		switch (token.kind) {
		case TOKEN_KIND_ADD: {
			left_value =
			    (struct mptcp_rbs_value *) mptcp_rbs_value_add_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_SUB: {
			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_subtract_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		}
	}

	return left_value;
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
static struct mptcp_rbs_value *parse_value_cmp(struct parse_ctx *ctx,
					       int *value_position)
{
	struct mptcp_rbs_value *left_value;
	struct mptcp_rbs_value *right_value;
	enum mptcp_rbs_type_kind left_type;
	enum mptcp_rbs_type_kind right_type;
	int right_value_position;
	struct mptcp_rbs_token token;

	left_value = parse_value_add(ctx, value_position);
	if (!left_value)
		return NULL;

	while (true) {
		/* =, !=, <, <=, > or >= might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			left_value->free(left_value);
			return NULL;
		}
		if (token.kind != TOKEN_KIND_EQUAL &&
		    token.kind != TOKEN_KIND_UNEQUAL &&
		    token.kind != TOKEN_KIND_LESS &&
		    token.kind != TOKEN_KIND_LESS_EQUAL &&
		    token.kind != TOKEN_KIND_GREATER &&
		    token.kind != TOKEN_KIND_GREATER_EQUAL)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		right_value = parse_value_add(ctx, &right_value_position);
		if (!right_value) {
			left_value->free(left_value);
			return NULL;
		}

		left_type = mptcp_rbs_value_get_type(left_value->kind);
		right_type = mptcp_rbs_value_get_type(right_value->kind);

		switch (token.kind) {
		case TOKEN_KIND_EQUAL: {
			if (right_type == TYPE_KIND_NULL) {
				left_value = (struct mptcp_rbs_value *)
				    mptcp_rbs_value_is_null_new(left_value);

				right_value->free(right_value);
				break;
			}

			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: = operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_equal_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_UNEQUAL: {
			if (right_type == TYPE_KIND_NULL) {
				left_value = (struct mptcp_rbs_value *)
				    mptcp_rbs_value_is_not_null_new(left_value);

				right_value->free(right_value);
				break;
			}

			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: != operator cannot be applied on "
				       "%s and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_unequal_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_LESS: {
			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: < operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value =
			    (struct mptcp_rbs_value *) mptcp_rbs_value_less_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_LESS_EQUAL: {
			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: <= operator cannot be applied on "
				       "%s and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_less_equal_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_GREATER: {
			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: > operator cannot be applied on %s "
				       "and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_greater_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		case TOKEN_KIND_GREATER_EQUAL: {
			if (left_type != TYPE_KIND_INT ||
			    right_type != TYPE_KIND_INT) {
				printk("%d: >= operator cannot be applied on "
				       "%s and %s\n",
				       token.position,
				       mptcp_rbs_type_get_name(left_type),
				       mptcp_rbs_type_get_name(right_type));
				left_value->free(left_value);
				right_value->free(right_value);
				return NULL;
			}

			left_value = (struct mptcp_rbs_value *)
			    mptcp_rbs_value_greater_equal_new(
				(struct mptcp_rbs_value_int *) left_value,
				(struct mptcp_rbs_value_int *) right_value);
			break;
		}
		}
	}

	return left_value;
}
#pragma GCC diagnostic pop

static struct mptcp_rbs_value *parse_value_and(struct parse_ctx *ctx,
					       int *value_position)
{
	struct mptcp_rbs_value *left_value;
	struct mptcp_rbs_value *right_value;
	enum mptcp_rbs_type_kind left_type;
	enum mptcp_rbs_type_kind right_type;
	int right_value_position;
	struct mptcp_rbs_token token;

	left_value = parse_value_cmp(ctx, value_position);
	if (!left_value)
		return NULL;

	while (true) {
		/* OR might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			left_value->free(left_value);
			return NULL;
		}
		if (token.kind != TOKEN_KIND_AND)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		right_value = parse_value_cmp(ctx, &right_value_position);
		if (!right_value) {
			left_value->free(left_value);
			return NULL;
		}

		left_type = mptcp_rbs_value_get_type(left_value->kind);
		right_type = mptcp_rbs_value_get_type(right_value->kind);

		if (left_type != TYPE_KIND_BOOL ||
		    right_type != TYPE_KIND_BOOL) {
			printk(
			    "%d: AND operator cannot be applied on %s and %s\n",
			    token.position, mptcp_rbs_type_get_name(left_type),
			    mptcp_rbs_type_get_name(right_type));
			left_value->free(left_value);
			right_value->free(right_value);
			return NULL;
		}

		left_value = (struct mptcp_rbs_value *) mptcp_rbs_value_and_new(
		    (struct mptcp_rbs_value_bool *) left_value,
		    (struct mptcp_rbs_value_bool *) right_value);
	}

	return left_value;
}

static struct mptcp_rbs_value *parse_value_allow_pop(struct parse_ctx *ctx,
						     int *value_position)
{
	struct mptcp_rbs_value *left_value;
	struct mptcp_rbs_value *right_value;
	enum mptcp_rbs_type_kind left_type;
	enum mptcp_rbs_type_kind right_type;
	int right_value_position;
	struct mptcp_rbs_token token;

	left_value = parse_value_and(ctx, value_position);
	if (!left_value)
		return NULL;

	while (true) {
		/* OR might follow */
		if (!lookahead_token(ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			left_value->free(left_value);
			return NULL;
		}
		if (token.kind != TOKEN_KIND_OR)
			break;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		right_value = parse_value_and(ctx, &right_value_position);
		if (!right_value) {
			left_value->free(left_value);
			return NULL;
		}

		left_type = mptcp_rbs_value_get_type(left_value->kind);
		right_type = mptcp_rbs_value_get_type(right_value->kind);

		if (left_type != TYPE_KIND_BOOL ||
		    right_type != TYPE_KIND_BOOL) {
			printk(
			    "%d: OR operator cannot be applied on %s and %s\n",
			    token.position, mptcp_rbs_type_get_name(left_type),
			    mptcp_rbs_type_get_name(right_type));
			left_value->free(left_value);
			right_value->free(right_value);
			return NULL;
		}

		left_value = (struct mptcp_rbs_value *) mptcp_rbs_value_or_new(
		    (struct mptcp_rbs_value_bool *) left_value,
		    (struct mptcp_rbs_value_bool *) right_value);
	}

	return left_value;
}

static struct mptcp_rbs_value *parse_value(struct parse_ctx *ctx,
					   int *value_position)
{
	struct mptcp_rbs_value *value;

	value = parse_value_allow_pop(ctx, value_position);
	if (value && value->kind == VALUE_KIND_SKBLIST_POP) {
		printk("%d: POP can only be used inside DROP or PUSH\n",
		       *value_position);
		value->free(value);
		return NULL;
	}

	return value;
}

static struct mptcp_rbs_value_bool *parse_value_bool(struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_BOOL) {
		printk("%d: Boolean value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_bool *) result;
}

static struct mptcp_rbs_value_int *parse_value_int(struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_INT) {
		printk("%d: Integer value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_int *) result;
}

static struct mptcp_rbs_value_string *parse_value_string(struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_STRING) {
		printk("%d: String value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_string *) result;
}

static struct mptcp_rbs_value_sbf *parse_value_sbf(struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_SBF) {
		printk("%d: Subflow value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_sbf *) result;
}

static struct mptcp_rbs_value_skb *parse_value_skb(struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_SKB) {
		printk("%d: Sockbuffer value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_skb *) result;
}

static struct mptcp_rbs_value_skb *parse_value_skb_allow_pop(
    struct parse_ctx *ctx)
{
	struct mptcp_rbs_value *result;
	enum mptcp_rbs_type_kind type;
	int value_position;

	result = parse_value_allow_pop(ctx, &value_position);
	if (!result)
		return NULL;

	type = mptcp_rbs_value_get_type(result->kind);

	if (type != TYPE_KIND_SKB) {
		printk("%d: Sockbuffer value expected but %s found\n",
		       value_position, mptcp_rbs_type_get_name(type));
		result->free(result);
		return NULL;
	}

	return (struct mptcp_rbs_value_skb *) result;
}

static bool parse_smt(struct parse_ctx *ctx, struct mptcp_rbs_cfg_block **block,
		      struct mptcp_rbs_smt **last_smt, bool *return_found);

static bool parse_smt_drop(struct parse_ctx *ctx,
			   struct mptcp_rbs_cfg_block **block,
			   struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_skb *value;
	struct mptcp_rbs_smt_drop *smt;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* SKB value must follow */
	value = parse_value_skb_allow_pop(ctx);
	if (!value)
		return false;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return false;
	}

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		value->free(value);
		return false;
	}

	smt = mptcp_rbs_smt_drop_new(value);
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) smt;
	*last_smt = (struct mptcp_rbs_smt *) smt;

	return true;
}

static bool parse_smts(struct parse_ctx *ctx,
		       struct mptcp_rbs_cfg_block **block, char *var_name,
		       int var_number, enum mptcp_rbs_type_kind var_type,
		       bool reinject, bool *return_found)
{
	bool result = true;
	struct var *var;
	struct var_list vars;
	struct mptcp_rbs_token token;
	struct mptcp_rbs_smt *last_smt = NULL;

	/* { must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_CURLY, &token))
		return false;

	INIT_VAR_LIST(&vars);
	PUSH_VAR_LIST(&ctx->var_stack, &vars);
	if (var_name) {
		var = var_new(var_name, var_number, var_type, &reinject, NULL);
		ADD_VAR(&vars, var);
	}

	while (true) {
		if (!parse_smt(ctx, block, &last_smt, return_found)) {
			result = false;
			break;
		}

		/* } might follow */
		if (!lookahead_token(ctx, &token)) {
			result = false;
			break;
		}
		if (token.kind == TOKEN_KIND_CLOSE_CURLY || *return_found) {
			/* } must have followed */
			if (!expect_token(ctx, TOKEN_KIND_CLOSE_CURLY, &token))
				result = false;
			break;
		}
	}

	POP_VAR_LIST(&ctx->var_stack);
	FOREACH_VAR(&vars, var, var_free(var));
	FREE_VAR_LIST(&vars);
	return result;
}

/*
 * FOREACH loops are translated into ifs and gotos as follows:
 *
 * FOREACH (VAR x IN y) {
 *   z;
 * }
 *
 * -->
 *
 * b0:
 *   VAR v1 = y;
 *   GOTO b1;
 *
 * b1:
 *   VAR x = v1.NEXT();
 *   if (x != NULL) GOTO b2 ELSE GOTO b3;
 *
 * b2:
 *   z;
 *   GOTO b1;
 *
 * b3:
 *   ...
 */
static bool parse_smt_foreach(struct parse_ctx *ctx,
			      struct mptcp_rbs_cfg_block **block,
			      struct mptcp_rbs_smt **last_smt,
			      bool *return_found)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_token ident_token;
	int value_position;
	struct mptcp_rbs_value *value;
	enum mptcp_rbs_type_kind type;
	int var_number;
	struct mptcp_rbs_smt_var *var_smt;
	struct mptcp_rbs_cfg_block *next_block;
	struct mptcp_rbs_cfg_block *last_block;
	enum mptcp_rbs_value_kind underlying_queue_kind;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* VAR must follow */
	if (!expect_token(ctx, TOKEN_KIND_VAR, &token))
		return false;

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &ident_token))
		return false;

	/* IN must follow */
	if (!expect_token(ctx, TOKEN_KIND_IN, &token))
		return false;

	/* Subflow or sockbuffer list must follow */
	value = parse_value(ctx, &value_position);
	if (!value)
		return false;
	underlying_queue_kind = ctx->underlying_queue_kind;

	type = mptcp_rbs_value_get_type(value->kind);
	if (type != TYPE_KIND_SBFLIST && type != TYPE_KIND_SKBLIST) {
		printk("%d: List value expected but %s found\n", value_position,
		       mptcp_rbs_type_get_name(type));
		value->free(value);
		return false;
	}

	/* Create VAR v1 = y; */
	var_number = ctx->var_index;
	var_smt = mptcp_rbs_smt_var_new(var_number, false, value);
	++ctx->var_index;
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) var_smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) var_smt;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token))
		return false;

	/* b1: */
	next_block = kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	(*block)->next = next_block;
	*block = next_block;

	/* VAR x = v1.NEXT(); */
	if (type == TYPE_KIND_SBFLIST) {
		struct mptcp_rbs_value_sbf_list_var *var_value =
		    mptcp_rbs_value_sbf_list_var_new(var_number);

		value = (struct mptcp_rbs_value *)
		    mptcp_rbs_value_sbf_list_next_new(
			(struct mptcp_rbs_value_sbf_list *) var_value);
	} else {
		struct mptcp_rbs_value_skb_list_var *var_value =
		    mptcp_rbs_value_skb_list_var_new(var_number,
						     underlying_queue_kind);

		value = (struct mptcp_rbs_value *)
		    mptcp_rbs_value_skb_list_next_new(
			(struct mptcp_rbs_value_skb_list *) var_value);
	}

	var_number = ctx->var_index;
	var_smt = mptcp_rbs_smt_var_new(var_number, false, value);
	++ctx->var_index;
	(*block)->first_smt = (struct mptcp_rbs_smt *) var_smt;

	/* if (x != NULL) GOTO b2 ELSE GOTO b3; */
	if (type == TYPE_KIND_SBFLIST) {
		value = (struct mptcp_rbs_value *) mptcp_rbs_value_sbf_var_new(
		    var_number);
		type = TYPE_KIND_SBF;
	} else {
		value = (struct mptcp_rbs_value *) mptcp_rbs_value_skb_var_new(
		    var_number, underlying_queue_kind == VALUE_KIND_RQ);
		type = TYPE_KIND_SKB;
	}

	(*block)->condition =
	    (struct mptcp_rbs_value_bool *) mptcp_rbs_value_is_not_null_new(
		value);

	/* b2: */
	next_block = kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	(*block)->next = next_block;

	/* Statements must follow */
	if (!parse_smts(ctx, &next_block, ident_token.string, var_number, type,
			underlying_queue_kind == VALUE_KIND_RQ, return_found))
		return false;

	/* b3: */
	last_block = kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	(*block)->next_else = last_block;

	if (*return_found) {
		/* GOTO b3; */
		next_block->next = last_block;
	} else {
		/* GOTO b1; */
		next_block->next = *block;
	}

	*block = last_block;
	*last_smt = NULL;
	return true;
}

static bool parse_smt_if(struct parse_ctx *ctx,
			 struct mptcp_rbs_cfg_block **block,
			 struct mptcp_rbs_smt **last_smt, bool *return_found)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_bool *value;
	struct mptcp_rbs_cfg_block *branch_block;
	struct mptcp_rbs_cfg_block *next_block = NULL;
	bool if_return_found;
	bool else_return_found = false;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* Boolean value must follow */
	value = parse_value_bool(ctx);
	if (!value)
		return false;
	(*block)->condition = value;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token))
		return false;

	branch_block = kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	(*block)->next = branch_block;

	/* Statements must follow */
	if (!parse_smts(ctx, &branch_block, NULL, 0, TYPE_KIND_NULL, false,
			&if_return_found))
		return false;

	if (!if_return_found) {
		next_block =
		    kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
		branch_block->next = next_block;
	}

	/* else might follow */
	if (!lookahead_token(ctx, &token))
		return false;

	if (token.kind == TOKEN_KIND_ELSE) {
		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		/* if might follow */
		if (!lookahead_token(ctx, &token))
			return false;

		branch_block =
		    kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
		(*block)->next_else = branch_block;

		if (token.kind == TOKEN_KIND_IF) {
			if (!parse_smt_if(ctx, &branch_block, last_smt,
					  &else_return_found))
				return false;
		} else {
			/* Statements must follow */
			if (!parse_smts(ctx, &branch_block, NULL, 0,
					TYPE_KIND_NULL, false,
					&else_return_found))
				return false;
		}

		if (!else_return_found) {
			if (!next_block)
				next_block =
				    kzalloc(sizeof(struct mptcp_rbs_cfg_block),
					    GFP_KERNEL);
			branch_block->next = next_block;
		}
	} else {
		if (!next_block)
			next_block = kzalloc(sizeof(struct mptcp_rbs_cfg_block),
					     GFP_KERNEL);

		(*block)->next_else = next_block;
	}

	*block = next_block;
	*last_smt = NULL;
	*return_found = if_return_found && else_return_found;
	return true;
}

static bool parse_smt_print(struct parse_ctx *ctx,
			    struct mptcp_rbs_cfg_block **block,
			    struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value_string *value;
	struct mptcp_rbs_value *arg_value = NULL;
	struct mptcp_rbs_smt_print *smt;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* String value must follow */
	value = parse_value_string(ctx);
	if (!value)
		return false;

	/* , might follow */
	if (!lookahead_token(ctx, &token)) {
		value->free(value);
		return false;
	}

	if (token.kind == TOKEN_KIND_COMMA) {
		int dummy1;
		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		/* Value must follow */
		arg_value = parse_value(ctx, &dummy1);
		if (!arg_value) {
			value->free(value);
			return false;
		}
	}

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		if (arg_value)
			arg_value->free(arg_value);
		return false;
	}

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		value->free(value);
		if (arg_value)
			arg_value->free(arg_value);
		return false;
	}

	smt = mptcp_rbs_smt_print_new(value, arg_value);
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) smt;
	*last_smt = (struct mptcp_rbs_smt *) smt;

	return true;
}

static bool parse_smt_return(struct parse_ctx *ctx,
			     struct mptcp_rbs_cfg_block **block)
{
	struct mptcp_rbs_token token;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token))
		return false;

	/* Do nothing because the next pointer of the block is
	 * already set to NULL
	 */
	return true;
}

static bool parse_smt_set(struct parse_ctx *ctx,
			  struct mptcp_rbs_cfg_block **block,
			  struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	int reg_number;
	struct mptcp_rbs_value_int *value;
	struct mptcp_rbs_smt_set *smt;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* R1 - R6 must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &token))
		return false;
	if (strlen(token.string) != 2 || token.string[0] != 'R' ||
	    token.string[1] < '1' ||
	    token.string[1] > ('0' + MPTCP_RBS_REG_COUNT)) {
		printk("%d: Register name %s is invalid\n", token.position,
		       token.string);
		return false;
	}
	reg_number = token.string[1] - '1';

	/* , must follow */
	if (!expect_token(ctx, TOKEN_KIND_COMMA, &token))
		return false;

	/* Integer value must follow */
	value = parse_value_int(ctx);
	if (!value)
		return false;

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		value->free(value);
		return false;
	}

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		value->free(value);
		return false;
	}

	smt = mptcp_rbs_smt_set_new(reg_number, value);
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) smt;
	*last_smt = (struct mptcp_rbs_smt *) smt;

	return true;
}

static bool parse_smt_var(struct parse_ctx *ctx,
			  struct mptcp_rbs_cfg_block **block,
			  struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	struct var_list *vars;
	struct var *var;
	struct mptcp_rbs_value *value;
	int dummy1;
	struct mptcp_rbs_smt_var *smt;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* Identifier must follow */
	if (!expect_token(ctx, TOKEN_KIND_IDENT, &token))
		return false;

	/* Check if identifier is already used */
	vars = GET_VAR_LIST_STACK_TOP(&ctx->var_stack);
	FOREACH_VAR(vars, var, if (!strcmp(token.string, var->name)) {
		printk("%d: Variable %s is already declared\n", token.position,
		       token.string);
		return false;
	});

	var = var_new(token.string, ctx->var_index, TYPE_KIND_NULL, NULL, NULL);
	ADD_VAR(vars, var);
	++ctx->var_index;

	/* = must follow */
	if (!expect_token(ctx, TOKEN_KIND_ASSIGN, &token))
		return false;

	/* Value must follow */
	value = parse_value(ctx, &dummy1);
	if (!value)
		return false;

	var->type = mptcp_rbs_value_get_type(value->kind);
	if (var->type == TYPE_KIND_SKB)
		var->reinject =
		    ((struct mptcp_rbs_value_skb *) value)->reinject;
	else if (var->type == TYPE_KIND_SKBLIST)
		var->underlying_queue_kind = ctx->underlying_queue_kind;

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		value->free(value);
		return false;
	}

	smt = mptcp_rbs_smt_var_new(var->var_number, false, value);
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) smt;
	*last_smt = (struct mptcp_rbs_smt *) smt;

	return true;
}

static bool parse_smt_void(struct parse_ctx *ctx,
			   struct mptcp_rbs_cfg_block **block,
			   struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	struct mptcp_rbs_value *value = NULL;
	int dummy1;
	struct mptcp_rbs_smt_void *smt;

	mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
				 &ctx->line_position, &token);

	/* ( must follow */
	if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token))
		return false;

	/* Value might follow */
	if (!lookahead_token(ctx, &token))
		return false;
	if (token.kind != TOKEN_KIND_CLOSE_BRACKET) {
		value = parse_value(ctx, &dummy1);
		if (!value)
			return false;
	}

	/* ) must follow */
	if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
		if (value)
			value->free(value);
		return false;
	}

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		if (value)
			value->free(value);
		return false;
	}

	smt = mptcp_rbs_smt_void_new(value);
	if (*last_smt)
		(*last_smt)->next = (struct mptcp_rbs_smt *) smt;
	else
		(*block)->first_smt = (struct mptcp_rbs_smt *) smt;
	*last_smt = (struct mptcp_rbs_smt *) smt;

	return true;
}

static bool parse_smt_other(struct parse_ctx *ctx,
			    struct mptcp_rbs_cfg_block **block,
			    struct mptcp_rbs_smt **last_smt)
{
	struct mptcp_rbs_token token;
	int value_position;
	struct mptcp_rbs_value *value = parse_value(ctx, &value_position);
	struct mptcp_rbs_smt *smt;

	if (!value)
		return false;

	/* PUSH might follow. In this case the previous . was
	 * already parsed
	 */
	if (!lookahead_token(ctx, &token)) {
		value->free(value);
		return false;
	}
    
	if (token.kind == TOKEN_KIND_PUSH) {
		struct mptcp_rbs_value_skb *skb_value;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		/* ( must follow */
		if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token)) {
			value->free(value);
			return false;
		}

		/* SKB value must follow */
		skb_value = parse_value_skb_allow_pop(ctx);
		if (!skb_value) {
			value->free(value);
			return false;
		}

		/* ) must follow */
		if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
			value->free(value);
			skb_value->free(skb_value);
			return false;
		}

		smt = (struct mptcp_rbs_smt *) mptcp_rbs_smt_push_new(
		    (struct mptcp_rbs_value_sbf *) value, skb_value);
    } else if (token.kind == TOKEN_KIND_SET_USER) {
		struct mptcp_rbs_value_int *int_value;

		mptcp_rbs_get_next_token(&ctx->str, &ctx->position, &ctx->line,
					 &ctx->line_position, &token);

		/* ( must follow */
		if (!expect_token(ctx, TOKEN_KIND_OPEN_BRACKET, &token)) {
			value->free(value);
			return false;
		}

        /* Integer value must follow */
        int_value = parse_value_int(ctx);
		if (!int_value) {
			value->free(value);
			return false;
		}

		/* ) must follow */
		if (!expect_token(ctx, TOKEN_KIND_CLOSE_BRACKET, &token)) {
			value->free(value);
			int_value->free(int_value);
			return false;
		}

		smt = (struct mptcp_rbs_smt *) mptcp_rbs_smt_set_user_new(
		    (struct mptcp_rbs_value_sbf *) value, int_value);
	} else {
		printk("%d: Values cannot stand alone\n", value_position);
		value->free(value);
		return false;
	}

	/* ; must follow */
	if (!expect_token(ctx, TOKEN_KIND_SEMICOLON, &token)) {
		smt->free(smt);
		return false;
	}

	if (*last_smt)
		(*last_smt)->next = smt;
	else
		(*block)->first_smt = smt;
	*last_smt = smt;

	return true;
}

static bool parse_smt(struct parse_ctx *ctx, struct mptcp_rbs_cfg_block **block,
		      struct mptcp_rbs_smt **last_smt, bool *return_found)
{
	struct mptcp_rbs_token token;

	if (!lookahead_token(ctx, &token))
		return false;

	switch (token.kind) {
	case TOKEN_KIND_DROP: {
		*return_found = false;
		return parse_smt_drop(ctx, block, last_smt);
	}
	case TOKEN_KIND_FOREACH:
		return parse_smt_foreach(ctx, block, last_smt, return_found);
	case TOKEN_KIND_IF:
		return parse_smt_if(ctx, block, last_smt, return_found);
	case TOKEN_KIND_PRINT: {
		*return_found = false;
		return parse_smt_print(ctx, block, last_smt);
	}
	case TOKEN_KIND_RETURN: {
		*return_found = true;
		return parse_smt_return(ctx, block);
	}
	case TOKEN_KIND_SET: {
		*return_found = false;
		return parse_smt_set(ctx, block, last_smt);
	}
	case TOKEN_KIND_VAR: {
		*return_found = false;
		return parse_smt_var(ctx, block, last_smt);
	}
#ifdef MPTCP_RBS_MEASURE
	case TOKEN_KIND_VOID: {
		*return_found = false;
		return parse_smt_void(ctx, block, last_smt);
	}
#endif
	default: {
		*return_found = false;
		return parse_smt_other(ctx, block, last_smt);
	}
	}
}

struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_parse(const char *str)
{
	struct mptcp_rbs_scheduler *scheduler =
	    kzalloc(sizeof(struct mptcp_rbs_scheduler), GFP_KERNEL);
	struct mptcp_rbs_cfg_block *block =
	    kzalloc(sizeof(struct mptcp_rbs_cfg_block), GFP_KERNEL);
	struct mptcp_rbs_smt *last_smt = NULL;
	struct mptcp_rbs_token token;
	struct var *var;
	struct var_list vars;
	struct parse_ctx ctx;
	ctx.str = str;
	ctx.position = 0;
	ctx.line = 0;
	ctx.line_position = 0;
	ctx.var_index = 0;
	scheduler->variations[0].first_block = block;

	/* SCHEDULER must follow */
	if (!expect_token(&ctx, TOKEN_KIND_SCHEDULER, &token)) {
		mptcp_rbs_scheduler_free(scheduler);
		return NULL;
	}

	/* Identifier must follow */
	if (!expect_token(&ctx, TOKEN_KIND_IDENT, &token)) {
		mptcp_rbs_scheduler_free(scheduler);
		return NULL;
	}
	scheduler->name = strclone(token.string);
	/* ; must follow */
	if (!expect_token(&ctx, TOKEN_KIND_SEMICOLON, &token)) {
		mptcp_rbs_scheduler_free(scheduler);
		return NULL;
	}

	INIT_REPL_STACK(&ctx.repls);
	INIT_VAR_LIST(&vars);
	INIT_VAR_LIST_STACK(&ctx.var_stack);
	PUSH_VAR_LIST(&ctx.var_stack, &vars);

	while (true) {
		bool return_found;
		/* Check if end is found */
		if (!lookahead_token(&ctx, &token)) {
			printk("%s\n", mptcp_rbs_get_last_error());
			mptcp_rbs_scheduler_free(scheduler);
			scheduler = NULL;
			break;
		}
		if (token.kind == TOKEN_KIND_EOD)
			break;

		/* Statement must follow */
		if (!parse_smt(&ctx, &block, &last_smt, &return_found)) {
			mptcp_rbs_scheduler_free(scheduler);
			scheduler = NULL;
			break;
		}

		if (return_found) {
			/* End found */
			if (!expect_token(&ctx, TOKEN_KIND_EOD, &token)) {
				mptcp_rbs_scheduler_free(scheduler);
				scheduler = NULL;
			}
			break;
		}
	}

	FREE_REPL_STACK(&ctx.repls);
	FOREACH_VAR(&vars, var, var_free(var));
	FREE_VAR_LIST(&vars);
	FREE_VAR_LIST_STACK(&ctx.var_stack);

	if (scheduler) {
		scheduler->variations[0].used_vars = ctx.var_index;
		if (ctx.var_index > MPTCP_RBS_MAX_VAR_COUNT) {
			printk("Scheduler cannot be parsed because too many "
			       "variables are used\n");
			mptcp_rbs_scheduler_free(scheduler);
			scheduler = NULL;
		}
	}

	return scheduler;
}
