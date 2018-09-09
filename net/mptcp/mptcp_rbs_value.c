#include "mptcp_rbs_value.h"
#include "mptcp_rbs_ctx.h"
#include "mptcp_rbs_lexer.h"
#include "mptcp_rbs_parser.h"
#include "mptcp_rbs_queue.h"
#include "mptcp_rbs_sched.h"
#include <linux/slab.h>

/* Macro to clone values */
#define APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                       \
	case ENUM: {                                                           \
		return (struct mptcp_rbs_value *) STRUCT##_clone(              \
		    ctx, (const struct STRUCT *) value);                       \
	}

/* Macro to print values */
#define APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)                       \
	case ENUM: {                                                           \
		return STRUCT##_print((const struct STRUCT *) value, buffer);  \
	}

/* Macro to get the type of a value */
#define APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)                    \
	case ENUM:                                                             \
		return RETURNTYPE;

/* Context only for cloning. This is necessary since we cannot simply copy
 * sbf/skb progress references to filters. Instead we have to replace the
 * pointer. Note that we assume that no more than MAX_NESTING filters are nested
 */
struct mptcp_rbs_value_clone_ctx {
#define MAX_NESTING 10
	struct {
		const void *repl;
		void *repl_with;
	} repls[MAX_NESTING];
	void *user_ctx;
	mptcp_rbs_value_clone_user_func user_func;
};

struct mptcp_rbs_value *mptcp_rbs_value_clone_ex(
    struct mptcp_rbs_value_clone_ctx *ctx, const struct mptcp_rbs_value *value);

#define CLONE(val)                                                             \
	val = (typeof(val)) mptcp_rbs_value_clone_ex(                          \
	    ctx, (struct mptcp_rbs_value *) val)

struct mptcp_rbs_value_constint *mptcp_rbs_value_constint_new(unsigned int num)
{
	struct mptcp_rbs_value_constint *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_constint), GFP_KERNEL);
	value->kind = VALUE_KIND_CONSTINT;
	value->free = &mptcp_rbs_value_constint_free;
	value->execute = &mptcp_rbs_value_constint_execute;
	value->value = num;

	return value;
}

void mptcp_rbs_value_constint_free(struct mptcp_rbs_value_constint *self)
{
	kfree(self);
}

s64 mptcp_rbs_value_constint_execute(struct mptcp_rbs_value_constint *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	return self->value;
}

struct mptcp_rbs_value_constint *mptcp_rbs_value_constint_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_constint *value)
{
	struct mptcp_rbs_value_constint *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_constint), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_constint_print(const struct mptcp_rbs_value_constint *value,
				   char *buffer)
{
	return sprintf_null(&buffer, "%u", value->value);
}

struct mptcp_rbs_value_conststring *mptcp_rbs_value_conststring_new(char *str)
{
	struct mptcp_rbs_value_conststring *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_conststring), GFP_KERNEL);
	value->kind = VALUE_KIND_CONSTSTRING;
	value->free = &mptcp_rbs_value_conststring_free;
	value->execute = &mptcp_rbs_value_conststring_execute;
	value->value = str;

	return value;
}

void mptcp_rbs_value_conststring_free(struct mptcp_rbs_value_conststring *self)
{
	kfree(self->value);
	kfree(self);
}

char *mptcp_rbs_value_conststring_execute(
    struct mptcp_rbs_value_conststring *self, struct mptcp_rbs_eval_ctx *ctx)
{
	return self->value;
}

struct mptcp_rbs_value_conststring *mptcp_rbs_value_conststring_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_conststring *value)
{
	struct mptcp_rbs_value_conststring *clone;
	int len;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_conststring), GFP_KERNEL);
	*clone = *value;
	len = strlen(value->value);
	clone->value = kmalloc(len + 1, GFP_KERNEL);
	memcpy(clone->value, value->value, len + 1);

	return clone;
}

int mptcp_rbs_value_conststring_print(
    const struct mptcp_rbs_value_conststring *value, char *buffer)
{
	int len = 0;
	char *str;

	len = replace_with_escape_chars(value->value, false);
	if (!buffer)
		return len + 2;

	str = kmalloc(len + 1, GFP_KERNEL);
	memcpy(str, value->value, strlen(value->value) + 1);
	replace_with_escape_chars(str, true);
	len = sprintf_null(&buffer, "\"%s\"", str);
	kfree(str);
	return len;
}

struct mptcp_rbs_value_null *mptcp_rbs_value_null_new(void)
{
	struct mptcp_rbs_value_null *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_null), GFP_KERNEL);
	value->kind = VALUE_KIND_NULL;
	value->free = &mptcp_rbs_value_null_free;
	value->execute = &mptcp_rbs_value_null_execute;

	return value;
}

void mptcp_rbs_value_null_free(struct mptcp_rbs_value_null *self)
{
	kfree(self);
}

s32 mptcp_rbs_value_null_execute(struct mptcp_rbs_value_null *self,
				 struct mptcp_rbs_eval_ctx *ctx)
{
	return -1;
}

struct mptcp_rbs_value_null *mptcp_rbs_value_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_null *value)
{
	struct mptcp_rbs_value_null *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_null), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_null_print(const struct mptcp_rbs_value_null *value,
			       char *buffer)
{
	return sprintf_null(&buffer, "NULL");
}

struct mptcp_rbs_value_bool_var *mptcp_rbs_value_bool_var_new(int var_number)
{
	struct mptcp_rbs_value_bool_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_bool_var), GFP_KERNEL);
	value->kind = VALUE_KIND_BOOL_VAR;
	value->free = mptcp_rbs_value_bool_var_free;
	value->execute = mptcp_rbs_value_bool_var_execute;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_bool_var_free(struct mptcp_rbs_value_bool_var *self)
{
	kfree(self);
}

s32 mptcp_rbs_value_bool_var_execute(struct mptcp_rbs_value_bool_var *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];

	if (var->is_lazy) {
		struct mptcp_rbs_value_bool *value =
		    (struct mptcp_rbs_value_bool *) var->lazy_value;
		var->bool_value = value->execute(value, ctx);
		var->is_lazy = false;
	}

	return var->bool_value;
}

struct mptcp_rbs_value_bool_var *mptcp_rbs_value_bool_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_bool_var *value)
{
	struct mptcp_rbs_value_bool_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_bool_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_bool_var_print(const struct mptcp_rbs_value_bool_var *value,
				   char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_int_var *mptcp_rbs_value_int_var_new(int var_number)
{
	struct mptcp_rbs_value_int_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_int_var), GFP_KERNEL);
	value->kind = VALUE_KIND_INT_VAR;
	value->free = mptcp_rbs_value_int_var_free;
	value->execute = mptcp_rbs_value_int_var_execute;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_int_var_free(struct mptcp_rbs_value_int_var *self)
{
	kfree(self);
}

s64 mptcp_rbs_value_int_var_execute(struct mptcp_rbs_value_int_var *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];

	if (var->is_lazy) {
		struct mptcp_rbs_value_int *value =
		    (struct mptcp_rbs_value_int *) var->lazy_value;
		var->int_value = value->execute(value, ctx);
		var->is_lazy = false;
	}

	return var->int_value;
}

struct mptcp_rbs_value_int_var *mptcp_rbs_value_int_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_int_var *value)
{
	struct mptcp_rbs_value_int_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_int_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_int_var_print(const struct mptcp_rbs_value_int_var *value,
				  char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_string_var *mptcp_rbs_value_string_var_new(
    int var_number)
{
	struct mptcp_rbs_value_string_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_string_var), GFP_KERNEL);
	value->kind = VALUE_KIND_STRING_VAR;
	value->free = mptcp_rbs_value_string_var_free;
	value->execute = mptcp_rbs_value_string_var_execute;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_string_var_free(struct mptcp_rbs_value_string_var *self)
{
	kfree(self);
}

char *mptcp_rbs_value_string_var_execute(
    struct mptcp_rbs_value_string_var *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];

	if (var->is_lazy) {
		struct mptcp_rbs_value_string *value =
		    (struct mptcp_rbs_value_string *) var->lazy_value;
		var->string_value = value->execute(value, ctx);
		var->is_lazy = false;
	}

	return var->string_value;
}

struct mptcp_rbs_value_string_var *mptcp_rbs_value_string_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_string_var *value)
{
	struct mptcp_rbs_value_string_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_string_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_string_var_print(
    const struct mptcp_rbs_value_string_var *value, char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_sbf_var *mptcp_rbs_value_sbf_var_new(int var_number)
{
	struct mptcp_rbs_value_sbf_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_var), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_VAR;
	value->free = mptcp_rbs_value_sbf_var_free;
	value->execute = mptcp_rbs_value_sbf_var_execute;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_sbf_var_free(struct mptcp_rbs_value_sbf_var *self)
{
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_var_execute(
    struct mptcp_rbs_value_sbf_var *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];

	if (var->is_lazy) {
		struct mptcp_rbs_value_sbf *value =
		    (struct mptcp_rbs_value_sbf *) var->lazy_value;
		var->sbf_value = value->execute(value, ctx);
		var->is_lazy = false;
	}

	return var->sbf_value;
}

struct mptcp_rbs_value_sbf_var *mptcp_rbs_value_sbf_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_var *value)
{
	struct mptcp_rbs_value_sbf_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_sbf_var_print(const struct mptcp_rbs_value_sbf_var *value,
				  char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_sbf_list_var *mptcp_rbs_value_sbf_list_var_new(
    int var_number)
{
	struct mptcp_rbs_value_sbf_list_var *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_var), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_VAR;
	value->free = mptcp_rbs_value_sbf_list_var_free;
	value->execute = mptcp_rbs_value_sbf_list_var_execute;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_sbf_list_var_free(
    struct mptcp_rbs_value_sbf_list_var *self)
{
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_var_execute(
    struct mptcp_rbs_value_sbf_list_var *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];
	struct tcp_sock **entry;

    mptcp_debug("%s self %p *prev %p var->is_lazy %u coming from %pS for meta_sk %p\n", __func__, self, *prev, var->is_lazy, __builtin_return_address(0), ctx->mpcb->meta_sk);

	if (var->is_lazy) {
		struct mptcp_rbs_value_sbf_list *value =
		    (struct mptcp_rbs_value_sbf_list *) var->lazy_value;
		return value->execute(value, ctx, prev, is_null);
	}

	if (!var->sbf_list_value) {
		*is_null = true;
		return NULL;
	}
	*is_null = false;

	if (*prev)
		entry = ((struct tcp_sock **) *prev) + 1;
	else
		entry = var->sbf_list_value;

	if (*entry)
		*prev = entry;

    mptcp_debug("%s returns %p with is at %p\n", __func__, *entry, entry);

	return *entry;
}

struct mptcp_rbs_value_sbf_list_var *mptcp_rbs_value_sbf_list_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_var *value)
{
	struct mptcp_rbs_value_sbf_list_var *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_sbf_list_var_print(
    const struct mptcp_rbs_value_sbf_list_var *value, char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_skb_var *mptcp_rbs_value_skb_var_new(int var_number,
							    bool reinject)
{
	struct mptcp_rbs_value_skb_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_var), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_VAR;
	value->free = mptcp_rbs_value_skb_var_free;
	value->execute = mptcp_rbs_value_skb_var_execute;
	value->reinject = reinject;
	value->var_number = var_number;

	return value;
}

void mptcp_rbs_value_skb_var_free(struct mptcp_rbs_value_skb_var *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_var_execute(
    struct mptcp_rbs_value_skb_var *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];

	if (var->is_lazy) {
		struct mptcp_rbs_value_skb *value =
		    (struct mptcp_rbs_value_skb *) var->lazy_value;
		var->skb_value = value->execute(value, ctx);
		var->is_lazy = false;
	}

	return var->skb_value;
}

struct mptcp_rbs_value_skb_var *mptcp_rbs_value_skb_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_var *value)
{
	struct mptcp_rbs_value_skb_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_skb_var_print(const struct mptcp_rbs_value_skb_var *value,
				  char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_skb_list_var *mptcp_rbs_value_skb_list_var_new(
    int var_number, enum mptcp_rbs_value_kind underlying_queue_kind)
{
	struct mptcp_rbs_value_skb_list_var *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_var), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_VAR;
	value->free = mptcp_rbs_value_skb_list_var_free;
	value->execute = mptcp_rbs_value_skb_list_var_execute;
	value->var_number = var_number;
	value->underlying_queue_kind = underlying_queue_kind;

	return value;
}

void mptcp_rbs_value_skb_list_var_free(
    struct mptcp_rbs_value_skb_list_var *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_var_execute(
    struct mptcp_rbs_value_skb_list_var *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null)
{
	struct mptcp_rbs_var *var = &ctx->vars[self->var_number];
	struct sk_buff **entry;

	if (var->is_lazy) {
		struct mptcp_rbs_value_skb_list *value =
		    (struct mptcp_rbs_value_skb_list *) var->lazy_value;
		return value->execute(value, ctx, prev, is_null);
	}

	if (!var->skb_list_value) {
		*is_null = true;
		return NULL;
	}
	*is_null = false;

	if (*prev)
		entry = ((struct sk_buff **) *prev) + 1;
	else
		entry = var->skb_list_value;

	if (*entry)
		*prev = entry;

	return *entry;
}

struct mptcp_rbs_value_skb_list_var *mptcp_rbs_value_skb_list_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_var *value)
{
	struct mptcp_rbs_value_skb_list_var *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_var), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_skb_list_var_print(
    const struct mptcp_rbs_value_skb_list_var *value, char *buffer)
{
	return sprintf_null(&buffer, "v%d", value->var_number + 1);
}

struct mptcp_rbs_value_not *mptcp_rbs_value_not_new(
    struct mptcp_rbs_value_bool *operand)
{
	struct mptcp_rbs_value_not *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_not), GFP_KERNEL);
	value->kind = VALUE_KIND_NOT;
	value->free = &mptcp_rbs_value_not_free;
	value->execute = &mptcp_rbs_value_not_execute;
	value->operand = operand;

	return value;
}

void mptcp_rbs_value_not_free(struct mptcp_rbs_value_not *self)
{
	MPTCP_RBS_VALUE_FREE(self->operand);
	kfree(self);
}

s32 mptcp_rbs_value_not_execute(struct mptcp_rbs_value_not *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	s32 b = self->operand->execute(self->operand, ctx);

	if (b == 0)
		return 1;
	if (b == -1)
		return -1;
	return 0;
}

struct mptcp_rbs_value_not *mptcp_rbs_value_not_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_not *value)
{
	struct mptcp_rbs_value_not *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_not), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->operand);

	return clone;
}

int mptcp_rbs_value_not_print(const struct mptcp_rbs_value_not *value,
			      char *buffer)
{
	int len = sprintf_null(&buffer, "!");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;
	return len;
}

struct mptcp_rbs_value_equal *mptcp_rbs_value_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_equal *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_equal), GFP_KERNEL);
	value->kind = VALUE_KIND_EQUAL;
	value->free = &mptcp_rbs_value_equal_free;
	value->execute = &mptcp_rbs_value_equal_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_equal_free(struct mptcp_rbs_value_equal *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_equal_execute(struct mptcp_rbs_value_equal *self,
				  struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == right)
		return 1;
	return 0;
}

struct mptcp_rbs_value_equal *mptcp_rbs_value_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_equal *value)
{
	struct mptcp_rbs_value_equal *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_equal), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_equal_print(const struct mptcp_rbs_value_equal *value,
				char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " == ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_unequal *mptcp_rbs_value_unequal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_unequal *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_unequal), GFP_KERNEL);
	value->kind = VALUE_KIND_UNEQUAL;
	value->free = &mptcp_rbs_value_unequal_free;
	value->execute = &mptcp_rbs_value_unequal_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_unequal_free(struct mptcp_rbs_value_unequal *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_unequal_execute(struct mptcp_rbs_value_unequal *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == right)
		return 0;
	return 1;
}

struct mptcp_rbs_value_unequal *mptcp_rbs_value_unequal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_unequal *value)
{
	struct mptcp_rbs_value_unequal *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_unequal), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_unequal_print(const struct mptcp_rbs_value_unequal *value,
				  char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " != ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_less *mptcp_rbs_value_less_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_less *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_less), GFP_KERNEL);
	value->kind = VALUE_KIND_LESS;
	value->free = &mptcp_rbs_value_less_free;
	value->execute = &mptcp_rbs_value_less_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_less_free(struct mptcp_rbs_value_less *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_less_execute(struct mptcp_rbs_value_less *self,
				 struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == -1 || right == -1)
		return -1;
	if (left < right)
		return 1;
	return 0;
}

struct mptcp_rbs_value_less *mptcp_rbs_value_less_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_less *value)
{
	struct mptcp_rbs_value_less *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_less), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_less_print(const struct mptcp_rbs_value_less *value,
			       char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " < ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_less_equal *mptcp_rbs_value_less_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_less_equal *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_less_equal), GFP_KERNEL);
	value->kind = VALUE_KIND_LESS_EQUAL;
	value->free = &mptcp_rbs_value_less_equal_free;
	value->execute = &mptcp_rbs_value_less_equal_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_less_equal_free(struct mptcp_rbs_value_less_equal *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_less_equal_execute(struct mptcp_rbs_value_less_equal *self,
				       struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == -1 || right == -1)
		return -1;
	if (left <= right)
		return 1;
	return 0;
}

struct mptcp_rbs_value_less_equal *mptcp_rbs_value_less_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_less_equal *value)
{
	struct mptcp_rbs_value_less_equal *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_less_equal), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_less_equal_print(
    const struct mptcp_rbs_value_less_equal *value, char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " <= ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_greater *mptcp_rbs_value_greater_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_greater *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_greater), GFP_KERNEL);
	value->kind = VALUE_KIND_GREATER;
	value->free = &mptcp_rbs_value_greater_free;
	value->execute = &mptcp_rbs_value_greater_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_greater_free(struct mptcp_rbs_value_greater *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_greater_execute(struct mptcp_rbs_value_greater *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == -1 || right == -1)
		return -1;
	if (left > right)
		return 1;
	return 0;
}

struct mptcp_rbs_value_greater *mptcp_rbs_value_greater_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_greater *value)
{
	struct mptcp_rbs_value_greater *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_greater), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_greater_print(const struct mptcp_rbs_value_greater *value,
				  char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " > ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_greater_equal *mptcp_rbs_value_greater_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_greater_equal *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_greater_equal), GFP_KERNEL);
	value->kind = VALUE_KIND_GREATER_EQUAL;
	value->free = &mptcp_rbs_value_greater_equal_free;
	value->execute = &mptcp_rbs_value_greater_equal_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_greater_equal_free(
    struct mptcp_rbs_value_greater_equal *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_greater_equal_execute(
    struct mptcp_rbs_value_greater_equal *self, struct mptcp_rbs_eval_ctx *ctx)
{
	s64 left = self->left_operand->execute(self->left_operand, ctx);
	s64 right = self->right_operand->execute(self->right_operand, ctx);

	if (left == -1 || right == -1)
		return -1;
	if (left >= right)
		return 1;
	return 0;
}

struct mptcp_rbs_value_greater_equal *mptcp_rbs_value_greater_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_greater_equal *value)
{
	struct mptcp_rbs_value_greater_equal *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_greater_equal), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_greater_equal_print(
    const struct mptcp_rbs_value_greater_equal *value, char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " >= ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_and *mptcp_rbs_value_and_new(
    struct mptcp_rbs_value_bool *left_operand,
    struct mptcp_rbs_value_bool *right_operand)
{
	struct mptcp_rbs_value_and *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_and), GFP_KERNEL);
	value->kind = VALUE_KIND_AND;
	value->free = &mptcp_rbs_value_and_free;
	value->execute = &mptcp_rbs_value_and_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_and_free(struct mptcp_rbs_value_and *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_and_execute(struct mptcp_rbs_value_and *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	s32 val = self->left_operand->execute(self->left_operand, ctx);
	if (val <= 0)
		return 0;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val <= 0)
		return 0;

	return 1;
}

struct mptcp_rbs_value_and *mptcp_rbs_value_and_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_and *value)
{
	struct mptcp_rbs_value_and *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_and), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_and_print(const struct mptcp_rbs_value_and *value,
			      char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " AND ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_or *mptcp_rbs_value_or_new(
    struct mptcp_rbs_value_bool *left_operand,
    struct mptcp_rbs_value_bool *right_operand)
{
	struct mptcp_rbs_value_or *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_or), GFP_KERNEL);
	value->kind = VALUE_KIND_OR;
	value->free = &mptcp_rbs_value_or_free;
	value->execute = &mptcp_rbs_value_or_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_or_free(struct mptcp_rbs_value_or *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s32 mptcp_rbs_value_or_execute(struct mptcp_rbs_value_or *self,
			       struct mptcp_rbs_eval_ctx *ctx)
{
	s32 val = self->left_operand->execute(self->left_operand, ctx);
	if (val == 1)
		return 1;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == 1)
		return 1;

	return 0;
}

struct mptcp_rbs_value_or *mptcp_rbs_value_or_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_or *value)
{
	struct mptcp_rbs_value_or *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_or), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_or_print(const struct mptcp_rbs_value_or *value,
			     char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " OR ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_add *mptcp_rbs_value_add_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_add *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_add), GFP_KERNEL);
	value->kind = VALUE_KIND_ADD;
	value->free = &mptcp_rbs_value_add_free;
	value->execute = &mptcp_rbs_value_add_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_add_free(struct mptcp_rbs_value_add *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s64 mptcp_rbs_value_add_execute(struct mptcp_rbs_value_add *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->left_operand->execute(self->left_operand, ctx);
	unsigned int result;

	if (val == -1)
		return -1;
	result = val;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == -1)
		return -1;
	result += val;

	return result;
}

struct mptcp_rbs_value_add *mptcp_rbs_value_add_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_add *value)
{
	struct mptcp_rbs_value_add *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_add), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_add_print(const struct mptcp_rbs_value_add *value,
			      char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " + ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_subtract *mptcp_rbs_value_subtract_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_subtract *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_subtract), GFP_KERNEL);
	value->kind = VALUE_KIND_SUBTRACT;
	value->free = &mptcp_rbs_value_subtract_free;
	value->execute = &mptcp_rbs_value_subtract_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_subtract_free(struct mptcp_rbs_value_subtract *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s64 mptcp_rbs_value_subtract_execute(struct mptcp_rbs_value_subtract *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->left_operand->execute(self->left_operand, ctx);
	unsigned int result;

	if (val == -1)
		return -1;
	result = val;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == -1)
		return -1;
	result -= val;

	return result;
}

struct mptcp_rbs_value_subtract *mptcp_rbs_value_subtract_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_subtract *value)
{
	struct mptcp_rbs_value_subtract *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_subtract), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_subtract_print(const struct mptcp_rbs_value_subtract *value,
				   char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " - ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_multiply *mptcp_rbs_value_multiply_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_multiply *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_multiply), GFP_KERNEL);
	value->kind = VALUE_KIND_MULTIPLY;
	value->free = &mptcp_rbs_value_multiply_free;
	value->execute = &mptcp_rbs_value_multiply_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_multiply_free(struct mptcp_rbs_value_multiply *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s64 mptcp_rbs_value_multiply_execute(struct mptcp_rbs_value_multiply *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->left_operand->execute(self->left_operand, ctx);
	unsigned int result;

	if (val == -1)
		return -1;
	result = val;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == -1)
		return -1;
	result *= val;

	return result;
}

struct mptcp_rbs_value_multiply *mptcp_rbs_value_multiply_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_multiply *value)
{
	struct mptcp_rbs_value_multiply *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_multiply), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_multiply_print(const struct mptcp_rbs_value_multiply *value,
				   char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " * ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_divide *mptcp_rbs_value_divide_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_divide *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_divide), GFP_KERNEL);
	value->kind = VALUE_KIND_DIVIDE;
	value->free = &mptcp_rbs_value_divide_free;
	value->execute = &mptcp_rbs_value_divide_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_divide_free(struct mptcp_rbs_value_divide *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s64 mptcp_rbs_value_divide_execute(struct mptcp_rbs_value_divide *self,
				   struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->left_operand->execute(self->left_operand, ctx);
	unsigned int result;

	if (val == -1)
		return -1;
	result = val;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == -1 || !val)
		return -1;
	result /= val;

	return result;
}

struct mptcp_rbs_value_divide *mptcp_rbs_value_divide_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_divide *value)
{
	struct mptcp_rbs_value_divide *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_divide), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_divide_print(const struct mptcp_rbs_value_divide *value,
				 char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " / ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_remainder *mptcp_rbs_value_remainder_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand)
{
	struct mptcp_rbs_value_remainder *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_remainder), GFP_KERNEL);
	value->kind = VALUE_KIND_REMAINDER;
	value->free = &mptcp_rbs_value_remainder_free;
	value->execute = &mptcp_rbs_value_remainder_execute;
	value->left_operand = left_operand;
	value->right_operand = right_operand;

	return value;
}

void mptcp_rbs_value_remainder_free(struct mptcp_rbs_value_remainder *self)
{
	MPTCP_RBS_VALUE_FREE(self->left_operand);
	MPTCP_RBS_VALUE_FREE(self->right_operand);
	kfree(self);
}

s64 mptcp_rbs_value_remainder_execute(struct mptcp_rbs_value_remainder *self,
				      struct mptcp_rbs_eval_ctx *ctx)
{
	s64 val = self->left_operand->execute(self->left_operand, ctx);
	unsigned int result;

	if (val == -1)
		return -1;
	result = val;

	val = self->right_operand->execute(self->right_operand, ctx);
	if (val == -1 || !val)
		return -1;
	result %= val;

	return result;
}

struct mptcp_rbs_value_remainder *mptcp_rbs_value_remainder_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_remainder *value)
{
	struct mptcp_rbs_value_remainder *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_remainder), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->left_operand);
	CLONE(clone->right_operand);

	return clone;
}

int mptcp_rbs_value_remainder_print(
    const struct mptcp_rbs_value_remainder *value, char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->left_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " % ");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->right_operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_is_null *mptcp_rbs_value_is_null_new(
    struct mptcp_rbs_value *operand)
{
	struct mptcp_rbs_value_is_null *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_is_null), GFP_KERNEL);
	value->kind = VALUE_KIND_IS_NULL;
	value->free = &mptcp_rbs_value_is_null_free;
	value->execute = &mptcp_rbs_value_is_null_execute;
	value->operand = operand;

	return value;
}

void mptcp_rbs_value_is_null_free(struct mptcp_rbs_value_is_null *self)
{
	MPTCP_RBS_VALUE_FREE(self->operand);
	kfree(self);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
s32 mptcp_rbs_value_is_null_execute(struct mptcp_rbs_value_is_null *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	switch (mptcp_rbs_value_get_type(self->operand->kind)) {
	case TYPE_KIND_NULL:
		return 1;
	case TYPE_KIND_BOOL: {
		struct mptcp_rbs_value_bool *bool_value =
		    (struct mptcp_rbs_value_bool *) self->operand;

		return bool_value->execute(bool_value, ctx) == -1;
	}
	case TYPE_KIND_INT: {
		struct mptcp_rbs_value_int *int_value =
		    (struct mptcp_rbs_value_int *) self->operand;

		return int_value->execute(int_value, ctx) == -1;
	}
	case TYPE_KIND_STRING: {
		struct mptcp_rbs_value_string *string_value =
		    (struct mptcp_rbs_value_string *) self->operand;

		return string_value->execute(string_value, ctx) == NULL;
	}
	case TYPE_KIND_SBF: {
		struct mptcp_rbs_value_sbf *sbf_value =
		    (struct mptcp_rbs_value_sbf *) self->operand;

		return sbf_value->execute(sbf_value, ctx) == NULL;
	}
	case TYPE_KIND_SBFLIST: {
		struct mptcp_rbs_value_sbf_list *sbf_list_value =
		    (struct mptcp_rbs_value_sbf_list *) self->operand;
		void *prev = NULL;
		bool is_null;

		sbf_list_value->execute(sbf_list_value, ctx, &prev, &is_null);
		return is_null;
	}
	case TYPE_KIND_SKB: {
		struct mptcp_rbs_value_skb *skb_value =
		    (struct mptcp_rbs_value_skb *) self->operand;

		return skb_value->execute(skb_value, ctx) == NULL;
	}
	case TYPE_KIND_SKBLIST: {
		struct mptcp_rbs_value_skb_list *skb_list_value =
		    (struct mptcp_rbs_value_skb_list *) self->operand;
		void *prev = NULL;
		bool is_null;

		skb_list_value->execute(skb_list_value, ctx, &prev, &is_null);
		return is_null;
	}
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_value_is_null *mptcp_rbs_value_is_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_is_null *value)
{
	struct mptcp_rbs_value_is_null *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_is_null), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->operand);

	return clone;
}

int mptcp_rbs_value_is_null_print(const struct mptcp_rbs_value_is_null *value,
				  char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(value->operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " == NULL)");
	return len;
}

struct mptcp_rbs_value_is_not_null *mptcp_rbs_value_is_not_null_new(
    struct mptcp_rbs_value *operand)
{
	struct mptcp_rbs_value_is_not_null *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_is_not_null), GFP_KERNEL);
	value->kind = VALUE_KIND_IS_NOT_NULL;
	value->free = &mptcp_rbs_value_is_not_null_free;
	value->execute = &mptcp_rbs_value_is_not_null_execute;
	value->operand = operand;

	return value;
}

void mptcp_rbs_value_is_not_null_free(struct mptcp_rbs_value_is_not_null *self)
{
	MPTCP_RBS_VALUE_FREE(self->operand);
	kfree(self);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
s32 mptcp_rbs_value_is_not_null_execute(
    struct mptcp_rbs_value_is_not_null *self, struct mptcp_rbs_eval_ctx *ctx)
{
	switch (mptcp_rbs_value_get_type(self->operand->kind)) {
	case TYPE_KIND_NULL:
		return 0;
	case TYPE_KIND_BOOL: {
		struct mptcp_rbs_value_bool *bool_value =
		    (struct mptcp_rbs_value_bool *) self->operand;

		return bool_value->execute(bool_value, ctx) != -1;
	}
	case TYPE_KIND_INT: {
		struct mptcp_rbs_value_int *int_value =
		    (struct mptcp_rbs_value_int *) self->operand;

		return int_value->execute(int_value, ctx) != -1;
	}
	case TYPE_KIND_STRING: {
		struct mptcp_rbs_value_string *string_value =
		    (struct mptcp_rbs_value_string *) self->operand;

		return string_value->execute(string_value, ctx) != NULL;
	}
	case TYPE_KIND_SBF: {
		struct mptcp_rbs_value_sbf *sbf_value =
		    (struct mptcp_rbs_value_sbf *) self->operand;

		return sbf_value->execute(sbf_value, ctx) != NULL;
	}
	case TYPE_KIND_SBFLIST: {
		struct mptcp_rbs_value_sbf_list *sbf_list_value =
		    (struct mptcp_rbs_value_sbf_list *) self->operand;
		void *prev = NULL;
		bool is_null;

		sbf_list_value->execute(sbf_list_value, ctx, &prev, &is_null);
		return !is_null;
	}
	case TYPE_KIND_SKB: {
		struct mptcp_rbs_value_skb *skb_value =
		    (struct mptcp_rbs_value_skb *) self->operand;

		return skb_value->execute(skb_value, ctx) != NULL;
	}
	case TYPE_KIND_SKBLIST: {
		struct mptcp_rbs_value_skb_list *skb_list_value =
		    (struct mptcp_rbs_value_skb_list *) self->operand;
		void *prev = NULL;
		bool is_null;

		skb_list_value->execute(skb_list_value, ctx, &prev, &is_null);
		return !is_null;
	}
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_value_is_not_null *mptcp_rbs_value_is_not_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_is_not_null *value)
{
	struct mptcp_rbs_value_is_not_null *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_is_not_null), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->operand);

	return clone;
}

int mptcp_rbs_value_is_not_null_print(
    const struct mptcp_rbs_value_is_not_null *value, char *buffer)
{
	int len = sprintf_null(&buffer, "(");
	int tmp_len = mptcp_rbs_value_print(value->operand, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, " != NULL)");
	return len;
}

struct mptcp_rbs_value_reg *mptcp_rbs_value_reg_new(int reg_number)
{
	struct mptcp_rbs_value_reg *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_reg), GFP_KERNEL);
	value->kind = VALUE_KIND_REG;
	value->free = mptcp_rbs_value_reg_free;
	value->execute = mptcp_rbs_value_reg_execute;
	value->reg_number = reg_number;

	return value;
}

void mptcp_rbs_value_reg_free(struct mptcp_rbs_value_reg *self)
{
	kfree(self);
}

s64 mptcp_rbs_value_reg_execute(struct mptcp_rbs_value_reg *self,
				struct mptcp_rbs_eval_ctx *ctx)
{
	return ctx->rbs_cb->regs[self->reg_number];
}

struct mptcp_rbs_value_reg *mptcp_rbs_value_reg_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_reg *value)
{
	struct mptcp_rbs_value_reg *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_reg), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_reg_print(const struct mptcp_rbs_value_reg *value,
			      char *buffer)
{
	return sprintf_null(&buffer, "R%d", value->reg_number + 1);
}

struct mptcp_rbs_value_q *mptcp_rbs_value_q_new(void)
{
	struct mptcp_rbs_value_q *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_q), GFP_KERNEL);
	value->kind = VALUE_KIND_Q;
	value->free = &mptcp_rbs_value_q_free;
	value->execute = &mptcp_rbs_value_q_execute;
	value->underlying_queue_kind = VALUE_KIND_Q;

	return value;
}

/* skip packets which should not be in the queue */
struct sk_buff *mptcp_rbs_next_in_queue(struct sk_buff_head *queue,
					struct sk_buff *skb)
{
	while (skb && TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue) {
		mptcp_debug("%s skipping skb %p with seq %u and end_seq %u as "
			    "it not in queue\n",
			    __func__, skb, TCP_SKB_CB(skb)->seq,
			    TCP_SKB_CB(skb)->end_seq);

		if (skb_queue_is_last(queue, skb))
			return NULL;
		else
			skb = skb_queue_next(queue, skb);
	}

	return skb;
}

void mptcp_rbs_value_q_free(struct mptcp_rbs_value_q *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_q_execute(struct mptcp_rbs_value_q *self,
					  struct mptcp_rbs_eval_ctx *ctx,
					  void **prev, bool *is_null)
{
	struct sk_buff *skb_candidate;
	struct sk_buff *skb_result;

	if (*prev) {
		skb_candidate = (struct sk_buff *) *prev;
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue,
				      skb_candidate))
			skb_candidate = NULL;
		else
			skb_candidate = skb_queue_next(
			    &ctx->meta_sk->sk_write_queue, skb_candidate);
	} else {
		skb_candidate = ctx->rbs_cb->queue_position;
	}

	skb_result = mptcp_rbs_next_in_queue(&ctx->meta_sk->sk_write_queue,
					     skb_candidate);

	*is_null = false;
	if (skb_result)
		*prev = skb_result;

	return skb_result;
}

struct mptcp_rbs_value_q *mptcp_rbs_value_q_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_q *value)
{
	struct mptcp_rbs_value_q *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_q), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_q_print(const struct mptcp_rbs_value_q *value, char *buffer)
{
	return sprintf_null(&buffer, "Q");
}

struct mptcp_rbs_value_qu *mptcp_rbs_value_qu_new(void)
{
	struct mptcp_rbs_value_qu *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_qu), GFP_KERNEL);
	value->kind = VALUE_KIND_QU;
	value->free = &mptcp_rbs_value_qu_free;
	value->execute = &mptcp_rbs_value_qu_execute;
	value->underlying_queue_kind = VALUE_KIND_QU;

	return value;
}

void mptcp_rbs_value_qu_free(struct mptcp_rbs_value_qu *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_qu_execute(struct mptcp_rbs_value_qu *self,
					   struct mptcp_rbs_eval_ctx *ctx,
					   void **prev, bool *is_null)
{
	struct sk_buff *skb;

	if (*prev) {
		skb = (struct sk_buff *) *prev;
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue, skb))
			skb = NULL;
		else {
			skb =
			    skb_queue_next(&ctx->meta_sk->sk_write_queue, skb);
		}
	} else {
		if (ctx->meta_sk->sk_write_queue.qlen == 0)
			/* queue is empty, rq is empty */
			skb = NULL;
		else
			/* start with  write_queue.next */
			skb = skb_peek(&ctx->meta_sk->sk_write_queue);
	}

	mptcp_debug("%s with prev %p has a candidate of %p\n", __func__, *prev,
		    skb);

	// TODO in the old version, we also checked for skb->next ==
	// queue_position
	if (skb == ctx->rbs_cb->queue_position) {
		mptcp_debug(
		    "%s skb %p matches the queue_position, we are at the end\n",
		    __func__, skb);
		skb = NULL;
	}

	// we can not use the approach of Q and RQ, as we have to check for
	// queue_position
	// skb_result = next_in_queue(&ctx->meta_sk->sk_write_queue,
	// skb_candidate);

	while (skb && TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue) {
		mptcp_debug("%s skips skb %p\n", __func__, skb);
		if (skb_queue_is_last(&ctx->meta_sk->sk_write_queue, skb) ||
		    /* Empty because it points to the element in Q */
		    skb == ctx->rbs_cb->queue_position) {
			skb = NULL;
			break;
		} else
			skb =
			    skb_queue_next(&ctx->meta_sk->sk_write_queue, skb);
	}

	*is_null = false;
	if (skb)
		*prev = skb;

	return skb;
}

struct mptcp_rbs_value_qu *mptcp_rbs_value_qu_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_qu *value)
{
	struct mptcp_rbs_value_qu *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_qu), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_qu_print(const struct mptcp_rbs_value_qu *value,
			     char *buffer)
{
	return sprintf_null(&buffer, "QU");
}

struct mptcp_rbs_value_rq *mptcp_rbs_value_rq_new(void)
{
	struct mptcp_rbs_value_rq *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_rq), GFP_KERNEL);
	value->kind = VALUE_KIND_RQ;
	value->free = &mptcp_rbs_value_rq_free;
	value->execute = &mptcp_rbs_value_rq_execute;
	value->underlying_queue_kind = VALUE_KIND_RQ;

	return value;
}

void mptcp_rbs_value_rq_free(struct mptcp_rbs_value_rq *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_rq_execute(struct mptcp_rbs_value_rq *self,
					   struct mptcp_rbs_eval_ctx *ctx,
					   void **prev, bool *is_null)
{
	struct sk_buff *skb_candidate;
	struct sk_buff *skb_result;

	if (*prev) {
		skb_candidate = (struct sk_buff *) *prev;
		if (skb_queue_is_last(&ctx->mpcb->reinject_queue,
				      skb_candidate)) {
			skb_candidate = NULL;
		} else {
			skb_candidate = skb_queue_next(
			    &ctx->mpcb->reinject_queue, skb_candidate);
		}
	} else {
		skb_candidate = skb_peek(&ctx->mpcb->reinject_queue);
	}

	skb_result =
	    mptcp_rbs_next_in_queue(&ctx->mpcb->reinject_queue, skb_candidate);

	mptcp_debug("%s with candidate %p and prev %p for rq %p with rq.len %u "
		    "has result %p\n",
		    __func__, skb_candidate, *prev, &ctx->mpcb->reinject_queue,
		    ctx->mpcb->reinject_queue.qlen, skb_result);

	*is_null = false;
	if (skb_result)
		*prev = skb_result;

	return skb_result;
}

struct mptcp_rbs_value_rq *mptcp_rbs_value_rq_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_rq *value)
{
	struct mptcp_rbs_value_rq *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_rq), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_rq_print(const struct mptcp_rbs_value_rq *value,
			     char *buffer)
{
	return sprintf_null(&buffer, "RQ");
}

struct mptcp_rbs_value_subflows *mptcp_rbs_value_subflows_new(void)
{
	struct mptcp_rbs_value_subflows *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_subflows), GFP_KERNEL);
	value->kind = VALUE_KIND_SUBFLOWS;
	value->free = mptcp_rbs_value_subflows_free;
	value->execute = mptcp_rbs_value_subflows_execute;

	return value;
}

void mptcp_rbs_value_subflows_free(struct mptcp_rbs_value_subflows *self)
{
	kfree(self);
}

bool mptcp_rbs_sbf_is_available(struct tcp_sock *sbf)
{
	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send((struct sock *) sbf)) {
		mptcp_debug("sbf_is_available %p can not send -> false\n", sbf);
		return false;
	}

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (sbf->mptcp->pre_established) {
		mptcp_debug("sbf_is_available %p preestablished -> false\n",
			    sbf);
		return false;
	}

	if (sbf->pf) {
		mptcp_debug("sbf_is_available %p pf -> false\n", sbf);
		return false;
	}

	/*if (inet_csk((struct sock *) sbf)->icsk_ca_state == TCP_CA_Loss) {
		mptcp_debug("sbf_is_available %p loss state -> false\n", sbf);*/
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
/*		if (!tcp_is_reno(sbf))
			return false;
		else if (sbf->snd_una != sbf->high_seq)
			return false;
	}*/

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
/*
	moved this test to a seperate prop

	if (test_bit(TSQ_THROTTLED, &sbf->tsq_flags)) {
		mptcp_debug("sbf_is_available %p tso throttle -> false\n", sbf);
		return false;
	}*/

	return true;
}

struct tcp_sock *mptcp_rbs_value_subflows_execute(
    struct mptcp_rbs_value_subflows *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null)
{
	struct tcp_sock *sbf;

//printk("%s self %p prev %p called\n", __func__, self, prev);

	if (*prev)
		sbf = ((struct tcp_sock *) *prev)->mptcp->next;
	else
		sbf = ctx->mpcb->connection_list;

	/* Skip unavailable subflows */
	while (sbf && !mptcp_rbs_sbf_is_available(sbf)) {
		printk("%s skips sbf %p for meta_sk %p coming from %pS\n", __func__, sbf, ctx->mpcb->meta_sk, __builtin_return_address(0));
		sbf = sbf->mptcp->next;
	}

	*is_null = false;
	if (sbf)
		*prev = sbf;

//printk("%s returns %p\n", __func__, sbf);

	return sbf;
}

struct mptcp_rbs_value_subflows *mptcp_rbs_value_subflows_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_subflows *value)
{
	struct mptcp_rbs_value_subflows *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_subflows), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_subflows_print(const struct mptcp_rbs_value_subflows *value,
				   char *buffer)
{
	return sprintf_null(&buffer, "SUBFLOWS");
}

struct mptcp_rbs_value_current_time_ms *mptcp_rbs_value_current_time_ms_new(
    void)
{
	struct mptcp_rbs_value_current_time_ms *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_current_time_ms), GFP_KERNEL);
	value->kind = VALUE_KIND_CURRENT_TIME_MS;
	value->free = mptcp_rbs_value_current_time_ms_free;
	value->execute = mptcp_rbs_value_current_time_ms_execute;

	return value;
}

void mptcp_rbs_value_current_time_ms_free(
    struct mptcp_rbs_value_current_time_ms *self)
{
	kfree(self);
}

s64 mptcp_rbs_value_current_time_ms_execute(
    struct mptcp_rbs_value_current_time_ms *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	u64 ct = ktime_get_raw_ns();
	u64 tp6 = 1000000;
	return ct / tp6;
}

struct mptcp_rbs_value_current_time_ms *mptcp_rbs_value_current_time_ms_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_current_time_ms *value)
{
	struct mptcp_rbs_value_current_time_ms *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_current_time_ms), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_current_time_ms_print(
    const struct mptcp_rbs_value_current_time_ms *value, char *buffer)
{
	return sprintf_null(&buffer, "CURRENT_TIME_MS");
}

struct mptcp_rbs_value_random *mptcp_rbs_value_random_new(void)
{
	struct mptcp_rbs_value_random *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_random), GFP_KERNEL);
	value->kind = VALUE_KIND_RANDOM;
	value->free = mptcp_rbs_value_random_free;
	value->execute = mptcp_rbs_value_random_execute;

	return value;
}

void mptcp_rbs_value_random_free(struct mptcp_rbs_value_random *self)
{
	kfree(self);
}

s64 mptcp_rbs_value_random_execute(struct mptcp_rbs_value_random *self,
				   struct mptcp_rbs_eval_ctx *ctx)
{
	unsigned int n;

	get_random_bytes(&n, sizeof(unsigned int));
	return n;
}

struct mptcp_rbs_value_random *mptcp_rbs_value_random_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_random *value)
{
	struct mptcp_rbs_value_random *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_random), GFP_KERNEL);
	*clone = *value;

	return clone;
}

int mptcp_rbs_value_random_print(const struct mptcp_rbs_value_random *value,
				 char *buffer)
{
	return sprintf_null(&buffer, "RANDOM");
}

struct mptcp_rbs_value_sbf_rtt *mptcp_rbs_value_sbf_rtt_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_rtt *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_rtt), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_RTT;
	value->free = mptcp_rbs_value_sbf_rtt_free;
	value->execute = mptcp_rbs_value_sbf_rtt_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_rtt_free(struct mptcp_rbs_value_sbf_rtt *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_rtt_execute(struct mptcp_rbs_value_sbf_rtt *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->srtt_us;
}

struct mptcp_rbs_value_sbf_rtt *mptcp_rbs_value_sbf_rtt_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt *value)
{
	struct mptcp_rbs_value_sbf_rtt *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_rtt), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_rtt_print(const struct mptcp_rbs_value_sbf_rtt *value,
				  char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".RTT");
	return len;
}

struct mptcp_rbs_value_sbf_rtt_ms *mptcp_rbs_value_sbf_rtt_ms_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_rtt_ms *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_rtt_ms), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_RTT_MS;
	value->free = mptcp_rbs_value_sbf_rtt_ms_free;
	value->execute = mptcp_rbs_value_sbf_rtt_ms_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_rtt_ms_free(struct mptcp_rbs_value_sbf_rtt_ms *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_rtt_ms_execute(struct mptcp_rbs_value_sbf_rtt_ms *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

    // we now are _MS
	return (sbf->srtt_us >> 3) / 1000;
}

struct mptcp_rbs_value_sbf_rtt_ms *mptcp_rbs_value_sbf_rtt_ms_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt_ms *value)
{
	struct mptcp_rbs_value_sbf_rtt_ms *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_rtt_ms), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_rtt_ms_print(const struct mptcp_rbs_value_sbf_rtt_ms *value,
				  char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".RTT_MS");
	return len;
}

struct mptcp_rbs_value_sbf_rtt_var *mptcp_rbs_value_sbf_rtt_var_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_rtt_var *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_rtt_var), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_RTT_VAR;
	value->free = mptcp_rbs_value_sbf_rtt_var_free;
	value->execute = mptcp_rbs_value_sbf_rtt_var_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_rtt_var_free(struct mptcp_rbs_value_sbf_rtt_var *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_rtt_var_execute(struct mptcp_rbs_value_sbf_rtt_var *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->rttvar_us;
}

struct mptcp_rbs_value_sbf_rtt_var *mptcp_rbs_value_sbf_rtt_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt_var *value)
{
	struct mptcp_rbs_value_sbf_rtt_var *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_rtt_var), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_rtt_var_print(const struct mptcp_rbs_value_sbf_rtt_var *value,
				  char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".RTT_VAR");
	return len;
}

struct mptcp_rbs_value_sbf_user *mptcp_rbs_value_sbf_user_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_user *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_user), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_USER;
	value->free = mptcp_rbs_value_sbf_user_free;
	value->execute = mptcp_rbs_value_sbf_user_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_user_free(struct mptcp_rbs_value_sbf_user *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_user_execute(struct mptcp_rbs_value_sbf_user *self,
				    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

//        return *((s64*) &sbf->mptcp->mptcp_sched[0]);
        return mptcp_rbs_get_sbf_cb(sbf)->user;
}

struct mptcp_rbs_value_sbf_user *mptcp_rbs_value_sbf_user_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_user *value)
{
	struct mptcp_rbs_value_sbf_user *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_user), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_user_print(const struct mptcp_rbs_value_sbf_user *value,
				  char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".USER");
	return len;
}

struct mptcp_rbs_value_sbf_is_backup *mptcp_rbs_value_sbf_is_backup_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_is_backup *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_is_backup), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_IS_BACKUP;
	value->free = mptcp_rbs_value_sbf_is_backup_free;
	value->execute = mptcp_rbs_value_sbf_is_backup_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_is_backup_free(
    struct mptcp_rbs_value_sbf_is_backup *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s32 mptcp_rbs_value_sbf_is_backup_execute(
    struct mptcp_rbs_value_sbf_is_backup *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->mptcp->low_prio || sbf->mptcp->rcv_low_prio;
}

struct mptcp_rbs_value_sbf_is_backup *mptcp_rbs_value_sbf_is_backup_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_is_backup *value)
{
	struct mptcp_rbs_value_sbf_is_backup *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_is_backup), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_is_backup_print(
    const struct mptcp_rbs_value_sbf_is_backup *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".IS_BACKUP");
	return len;
}

struct mptcp_rbs_value_sbf_cwnd *mptcp_rbs_value_sbf_cwnd_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_cwnd *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_cwnd), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_CWND;
	value->free = mptcp_rbs_value_sbf_cwnd_free;
	value->execute = mptcp_rbs_value_sbf_cwnd_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_cwnd_free(struct mptcp_rbs_value_sbf_cwnd *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_cwnd_execute(struct mptcp_rbs_value_sbf_cwnd *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->snd_cwnd;
}

struct mptcp_rbs_value_sbf_cwnd *mptcp_rbs_value_sbf_cwnd_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_cwnd *value)
{
	struct mptcp_rbs_value_sbf_cwnd *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_cwnd), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_cwnd_print(const struct mptcp_rbs_value_sbf_cwnd *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".CWND");
	return len;
}

struct mptcp_rbs_value_sbf_queued *mptcp_rbs_value_sbf_queued_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_queued *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_queued), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_QUEUED;
	value->free = mptcp_rbs_value_sbf_queued_free;
	value->execute = mptcp_rbs_value_sbf_queued_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_queued_free(struct mptcp_rbs_value_sbf_queued *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_queued_execute(struct mptcp_rbs_value_sbf_queued *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return (sbf->write_seq - sbf->snd_nxt) / sbf->mss_cache;
}

struct mptcp_rbs_value_sbf_queued *mptcp_rbs_value_sbf_queued_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_queued *value)
{
	struct mptcp_rbs_value_sbf_queued *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_queued), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_queued_print(const struct mptcp_rbs_value_sbf_queued *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".QUEUED");
	return len;
}

struct mptcp_rbs_value_sbf_skbs_in_flight *
mptcp_rbs_value_sbf_skbs_in_flight_new(struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_skbs_in_flight *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_skbs_in_flight),
			GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_SKBS_IN_FLIGHT;
	value->free = mptcp_rbs_value_sbf_skbs_in_flight_free;
	value->execute = mptcp_rbs_value_sbf_skbs_in_flight_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_skbs_in_flight_free(
    struct mptcp_rbs_value_sbf_skbs_in_flight *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_skbs_in_flight_execute(
    struct mptcp_rbs_value_sbf_skbs_in_flight *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->packets_out;
}

struct mptcp_rbs_value_sbf_skbs_in_flight *
mptcp_rbs_value_sbf_skbs_in_flight_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_skbs_in_flight *value)
{
	struct mptcp_rbs_value_sbf_skbs_in_flight *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_skbs_in_flight),
			GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_skbs_in_flight_print(
    const struct mptcp_rbs_value_sbf_skbs_in_flight *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SKBS_IN_FLIGHT");
	return len;
}

struct mptcp_rbs_value_sbf_lost_skbs *mptcp_rbs_value_sbf_lost_skbs_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_lost_skbs *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_lost_skbs), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_LOST_SKBS;
	value->free = mptcp_rbs_value_sbf_lost_skbs_free;
	value->execute = mptcp_rbs_value_sbf_lost_skbs_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_lost_skbs_free(
    struct mptcp_rbs_value_sbf_lost_skbs *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_lost_skbs_execute(
    struct mptcp_rbs_value_sbf_lost_skbs *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->lost_out;
}

struct mptcp_rbs_value_sbf_lost_skbs *mptcp_rbs_value_sbf_lost_skbs_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_lost_skbs *value)
{
	struct mptcp_rbs_value_sbf_lost_skbs *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_lost_skbs), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_lost_skbs_print(
    const struct mptcp_rbs_value_sbf_lost_skbs *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".LOST_SKBS");
	return len;
}

struct mptcp_rbs_value_sbf_has_window_for *
mptcp_rbs_value_sbf_has_window_for_new(struct mptcp_rbs_value_sbf *sbf,
				       struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_sbf_has_window_for *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_has_window_for),
			GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_HAS_WINDOW_FOR;
	value->free = mptcp_rbs_value_sbf_has_window_for_free;
	value->execute = mptcp_rbs_value_sbf_has_window_for_execute;
	value->sbf = sbf;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_sbf_has_window_for_free(
    struct mptcp_rbs_value_sbf_has_window_for *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s32 mptcp_rbs_value_sbf_has_window_for_execute(
    struct mptcp_rbs_value_sbf_has_window_for *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	unsigned int mss_now = tcp_current_mss(ctx->meta_sk);
	struct tcp_sock *sbf;
	struct sk_buff *skb;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	/* RBS copied from mptcp_sched.c */
	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (after(sbf->write_seq + min(skb->len, mss_now), tcp_wnd_end(sbf)))
		return 0;
	return 1;
}

struct mptcp_rbs_value_sbf_has_window_for *
mptcp_rbs_value_sbf_has_window_for_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_has_window_for *value)
{
	struct mptcp_rbs_value_sbf_has_window_for *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_has_window_for),
			GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_sbf_has_window_for_print(
    const struct mptcp_rbs_value_sbf_has_window_for *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".HAS_WINDOW_FOR(");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_sbf_id *mptcp_rbs_value_sbf_id_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_id *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_id), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_ID;
	value->free = mptcp_rbs_value_sbf_id_free;
	value->execute = mptcp_rbs_value_sbf_id_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_id_free(struct mptcp_rbs_value_sbf_id *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_id_execute(struct mptcp_rbs_value_sbf_id *self,
				   struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->mptcp->sbf_id;
}

struct mptcp_rbs_value_sbf_id *mptcp_rbs_value_sbf_id_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_id *value)
{
	struct mptcp_rbs_value_sbf_id *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_id), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_id_print(const struct mptcp_rbs_value_sbf_id *value,
				 char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".ID");
	return len;
}

/* some helper for delay calculation */

void mptcp_rbs_sbf_delay_update(struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* Recalculate delays */
	/* Size considerations: we subtract two u32 values, the result might
	 * have a sign (requires 33 bit)
	 * However, we can safely ignore the highest bit of the u32 values
	 * (0x80000000),
	 * add 1 << 32 (0x80000000and) for the subtraction and store it as u32.
	 */
	struct mptcp_rbs_sbf_cb *sbf_cb = mptcp_rbs_get_sbf_cb(tp);
	const unsigned int first_bit_set = 0x80000000;
	const unsigned int first_bit_not_set = 0x7FFFFFFF;
	sbf_cb->delay_in =
	    (first_bit_set + (tcp_time_stamp & first_bit_not_set)) -
	    (tp->rx_opt.rcv_tsval & first_bit_not_set);
	sbf_cb->delay_out =
	    (first_bit_set + (tp->rx_opt.rcv_tsval & first_bit_not_set)) -
	    (tp->rx_opt.rcv_tsecr & first_bit_not_set);
//    printk("rcv_tsval %u and rcv_tsecr %u lead to delay out %u and delay in %u\n", tp->rx_opt.rcv_tsval, tp->rx_opt.rcv_tsecr, sbf_cb->delay_out, sbf_cb->delay_in);
}

/* delay out */

struct mptcp_rbs_value_sbf_delay_out *mptcp_rbs_value_sbf_delay_out_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_delay_out *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_delay_out), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_DELAY_OUT;
	value->free = mptcp_rbs_value_sbf_delay_out_free;
	value->execute = mptcp_rbs_value_sbf_delay_out_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_delay_out_free(
    struct mptcp_rbs_value_sbf_delay_out *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_delay_out_execute(
    struct mptcp_rbs_value_sbf_delay_out *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return mptcp_rbs_get_sbf_cb(sbf)->delay_out;
}

struct mptcp_rbs_value_sbf_delay_out *mptcp_rbs_value_sbf_delay_out_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_delay_out *value)
{
	struct mptcp_rbs_value_sbf_delay_out *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_delay_out), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_delay_out_print(
    const struct mptcp_rbs_value_sbf_delay_out *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".DELAY_OUT");
	return len;
}

/* delay in */

struct mptcp_rbs_value_sbf_delay_in *mptcp_rbs_value_sbf_delay_in_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_delay_in *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_delay_in), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_DELAY_IN;
	value->free = mptcp_rbs_value_sbf_delay_in_free;
	value->execute = mptcp_rbs_value_sbf_delay_in_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_delay_in_free(
    struct mptcp_rbs_value_sbf_delay_in *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_delay_in_execute(
    struct mptcp_rbs_value_sbf_delay_in *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return mptcp_rbs_get_sbf_cb(sbf)->delay_in;
}

struct mptcp_rbs_value_sbf_delay_in *mptcp_rbs_value_sbf_delay_in_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_delay_in *value)
{
	struct mptcp_rbs_value_sbf_delay_in *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_delay_in), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_delay_in_print(
    const struct mptcp_rbs_value_sbf_delay_in *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".DELAY_IN");
	return len;
}

/* some helper for bw calculation */

u64 mptcp_rbs_sbf_get_bw_send(struct mptcp_rbs_sbf_cb *sbf_cb)
{
	u64 RBS_BW_INTERVAL_NS = 1000000000; // one second
	u64 diff = ktime_get_raw_ns() - sbf_cb->bw_out_last_update_ns;

	/* how much time is gone since the last update */
	if (diff > RBS_BW_INTERVAL_NS)
		return 0;

	/* only use the portion of one second */
	return (RBS_BW_INTERVAL_NS - diff) * sbf_cb->bw_out_bytes /
	       RBS_BW_INTERVAL_NS;
}

u64 mptcp_rbs_sbf_get_bw_ack(struct mptcp_rbs_sbf_cb *sbf_cb)
{
	u64 RBS_BW_INTERVAL_NS = 1000000000; // one second
	u64 diff = ktime_get_raw_ns() - sbf_cb->bw_ack_last_update_ns;

	/* how much time is gone since the last update */
	if (diff > RBS_BW_INTERVAL_NS)
		return 0;

	/* only use the portion of one second */
	return (RBS_BW_INTERVAL_NS - diff) * sbf_cb->bw_ack_bytes /
	       RBS_BW_INTERVAL_NS;
}

void mptcp_rbs_sbf_bw_add(u64 *last_update_ns, u64 *bytes_in_cb,
			  unsigned int bytes)
{
	u64 ct = ktime_get_raw_ns();
	u64 RBS_BW_INTERVAL_NS = 1000000000; // one second

	mptcp_debug("rbs_bw compares %llu and %llu, or more precise, the diff "
		    "is %llu\n",
		    ct, (*last_update_ns), (ct - *last_update_ns));

	if (bytes == 0) // nothing to do
		return;

	if (ct - *last_update_ns <
	    RBS_BW_INTERVAL_NS) { // delta t less than a second
		u64 delta_t = ct - (*last_update_ns);
		*bytes_in_cb = (*bytes_in_cb) * (RBS_BW_INTERVAL_NS - delta_t) /
				   RBS_BW_INTERVAL_NS +
			       bytes;
		mptcp_debug("rbs_bw sets bw to %llu with delta_t %llu\n",
			    *bytes_in_cb, delta_t);
	} else {
		*bytes_in_cb = bytes;
		mptcp_debug(
		    "rbs_bw sets new value after more than 1 second to  %u\n",
		    bytes);
	}

	*last_update_ns = ct;
}

void mptcp_rbs_sbf_bw_send_add(struct tcp_sock *tp, unsigned int bytes)
{
	struct mptcp_rbs_sbf_cb *sbf_cb = mptcp_rbs_get_sbf_cb(tp);
	mptcp_rbs_sbf_bw_add(&sbf_cb->bw_out_last_update_ns,
			     &sbf_cb->bw_out_bytes, bytes);
}

void mptcp_rbs_sbf_bw_ack_add(struct tcp_sock *tp, unsigned int bytes)
{
	struct mptcp_rbs_sbf_cb *sbf_cb = mptcp_rbs_get_sbf_cb(tp);
	mptcp_rbs_sbf_bw_add(&sbf_cb->bw_ack_last_update_ns,
			     &sbf_cb->bw_ack_bytes, bytes);
}

/* bw out ack */

struct mptcp_rbs_value_sbf_bw_out_ack *mptcp_rbs_value_sbf_bw_out_ack_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_bw_out_ack *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_bw_out_ack), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_BW_OUT_ACK;
	value->free = mptcp_rbs_value_sbf_bw_out_ack_free;
	value->execute = mptcp_rbs_value_sbf_bw_out_ack_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_bw_out_ack_free(
    struct mptcp_rbs_value_sbf_bw_out_ack *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_bw_out_ack_execute(
    struct mptcp_rbs_value_sbf_bw_out_ack *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return mptcp_rbs_sbf_get_bw_ack(mptcp_rbs_get_sbf_cb(sbf));
}

struct mptcp_rbs_value_sbf_bw_out_ack *mptcp_rbs_value_sbf_bw_out_ack_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_bw_out_ack *value)
{
	struct mptcp_rbs_value_sbf_bw_out_ack *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_bw_out_ack), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_bw_out_ack_print(
    const struct mptcp_rbs_value_sbf_bw_out_ack *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".BW_OUT_ACK");
	return len;
}

/* bw out send */

struct mptcp_rbs_value_sbf_bw_out_send *mptcp_rbs_value_sbf_bw_out_send_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_bw_out_send *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_bw_out_send), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_BW_OUT_SEND;
	value->free = mptcp_rbs_value_sbf_bw_out_send_free;
	value->execute = mptcp_rbs_value_sbf_bw_out_send_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_bw_out_send_free(
    struct mptcp_rbs_value_sbf_bw_out_send *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_bw_out_send_execute(
    struct mptcp_rbs_value_sbf_bw_out_send *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return mptcp_rbs_sbf_get_bw_send(mptcp_rbs_get_sbf_cb(sbf));
}

struct mptcp_rbs_value_sbf_bw_out_send *mptcp_rbs_value_sbf_bw_out_send_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_bw_out_send *value)
{
	struct mptcp_rbs_value_sbf_bw_out_send *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_bw_out_send), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_bw_out_send_print(
    const struct mptcp_rbs_value_sbf_bw_out_send *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".BW_OUT_SEND");
	return len;
}

/* slow start threshold ssthresh */

struct mptcp_rbs_value_sbf_ssthresh *mptcp_rbs_value_sbf_ssthresh_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_ssthresh *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_ssthresh), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_SSTHRESH;
	value->free = mptcp_rbs_value_sbf_ssthresh_free;
	value->execute = mptcp_rbs_value_sbf_ssthresh_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_ssthresh_free(
    struct mptcp_rbs_value_sbf_ssthresh *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_ssthresh_execute(
    struct mptcp_rbs_value_sbf_ssthresh *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return sbf->snd_ssthresh;
}

struct mptcp_rbs_value_sbf_ssthresh *mptcp_rbs_value_sbf_ssthresh_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_ssthresh *value)
{
	struct mptcp_rbs_value_sbf_ssthresh *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_ssthresh), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_ssthresh_print(
    const struct mptcp_rbs_value_sbf_ssthresh *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SSTHRESH");
	return len;
}

struct mptcp_rbs_value_sbf_throttled *mptcp_rbs_value_sbf_throttled_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_throttled *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_throttled), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_THROTTLED;
	value->free = mptcp_rbs_value_sbf_throttled_free;
	value->execute = mptcp_rbs_value_sbf_throttled_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_throttled_free(
    struct mptcp_rbs_value_sbf_throttled *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s32 mptcp_rbs_value_sbf_throttled_execute(
    struct mptcp_rbs_value_sbf_throttled *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return test_bit(TSQ_THROTTLED, &sbf->tsq_flags);
}

struct mptcp_rbs_value_sbf_throttled *mptcp_rbs_value_sbf_throttled_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_throttled *value)
{
	struct mptcp_rbs_value_sbf_throttled *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_throttled), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_throttled_print(
    const struct mptcp_rbs_value_sbf_throttled *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".THROTTLED");
	return len;
}

struct mptcp_rbs_value_sbf_lossy *mptcp_rbs_value_sbf_lossy_new(
    struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_sbf_lossy *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_lossy), GFP_KERNEL);
	value->kind = VALUE_KIND_SBF_LOSSY;
	value->free = mptcp_rbs_value_sbf_lossy_free;
	value->execute = mptcp_rbs_value_sbf_lossy_execute;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_sbf_lossy_free(struct mptcp_rbs_value_sbf_lossy *self)
{
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s32 mptcp_rbs_value_sbf_lossy_execute(struct mptcp_rbs_value_sbf_lossy *self,
				      struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	if (inet_csk((struct sock *) sbf)->icsk_ca_state == TCP_CA_Loss) {
		mptcp_debug("sbf_is_available %p loss state -> false\n", sbf);
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(sbf))
			return true;
		else if (sbf->snd_una != sbf->high_seq)
			return true;
	}

	return false;
}

struct mptcp_rbs_value_sbf_lossy *mptcp_rbs_value_sbf_lossy_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_lossy *value)
{
	struct mptcp_rbs_value_sbf_lossy *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_lossy), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);

	return clone;
}

int mptcp_rbs_value_sbf_lossy_print(
    const struct mptcp_rbs_value_sbf_lossy *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".LOSSY");
	return len;
}

struct mptcp_rbs_value_sbf_list_next *mptcp_rbs_value_sbf_list_next_new(
    struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_value_sbf_list_next *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_next), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_NEXT;
	value->free = mptcp_rbs_value_sbf_list_next_free;
	value->execute = mptcp_rbs_value_sbf_list_next_execute;
	value->list = list;

	return value;
}

void mptcp_rbs_value_sbf_list_next_free(
    struct mptcp_rbs_value_sbf_list_next *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_next_execute(
    struct mptcp_rbs_value_sbf_list_next *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;

mptcp_debug("%s for meta_sk %p with self %p coming from %pS with self->exec_count %u and rbs_cb->exec_count %u and prev %p and isnull %d\n", __func__, ctx->mpcb->meta_sk, self,  __builtin_return_address(0), self->exec_count, ctx->rbs_cb->exec_count, self->prev, self->is_null);

	if (self->exec_count != ctx->rbs_cb->exec_count) {
		self->prev = NULL;
		self->is_null = false;
		self->exec_count = ctx->rbs_cb->exec_count;
	}
	if (self->is_null)
		return NULL;

	sbf = self->list->execute(self->list, ctx, &self->prev, &self->is_null);
	if (!sbf) {
		self->prev = NULL;
		self->is_null = true;

		/* If we have nested loops we have to make sure that next time
		 * we visit this value the first item of the list is returned
		 */
		--self->exec_count;
	}

	return sbf;
}

struct mptcp_rbs_value_sbf_list_next *mptcp_rbs_value_sbf_list_next_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_next *value)
{
	struct mptcp_rbs_value_sbf_list_next *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_next), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_sbf_list_next_print(
    const struct mptcp_rbs_value_sbf_list_next *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".NEXT()");
	return len;
}

struct mptcp_rbs_value_sbf_list_empty *mptcp_rbs_value_sbf_list_empty_new(
    struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_value_sbf_list_empty *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_empty), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_EMPTY;
	value->free = mptcp_rbs_value_sbf_list_empty_free;
	value->execute = mptcp_rbs_value_sbf_list_empty_execute;
	value->list = list;

	return value;
}

void mptcp_rbs_value_sbf_list_empty_free(
    struct mptcp_rbs_value_sbf_list_empty *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

s32 mptcp_rbs_value_sbf_list_empty_execute(
    struct mptcp_rbs_value_sbf_list_empty *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct tcp_sock *sbf;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);

	if (is_null)
		return -1;
	return sbf ? 0 : 1;
}

struct mptcp_rbs_value_sbf_list_empty *mptcp_rbs_value_sbf_list_empty_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_empty *value)
{
	struct mptcp_rbs_value_sbf_list_empty *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_empty), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_sbf_list_empty_print(
    const struct mptcp_rbs_value_sbf_list_empty *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".EMPTY");
	return len;
}

struct mptcp_rbs_value_sbf_list_filter *mptcp_rbs_value_sbf_list_filter_new(
    void)
{
	struct mptcp_rbs_value_sbf_list_filter *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_filter), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_FILTER;
	value->free = mptcp_rbs_value_sbf_list_filter_free;
	value->execute = mptcp_rbs_value_sbf_list_filter_execute;
	/* value->list and value->cond are set later */

	return value;
}

void mptcp_rbs_value_sbf_list_filter_free(
    struct mptcp_rbs_value_sbf_list_filter *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->cond);
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_filter_execute(
    struct mptcp_rbs_value_sbf_list_filter *self,
    struct mptcp_rbs_eval_ctx *ctx, void **prev, bool *is_null)
{
	struct tcp_sock *sbf;
	s32 b;

	sbf = self->list->execute(self->list, ctx, prev, is_null);
	if (*is_null)
		return NULL;

	while (sbf) {
		self->cur = sbf;
		b = self->cond->execute(self->cond, ctx);
		if (b > 0)
			break;

		sbf = self->list->execute(self->list, ctx, prev, is_null);
	}

	return sbf;
}

struct mptcp_rbs_value_sbf_list_filter *mptcp_rbs_value_sbf_list_filter_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_filter *value)
{
	struct mptcp_rbs_value_sbf_list_filter *clone;
	int i;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_filter), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	for (i = 0; i < MAX_NESTING; ++i) {
		if (!ctx->repls[i].repl)
			break;
	}
	BUG_ON(i == MAX_NESTING);

	ctx->repls[i].repl = &value->cur;
	ctx->repls[i].repl_with = &clone->cur;
	CLONE(clone->cond);
	ctx->repls[i].repl = NULL;

	return clone;
}

int mptcp_rbs_value_sbf_list_filter_print(
    const struct mptcp_rbs_value_sbf_list_filter *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".FILTER(v%p => ", &value->cur);

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->cond, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_sbf_list_filter_sbf *
mptcp_rbs_value_sbf_list_filter_sbf_new(struct tcp_sock **cur)
{
	struct mptcp_rbs_value_sbf_list_filter_sbf *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_filter_sbf),
			GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_FILTER_SBF;
	value->free = mptcp_rbs_value_sbf_list_filter_sbf_free;
	value->execute = mptcp_rbs_value_sbf_list_filter_sbf_execute;
	value->cur = cur;

	return value;
}

void mptcp_rbs_value_sbf_list_filter_sbf_free(
    struct mptcp_rbs_value_sbf_list_filter_sbf *self)
{
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_filter_sbf_execute(
    struct mptcp_rbs_value_sbf_list_filter_sbf *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	return *self->cur;
}

struct mptcp_rbs_value_sbf_list_filter_sbf *
mptcp_rbs_value_sbf_list_filter_sbf_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_filter_sbf *value)
{
	struct mptcp_rbs_value_sbf_list_filter_sbf *clone;
	int i;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_filter_sbf),
			GFP_KERNEL);
	*clone = *value;

	for (i = 0; i < MAX_NESTING; ++i) {
		if (clone->cur == ctx->repls[i].repl) {
			clone->cur = ctx->repls[i].repl_with;
			break;
		}
	}

	return clone;
}

int mptcp_rbs_value_sbf_list_filter_sbf_print(
    const struct mptcp_rbs_value_sbf_list_filter_sbf *value, char *buffer)
{
	return sprintf_null(&buffer, "v%p", value->cur);
}

struct mptcp_rbs_value_sbf_list_max *mptcp_rbs_value_sbf_list_max_new(void)
{
	struct mptcp_rbs_value_sbf_list_max *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_max), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_MAX;
	value->free = mptcp_rbs_value_sbf_list_max_free;
	value->execute = mptcp_rbs_value_sbf_list_max_execute;
	/* value->list and value->cond are set later */

	return value;
}

void mptcp_rbs_value_sbf_list_max_free(
    struct mptcp_rbs_value_sbf_list_max *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->cond);
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_max_execute(
    struct mptcp_rbs_value_sbf_list_max *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct tcp_sock *sbf;
	s64 value;
	struct tcp_sock *max_sbf = NULL;
	s64 max_value = -1;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	if (is_null)
		return NULL;

	while (sbf) {
		self->cur = sbf;
		value = self->cond->execute(self->cond, ctx);
		if (value != -1 && value > max_value) {
			max_value = value;
			max_sbf = sbf;
		}

		sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return max_sbf;
}

struct mptcp_rbs_value_sbf_list_max *mptcp_rbs_value_sbf_list_max_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_max *value)
{
	struct mptcp_rbs_value_sbf_list_max *clone;
	int i;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_max), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	for (i = 0; i < MAX_NESTING; ++i) {
		if (!ctx->repls[i].repl)
			break;
	}
	BUG_ON(i == MAX_NESTING);

	ctx->repls[i].repl = &value->cur;
	ctx->repls[i].repl_with = &clone->cur;
	CLONE(clone->cond);
	ctx->repls[i].repl = NULL;

	return clone;
}

int mptcp_rbs_value_sbf_list_max_print(
    const struct mptcp_rbs_value_sbf_list_max *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".MAX(v%p => ", &value->cur);

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->cond, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_sbf_list_min *mptcp_rbs_value_sbf_list_min_new(void)
{
	struct mptcp_rbs_value_sbf_list_min *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_min), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_MIN;
	value->free = mptcp_rbs_value_sbf_list_min_free;
	value->execute = mptcp_rbs_value_sbf_list_min_execute;
	/* value->list and value->cond are set later */

	return value;
}

void mptcp_rbs_value_sbf_list_min_free(
    struct mptcp_rbs_value_sbf_list_min *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->cond);
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_min_execute(
    struct mptcp_rbs_value_sbf_list_min *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct tcp_sock *sbf;
	s64 value;
	struct tcp_sock *min_sbf = NULL;
	s64 min_value = 0xFFFFFFFFll;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	if (is_null)
		return NULL;

	while (sbf) {
		self->cur = sbf;
		value = self->cond->execute(self->cond, ctx);
		if (value != -1 && value < min_value) {
			min_value = value;
			min_sbf = sbf;
		}

		sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return min_sbf;
}

struct mptcp_rbs_value_sbf_list_min *mptcp_rbs_value_sbf_list_min_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_min *value)
{
	struct mptcp_rbs_value_sbf_list_min *clone;
	int i;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_min), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	for (i = 0; i < MAX_NESTING; ++i) {
		if (!ctx->repls[i].repl)
			break;
	}
	BUG_ON(i == MAX_NESTING);

	ctx->repls[i].repl = &value->cur;
	ctx->repls[i].repl_with = &clone->cur;
	CLONE(clone->cond);
	ctx->repls[i].repl = NULL;

	return clone;
}

int mptcp_rbs_value_sbf_list_min_print(
    const struct mptcp_rbs_value_sbf_list_min *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".MIN(v%p => ", &value->cur);

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->cond, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_sbf_list_get *mptcp_rbs_value_sbf_list_get_new(
    struct mptcp_rbs_value_sbf_list *list, struct mptcp_rbs_value_int *index)
{
	struct mptcp_rbs_value_sbf_list_get *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_get), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_GET;
	value->free = mptcp_rbs_value_sbf_list_get_free;
	value->execute = mptcp_rbs_value_sbf_list_get_execute;
	value->list = list;
	value->index = index;

	return value;
}

void mptcp_rbs_value_sbf_list_get_free(
    struct mptcp_rbs_value_sbf_list_get *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->index);
	kfree(self);
}

struct tcp_sock *mptcp_rbs_value_sbf_list_get_execute(
    struct mptcp_rbs_value_sbf_list_get *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct tcp_sock *sbf;
	s64 idx;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	idx = self->index->execute(self->index, ctx);

	if (is_null || idx < 0)
		return NULL;

	while (sbf && idx) {
		--idx;
		sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return sbf;
}

struct mptcp_rbs_value_sbf_list_get *mptcp_rbs_value_sbf_list_get_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_get *value)
{
	struct mptcp_rbs_value_sbf_list_get *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_get), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);
	CLONE(clone->index);

	return clone;
}

int mptcp_rbs_value_sbf_list_get_print(
    const struct mptcp_rbs_value_sbf_list_get *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".GET(");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->index, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");

	return len;
}

struct mptcp_rbs_value_sbf_list_count *mptcp_rbs_value_sbf_list_count_new(
    struct mptcp_rbs_value_sbf_list *list)
{
	struct mptcp_rbs_value_sbf_list_count *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_count), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_COUNT;
	value->free = mptcp_rbs_value_sbf_list_count_free;
	value->execute = mptcp_rbs_value_sbf_list_count_execute;
	value->list = list;

	return value;
}

void mptcp_rbs_value_sbf_list_count_free(
    struct mptcp_rbs_value_sbf_list_count *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_list_count_execute(
    struct mptcp_rbs_value_sbf_list_count *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct tcp_sock *sbf;
	void *prev = NULL;
	bool is_null;
	int n = 0;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	if (is_null)
		return -1;

	while (sbf) {
		++n;
		sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return n;
}

struct mptcp_rbs_value_sbf_list_count *mptcp_rbs_value_sbf_list_count_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_count *value)
{
	struct mptcp_rbs_value_sbf_list_count *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_count), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_sbf_list_count_print(
    const struct mptcp_rbs_value_sbf_list_count *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".COUNT");
	return len;
}

struct mptcp_rbs_value_sbf_list_sum *mptcp_rbs_value_sbf_list_sum_new(void)
{
	struct mptcp_rbs_value_sbf_list_sum *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_sbf_list_sum), GFP_KERNEL);
	value->kind = VALUE_KIND_SBFLIST_SUM;
	value->free = mptcp_rbs_value_sbf_list_sum_free;
	value->execute = mptcp_rbs_value_sbf_list_sum_execute;
	/* value->list and value->cond are set later */

	return value;
}

void mptcp_rbs_value_sbf_list_sum_free(
    struct mptcp_rbs_value_sbf_list_sum *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->cond);
	kfree(self);
}

s64 mptcp_rbs_value_sbf_list_sum_execute(
    struct mptcp_rbs_value_sbf_list_sum *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct tcp_sock *sbf;
	s64 sum = 0;
	s64 value;

	sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	if (is_null)
		return -1;

	while (sbf) {
		self->cur = sbf;
		value = self->cond->execute(self->cond, ctx);
		if (value != -1)
			sum += value;

		sbf = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return sum;
}

struct mptcp_rbs_value_sbf_list_sum *mptcp_rbs_value_sbf_list_sum_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_sum *value)
{
	struct mptcp_rbs_value_sbf_list_sum *clone;
	int i;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_sbf_list_sum), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	for (i = 0; i < MAX_NESTING; ++i) {
		if (!ctx->repls[i].repl)
			break;
	}
	BUG_ON(i == MAX_NESTING);

	ctx->repls[i].repl = &value->cur;
	ctx->repls[i].repl_with = &clone->cur;
	CLONE(clone->cond);
	ctx->repls[i].repl = NULL;

	return clone;
}

int mptcp_rbs_value_sbf_list_sum_print(
    const struct mptcp_rbs_value_sbf_list_sum *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SUM(v%p => ", &value->cur);

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->cond, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_skb_list_next *mptcp_rbs_value_skb_list_next_new(
    struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_value_skb_list_next *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_next), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_NEXT;
	value->free = mptcp_rbs_value_skb_list_next_free;
	value->execute = mptcp_rbs_value_skb_list_next_execute;
	value->list = list;
	value->reinject = list->underlying_queue_kind == VALUE_KIND_RQ;

	return value;
}

void mptcp_rbs_value_skb_list_next_free(
    struct mptcp_rbs_value_skb_list_next *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_next_execute(
    struct mptcp_rbs_value_skb_list_next *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	if (self->exec_count != ctx->rbs_cb->exec_count) {
		self->prev = NULL;
		self->is_null = false;
		self->exec_count = ctx->rbs_cb->exec_count;
	}
	if (self->is_null)
		return NULL;

	skb = self->list->execute(self->list, ctx, &self->prev, &self->is_null);
	if (!skb) {
		self->prev = NULL;
		self->is_null = true;

		/* If we have nested loops we have to make sure that next time
		 * we visit this value the first item of the list is returned
		 */
		--self->exec_count;
	}

	return skb;
}

struct mptcp_rbs_value_skb_list_next *mptcp_rbs_value_skb_list_next_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_next *value)
{
	struct mptcp_rbs_value_skb_list_next *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_next), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_skb_list_next_print(
    const struct mptcp_rbs_value_skb_list_next *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".NEXT()");
	return len;
}

struct mptcp_rbs_value_skb_sent_on *mptcp_rbs_value_skb_sent_on_new(
    struct mptcp_rbs_value_skb *skb, struct mptcp_rbs_value_sbf *sbf)
{
	struct mptcp_rbs_value_skb_sent_on *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_sent_on), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_SENT_ON;
	value->free = mptcp_rbs_value_skb_sent_on_free;
	value->execute = mptcp_rbs_value_skb_sent_on_execute;
	value->skb = skb;
	value->sbf = sbf;

	return value;
}

void mptcp_rbs_value_skb_sent_on_free(struct mptcp_rbs_value_skb_sent_on *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	MPTCP_RBS_VALUE_FREE(self->sbf);
	kfree(self);
}

s32 mptcp_rbs_value_skb_sent_on_execute(
    struct mptcp_rbs_value_skb_sent_on *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;
	struct tcp_sock *sbf;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	sbf = self->sbf->execute(self->sbf, ctx);
	if (!sbf)
		return -1;

	return mptcp_pi_to_flag(sbf->mptcp->path_index) &
	       TCP_SKB_CB(skb)->path_mask;
}

struct mptcp_rbs_value_skb_sent_on *mptcp_rbs_value_skb_sent_on_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_sent_on *value)
{
	struct mptcp_rbs_value_skb_sent_on *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_sent_on), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->sbf);
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_sent_on_print(
    const struct mptcp_rbs_value_skb_sent_on *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SENT_ON(");

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->sbf, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_skb_sent_on_all *mptcp_rbs_value_skb_sent_on_all_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_skb_sent_on_all *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_sent_on_all), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_SENT_ON_ALL;
	value->free = mptcp_rbs_value_skb_sent_on_all_free;
	value->execute = mptcp_rbs_value_skb_sent_on_all_execute;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_skb_sent_on_all_free(
    struct mptcp_rbs_value_skb_sent_on_all *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s32 mptcp_rbs_value_skb_sent_on_all_execute(
    struct mptcp_rbs_value_skb_sent_on_all *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;
	u32 mask;
	struct tcp_sock *sbf;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	mask = TCP_SKB_CB(skb)->path_mask;
	sbf = ctx->mpcb->connection_list;

	while (sbf) {
		if (!(mask & mptcp_pi_to_flag(sbf->mptcp->path_index)))
			return 0;

		sbf = sbf->mptcp->next;
	}

	return 1;
}

struct mptcp_rbs_value_skb_sent_on_all *mptcp_rbs_value_skb_sent_on_all_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_sent_on_all *value)
{
	struct mptcp_rbs_value_skb_sent_on_all *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_sent_on_all), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_sent_on_all_print(
    const struct mptcp_rbs_value_skb_sent_on_all *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SENT_ON_ALL");
	return len;
}

struct mptcp_rbs_value_skb_user *mptcp_rbs_value_skb_user_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_skb_user *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_user), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_USER;
	value->free = mptcp_rbs_value_skb_user_free;
	value->execute = mptcp_rbs_value_skb_user_execute;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_skb_user_free(struct mptcp_rbs_value_skb_user *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s64 mptcp_rbs_value_skb_user_execute(struct mptcp_rbs_value_skb_user *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	return TCP_SKB_CB(skb)->mptcp_rbs.user;
}

struct mptcp_rbs_value_skb_user *mptcp_rbs_value_skb_user_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_user *value)
{
	struct mptcp_rbs_value_skb_user *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_user), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_user_print(const struct mptcp_rbs_value_skb_user *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".USER");
	return len;
}

struct mptcp_rbs_value_skb_seq *mptcp_rbs_value_skb_seq_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_skb_seq *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_seq), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_SEQ;
	value->free = mptcp_rbs_value_skb_seq_free;
	value->execute = mptcp_rbs_value_skb_seq_execute;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_skb_seq_free(struct mptcp_rbs_value_skb_seq *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s64 mptcp_rbs_value_skb_seq_execute(struct mptcp_rbs_value_skb_seq *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	return TCP_SKB_CB(skb)->seq;
}

struct mptcp_rbs_value_skb_seq *mptcp_rbs_value_skb_seq_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_seq *value)
{
	struct mptcp_rbs_value_skb_seq *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_seq), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_seq_print(const struct mptcp_rbs_value_skb_seq *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".SEQ");
	return len;
}

struct mptcp_rbs_value_skb_psh *mptcp_rbs_value_skb_psh_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_skb_psh *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_psh), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_PSH;
	value->free = mptcp_rbs_value_skb_psh_free;
	value->execute = mptcp_rbs_value_skb_psh_execute;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_skb_psh_free(struct mptcp_rbs_value_skb_psh *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s32 mptcp_rbs_value_skb_psh_execute(struct mptcp_rbs_value_skb_psh *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	return TCP_SKB_CB(skb)->tcp_flags & TCPHDR_PSH;
}

struct mptcp_rbs_value_skb_psh *mptcp_rbs_value_skb_psh_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_psh *value)
{
	struct mptcp_rbs_value_skb_psh *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_psh), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_psh_print(const struct mptcp_rbs_value_skb_psh *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".PSH");
	return len;
}

struct mptcp_rbs_value_skb_length *mptcp_rbs_value_skb_length_new(
    struct mptcp_rbs_value_skb *skb)
{
	struct mptcp_rbs_value_skb_length *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_length), GFP_KERNEL);
	value->kind = VALUE_KIND_SKB_LENGTH;
	value->free = mptcp_rbs_value_skb_length_free;
	value->execute = mptcp_rbs_value_skb_length_execute;
	value->skb = skb;

	return value;
}

void mptcp_rbs_value_skb_length_free(struct mptcp_rbs_value_skb_length *self)
{
	MPTCP_RBS_VALUE_FREE(self->skb);
	kfree(self);
}

s64 mptcp_rbs_value_skb_length_execute(struct mptcp_rbs_value_skb_length *self,
				     struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;

	skb = self->skb->execute(self->skb, ctx);
	if (!skb)
		return -1;

	return TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
}

struct mptcp_rbs_value_skb_length *mptcp_rbs_value_skb_length_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_length *value)
{
	struct mptcp_rbs_value_skb_length *clone;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_length), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->skb);

	return clone;
}

int mptcp_rbs_value_skb_length_print(const struct mptcp_rbs_value_skb_length *value,
				   char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->skb, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".LENGTH");
	return len;
}

struct mptcp_rbs_value_skb_list_empty *mptcp_rbs_value_skb_list_empty_new(
    struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_value_skb_list_empty *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_empty), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_EMPTY;
	value->free = mptcp_rbs_value_skb_list_empty_free;
	value->execute = mptcp_rbs_value_skb_list_empty_execute;
	value->list = list;

	return value;
}

void mptcp_rbs_value_skb_list_empty_free(
    struct mptcp_rbs_value_skb_list_empty *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

s32 mptcp_rbs_value_skb_list_empty_execute(
    struct mptcp_rbs_value_skb_list_empty *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct sk_buff *skb;

	skb = self->list->execute(self->list, ctx, &prev, &is_null);

	if (is_null)
		return -1;
	return skb ? 0 : 1;
}

struct mptcp_rbs_value_skb_list_empty *mptcp_rbs_value_skb_list_empty_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_empty *value)
{
	struct mptcp_rbs_value_skb_list_empty *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_empty), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_skb_list_empty_print(
    const struct mptcp_rbs_value_skb_list_empty *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".EMPTY");
	return len;
}

struct mptcp_rbs_value_skb_list_pop *mptcp_rbs_value_skb_list_pop_new(
    struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_value_skb_list_pop *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_pop), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_POP;
	value->free = mptcp_rbs_value_skb_list_pop_free;
	value->execute = mptcp_rbs_value_skb_list_pop_execute;
	value->list = list;
	value->reinject = list->underlying_queue_kind == VALUE_KIND_RQ;

	return value;
}

void mptcp_rbs_value_skb_list_pop_free(
    struct mptcp_rbs_value_skb_list_pop *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_pop_execute(
    struct mptcp_rbs_value_skb_list_pop *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct sk_buff *skb =
	    self->list->execute(self->list, ctx, &prev, &is_null);

	if (is_null || !skb)
		return NULL;

	/* after this point, we are sure that we execute a pop */
	ctx->side_effects = 1;

	if (self->list->underlying_queue_kind == VALUE_KIND_Q) {
		/*
		 * Pop an element from Q might be the queue_position or later
		 */
		if (skb == ctx->rbs_cb->queue_position) {
			mptcp_rbs_advance_send_head(
			    ctx->meta_sk, &ctx->rbs_cb->queue_position);
			mptcp_rbs_debug(
			    "rbs_q_pop returns %p, new queue head %p\n", skb,
			    ctx->rbs_cb->queue_position);
		} else {
			/* we can not unlink the packet, as all skbs have to
			 * stay in the circular buffer */
			mptcp_debug(
			    "%s sets not_in_queue for packet %p in Q, was %u\n",
			    __func__, skb,
			    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
			TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		}

		return skb;
	}

	if (self->list->underlying_queue_kind == VALUE_KIND_RQ) {
		mptcp_debug("%s sets not_in_queue, to_free and to_unlink for "
			    "packet %p in RQ, was %u\n",
			    __func__, skb,
			    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
		TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		TCP_SKB_CB(skb)->mptcp_rbs.flags_to_free = 1;
		TCP_SKB_CB(skb)->mptcp_rbs.flags_to_unlink = 1;

		return skb;
	}

	if (self->list->underlying_queue_kind == VALUE_KIND_QU) {
		mptcp_debug(
		    "%s sets not_in_queue for packet %p in QU, was %u\n",
		    __func__, skb,
		    TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue);
		TCP_SKB_CB(skb)->mptcp_rbs.flags_not_in_queue = 1;
		return skb;
	}

	mptcp_rbs_debug("mptcp_rbs_value_skb_list_pop_execute on "
			"unexpected list kind %u\n",
			self->list->kind);
	return NULL;
}

struct mptcp_rbs_value_skb_list_pop *mptcp_rbs_value_skb_list_pop_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_pop *value)
{
	struct mptcp_rbs_value_skb_list_pop *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_pop), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_skb_list_pop_print(
    const struct mptcp_rbs_value_skb_list_pop *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".POP()");
	return len;
}

struct mptcp_rbs_value_skb_list_filter *mptcp_rbs_value_skb_list_filter_new(
    void)
{
	struct mptcp_rbs_value_skb_list_filter *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_filter), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_FILTER;
	value->free = mptcp_rbs_value_skb_list_filter_free;
	value->execute = mptcp_rbs_value_skb_list_filter_execute;
	/* value->list and value->cond are set later */

	return value;
}

void mptcp_rbs_value_skb_list_filter_free(
    struct mptcp_rbs_value_skb_list_filter *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->cond);
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_filter_execute(
    struct mptcp_rbs_value_skb_list_filter *self,
    struct mptcp_rbs_eval_ctx *ctx, void **prev, bool *is_null)
{
	struct sk_buff *skb;
	s32 b;

	skb = self->list->execute(self->list, ctx, prev, is_null);
	if (*is_null)
		return NULL;

	while (skb) {
		self->progress.cur = skb;
		b = self->cond->execute(self->cond, ctx);
		if (b > 0)
			break;

		skb = self->list->execute(self->list, ctx, prev, is_null);
	}

	return skb;
}

struct mptcp_rbs_value_skb_list_filter *mptcp_rbs_value_skb_list_filter_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_filter *value)
{
	struct mptcp_rbs_value_skb_list_filter *clone;
	int i;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_filter), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	for (i = 0; i < MAX_NESTING; ++i) {
		if (!ctx->repls[i].repl)
			break;
	}
	BUG_ON(i == MAX_NESTING);

	ctx->repls[i].repl = &value->progress;
	ctx->repls[i].repl_with = &clone->progress;
	CLONE(clone->cond);
	ctx->repls[i].repl = NULL;

	return clone;
}

int mptcp_rbs_value_skb_list_filter_print(
    const struct mptcp_rbs_value_skb_list_filter *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".FILTER(v%p => ", &value->progress);

	tmp_len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->cond, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");
	return len;
}

struct mptcp_rbs_value_skb_list_filter_skb *
mptcp_rbs_value_skb_list_filter_skb_new(
    struct mptcp_rbs_value_skb_list_filter_progress *progress)
{
	struct mptcp_rbs_value_skb_list_filter_skb *value;

	value = kzalloc(sizeof(struct mptcp_rbs_value_skb_list_filter_skb),
			GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_FILTER_SKB;
	value->free = mptcp_rbs_value_skb_list_filter_skb_free;
	value->execute = mptcp_rbs_value_skb_list_filter_skb_execute;
	value->progress = progress;
	value->reinject = progress->reinject;

	return value;
}

void mptcp_rbs_value_skb_list_filter_skb_free(
    struct mptcp_rbs_value_skb_list_filter_skb *self)
{
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_filter_skb_execute(
    struct mptcp_rbs_value_skb_list_filter_skb *self,
    struct mptcp_rbs_eval_ctx *ctx)
{
	return self->progress->cur;
}

struct mptcp_rbs_value_skb_list_filter_skb *
mptcp_rbs_value_skb_list_filter_skb_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_filter_skb *value)
{
	struct mptcp_rbs_value_skb_list_filter_skb *clone;
	int i;

	clone = kmalloc(sizeof(struct mptcp_rbs_value_skb_list_filter_skb),
			GFP_KERNEL);
	*clone = *value;

	for (i = 0; i < MAX_NESTING; ++i) {
		if (clone->progress == ctx->repls[i].repl) {
			clone->progress = ctx->repls[i].repl_with;
			break;
		}
	}
	BUG_ON(i == MAX_NESTING);

	return clone;
}

int mptcp_rbs_value_skb_list_filter_skb_print(
    const struct mptcp_rbs_value_skb_list_filter_skb *value, char *buffer)
{
	return sprintf_null(&buffer, "v%p", value->progress);
}

struct mptcp_rbs_value_skb_list_count *mptcp_rbs_value_skb_list_count_new(
    struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_value_skb_list_count *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_count), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_COUNT;
	value->free = mptcp_rbs_value_skb_list_count_free;
	value->execute = mptcp_rbs_value_skb_list_count_execute;
	value->list = list;

	return value;
}

void mptcp_rbs_value_skb_list_count_free(
    struct mptcp_rbs_value_skb_list_count *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

s64 mptcp_rbs_value_skb_list_count_execute(
    struct mptcp_rbs_value_skb_list_count *self, struct mptcp_rbs_eval_ctx *ctx)
{
	struct sk_buff *skb;
	void *prev = NULL;
	bool is_null;
	int n = 0;

	skb = self->list->execute(self->list, ctx, &prev, &is_null);
	if (is_null)
		return -1;

	while (skb) {
		++n;
		skb = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return n;
}

struct mptcp_rbs_value_skb_list_count *mptcp_rbs_value_skb_list_count_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_count *value)
{
	struct mptcp_rbs_value_skb_list_count *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_count), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_skb_list_count_print(
    const struct mptcp_rbs_value_skb_list_count *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".COUNT");
	return len;
}

struct mptcp_rbs_value_skb_list_top *mptcp_rbs_value_skb_list_top_new(
    struct mptcp_rbs_value_skb_list *list)
{
	struct mptcp_rbs_value_skb_list_top *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_top), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_TOP;
	value->free = mptcp_rbs_value_skb_list_top_free;
	value->execute = mptcp_rbs_value_skb_list_top_execute;
	value->list = list;
	value->reinject = list->underlying_queue_kind == VALUE_KIND_RQ;

	return value;
}

void mptcp_rbs_value_skb_list_top_free(
    struct mptcp_rbs_value_skb_list_top *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_top_execute(
    struct mptcp_rbs_value_skb_list_top *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct sk_buff *skb =
	    self->list->execute(self->list, ctx, &prev, &is_null);

	/*
	 * IMPORTANT: do not unset TCP_SKB_CB(skb)->mptcp_rbs_... here!
	 * only POP might set it, once it is set, it remains forever!
	 */

	if (is_null)
		return NULL;

	return skb;
}

struct mptcp_rbs_value_skb_list_top *mptcp_rbs_value_skb_list_top_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_top *value)
{
	struct mptcp_rbs_value_skb_list_top *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_top), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);

	return clone;
}

int mptcp_rbs_value_skb_list_top_print(
    const struct mptcp_rbs_value_skb_list_top *value, char *buffer)
{
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".TOP");
	return len;
}

struct mptcp_rbs_value_skb_list_get *mptcp_rbs_value_skb_list_get_new(
    struct mptcp_rbs_value_skb_list *list, struct mptcp_rbs_value_int *index)
{
	struct mptcp_rbs_value_skb_list_get *value;

	value =
	    kzalloc(sizeof(struct mptcp_rbs_value_skb_list_get), GFP_KERNEL);
	value->kind = VALUE_KIND_SKBLIST_GET;
	value->free = mptcp_rbs_value_skb_list_get_free;
	value->execute = mptcp_rbs_value_skb_list_get_execute;
	value->list = list;
	value->index = index;

	return value;
}

void mptcp_rbs_value_skb_list_get_free(
    struct mptcp_rbs_value_skb_list_get *self)
{
	MPTCP_RBS_VALUE_FREE(self->list);
	MPTCP_RBS_VALUE_FREE(self->index);
	kfree(self);
}

struct sk_buff *mptcp_rbs_value_skb_list_get_execute(
    struct mptcp_rbs_value_skb_list_get *self, struct mptcp_rbs_eval_ctx *ctx)
{
	void *prev = NULL;
	bool is_null;
	struct sk_buff *skb;
	s64 idx;

	skb  = self->list->execute(self->list, ctx, &prev, &is_null);
	idx = self->index->execute(self->index, ctx);

	/*
	 * IMPORTANT: do not unset TCP_SKB_CB(skb)->mptcp_rbs_... here!
	 * only POP might set it, once it is set, it remains forever!
	 */

	if (is_null || idx < 0)
		return NULL;

	while (skb && idx) {
		idx--;
		skb = self->list->execute(self->list, ctx, &prev, &is_null);
	}

	return skb;
}

struct mptcp_rbs_value_skb_list_get *mptcp_rbs_value_skb_list_get_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_get *value)
{
	struct mptcp_rbs_value_skb_list_get *clone;

	clone =
	    kmalloc(sizeof(struct mptcp_rbs_value_skb_list_get), GFP_KERNEL);
	*clone = *value;
	CLONE(clone->list);
	CLONE(clone->index);

	return clone;
}

int mptcp_rbs_value_skb_list_get_print(
    const struct mptcp_rbs_value_skb_list_get *value, char *buffer)
{
	int tmp_len;
	int len = mptcp_rbs_value_print(
	    (const struct mptcp_rbs_value *) value->list, buffer);
	if (buffer)
		buffer += len;

	len += sprintf_null(&buffer, ".GET(");

	tmp_len = mptcp_rbs_value_print(
		(const struct mptcp_rbs_value *) value->index, buffer);
	len += tmp_len;
	if (buffer)
		buffer += tmp_len;

	len += sprintf_null(&buffer, ")");

	return len;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
enum mptcp_rbs_type_kind mptcp_rbs_value_get_type(
    enum mptcp_rbs_value_kind kind)
{
	switch (kind) {
	/* Built-in values */
	case VALUE_KIND_CONSTINT:
		return TYPE_KIND_INT;
	case VALUE_KIND_CONSTSTRING:
		return TYPE_KIND_STRING;
	case VALUE_KIND_NULL:
		return TYPE_KIND_NULL;
	case VALUE_KIND_BOOL_VAR:
		return TYPE_KIND_BOOL;
	case VALUE_KIND_INT_VAR:
		return TYPE_KIND_INT;
	case VALUE_KIND_STRING_VAR:
		return TYPE_KIND_STRING;
	case VALUE_KIND_SBF_VAR:
		return TYPE_KIND_SBF;
	case VALUE_KIND_SBFLIST_VAR:
		return TYPE_KIND_SBFLIST;
	case VALUE_KIND_SKB_VAR:
		return TYPE_KIND_SKB;
	case VALUE_KIND_SKBLIST_VAR:
		return TYPE_KIND_SKBLIST;
	case VALUE_KIND_NOT:
	case VALUE_KIND_EQUAL:
	case VALUE_KIND_UNEQUAL:
	case VALUE_KIND_LESS:
	case VALUE_KIND_LESS_EQUAL:
	case VALUE_KIND_GREATER:
	case VALUE_KIND_GREATER_EQUAL:
	case VALUE_KIND_AND:
	case VALUE_KIND_OR:
		return TYPE_KIND_BOOL;
	case VALUE_KIND_ADD:
	case VALUE_KIND_SUBTRACT:
	case VALUE_KIND_MULTIPLY:
	case VALUE_KIND_DIVIDE:
	case VALUE_KIND_REMAINDER:
		return TYPE_KIND_INT;
	case VALUE_KIND_IS_NULL:
	case VALUE_KIND_IS_NOT_NULL:
		return TYPE_KIND_BOOL;
	case VALUE_KIND_REG:
		return TYPE_KIND_INT;
	case VALUE_KIND_SBFLIST_NEXT:
		return TYPE_KIND_SBF;
	case VALUE_KIND_SKBLIST_NEXT:
		return TYPE_KIND_SKB;

/* Custom values */
#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_GET_VALUE_TYPE(ENUM, STR, STRUCT, RETURNTYPE)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST
	}
}
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
struct mptcp_rbs_value *mptcp_rbs_value_clone_ex(
    struct mptcp_rbs_value_clone_ctx *ctx, const struct mptcp_rbs_value *value)
{
	if (ctx->user_func) {
		struct mptcp_rbs_value *clone;

		clone = ctx->user_func(ctx->user_ctx, value);
		if (clone)
			return clone;
	}

	switch (value->kind) {
		/* Built-in values */
		APPLY_CLONE_VALUE(VALUE_KIND_CONSTINT, ,
				  mptcp_rbs_value_constint, )
		APPLY_CLONE_VALUE(VALUE_KIND_CONSTSTRING, ,
				  mptcp_rbs_value_conststring, )
		APPLY_CLONE_VALUE(VALUE_KIND_NULL, , mptcp_rbs_value_null, )
		APPLY_CLONE_VALUE(VALUE_KIND_BOOL_VAR, ,
				  mptcp_rbs_value_bool_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_INT_VAR, ,
				  mptcp_rbs_value_int_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_STRING_VAR, ,
				  mptcp_rbs_value_string_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_SBF_VAR, ,
				  mptcp_rbs_value_sbf_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_SBFLIST_VAR, ,
				  mptcp_rbs_value_sbf_list_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_SKB_VAR, ,
				  mptcp_rbs_value_skb_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_SKBLIST_VAR, ,
				  mptcp_rbs_value_skb_list_var, )
		APPLY_CLONE_VALUE(VALUE_KIND_NOT, , mptcp_rbs_value_not, )
		APPLY_CLONE_VALUE(VALUE_KIND_EQUAL, , mptcp_rbs_value_equal, )
		APPLY_CLONE_VALUE(VALUE_KIND_UNEQUAL, ,
				  mptcp_rbs_value_unequal, )
		APPLY_CLONE_VALUE(VALUE_KIND_LESS, , mptcp_rbs_value_less, )
		APPLY_CLONE_VALUE(VALUE_KIND_LESS_EQUAL, ,
				  mptcp_rbs_value_less_equal, )
		APPLY_CLONE_VALUE(VALUE_KIND_GREATER, ,
				  mptcp_rbs_value_greater, )
		APPLY_CLONE_VALUE(VALUE_KIND_GREATER_EQUAL, ,
				  mptcp_rbs_value_greater_equal, )
		APPLY_CLONE_VALUE(VALUE_KIND_AND, , mptcp_rbs_value_and, )
		APPLY_CLONE_VALUE(VALUE_KIND_OR, , mptcp_rbs_value_or, )
		APPLY_CLONE_VALUE(VALUE_KIND_ADD, , mptcp_rbs_value_add, )
		APPLY_CLONE_VALUE(VALUE_KIND_SUBTRACT, ,
				  mptcp_rbs_value_subtract, )
		APPLY_CLONE_VALUE(VALUE_KIND_MULTIPLY, ,
				  mptcp_rbs_value_multiply, )
		APPLY_CLONE_VALUE(VALUE_KIND_DIVIDE, , mptcp_rbs_value_divide, )
		APPLY_CLONE_VALUE(VALUE_KIND_REMAINDER, ,
				  mptcp_rbs_value_remainder, )
		APPLY_CLONE_VALUE(VALUE_KIND_IS_NULL, ,
				  mptcp_rbs_value_is_null, )
		APPLY_CLONE_VALUE(VALUE_KIND_IS_NOT_NULL, ,
				  mptcp_rbs_value_is_not_null, )
		APPLY_CLONE_VALUE(VALUE_KIND_REG, , mptcp_rbs_value_reg, )
		APPLY_CLONE_VALUE(VALUE_KIND_SBFLIST_NEXT, ,
				  mptcp_rbs_value_sbf_list_next, )
		APPLY_CLONE_VALUE(VALUE_KIND_SKBLIST_NEXT, ,
				  mptcp_rbs_value_skb_list_next, )

/* Custom values */
#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_CLONE_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST
	}
}
#pragma GCC diagnostic pop

struct mptcp_rbs_value *mptcp_rbs_value_clone(
    const struct mptcp_rbs_value *value, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func)
{
	struct mptcp_rbs_value_clone_ctx ctx;

	memset(&ctx, 0, sizeof(struct mptcp_rbs_value_clone_ctx));
	ctx.user_ctx = user_ctx;
	ctx.user_func = user_func;
	return mptcp_rbs_value_clone_ex(&ctx, value);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#pragma GCC diagnostic ignored "-Wreturn-type"
int mptcp_rbs_value_print(const struct mptcp_rbs_value *value, char *buffer)
{
	switch (value->kind) {
		/* Built-in values */
		APPLY_PRINT_VALUE(VALUE_KIND_CONSTINT, ,
				  mptcp_rbs_value_constint, )
		APPLY_PRINT_VALUE(VALUE_KIND_CONSTSTRING, ,
				  mptcp_rbs_value_conststring, )
		APPLY_PRINT_VALUE(VALUE_KIND_NULL, , mptcp_rbs_value_null, )
		APPLY_PRINT_VALUE(VALUE_KIND_BOOL_VAR, ,
				  mptcp_rbs_value_bool_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_INT_VAR, ,
				  mptcp_rbs_value_int_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_STRING_VAR, ,
				  mptcp_rbs_value_string_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_SBF_VAR, ,
				  mptcp_rbs_value_sbf_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_SBFLIST_VAR, ,
				  mptcp_rbs_value_sbf_list_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_SKB_VAR, ,
				  mptcp_rbs_value_skb_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_SKBLIST_VAR, ,
				  mptcp_rbs_value_skb_list_var, )
		APPLY_PRINT_VALUE(VALUE_KIND_NOT, , mptcp_rbs_value_not, )
		APPLY_PRINT_VALUE(VALUE_KIND_EQUAL, , mptcp_rbs_value_equal, )
		APPLY_PRINT_VALUE(VALUE_KIND_UNEQUAL, ,
				  mptcp_rbs_value_unequal, )
		APPLY_PRINT_VALUE(VALUE_KIND_LESS, , mptcp_rbs_value_less, )
		APPLY_PRINT_VALUE(VALUE_KIND_LESS_EQUAL, ,
				  mptcp_rbs_value_less_equal, )
		APPLY_PRINT_VALUE(VALUE_KIND_GREATER, ,
				  mptcp_rbs_value_greater, )
		APPLY_PRINT_VALUE(VALUE_KIND_GREATER_EQUAL, ,
				  mptcp_rbs_value_greater_equal, )
		APPLY_PRINT_VALUE(VALUE_KIND_AND, , mptcp_rbs_value_and, )
		APPLY_PRINT_VALUE(VALUE_KIND_OR, , mptcp_rbs_value_or, )
		APPLY_PRINT_VALUE(VALUE_KIND_ADD, , mptcp_rbs_value_add, )
		APPLY_PRINT_VALUE(VALUE_KIND_SUBTRACT, ,
				  mptcp_rbs_value_subtract, )
		APPLY_PRINT_VALUE(VALUE_KIND_MULTIPLY, ,
				  mptcp_rbs_value_multiply, )
		APPLY_PRINT_VALUE(VALUE_KIND_DIVIDE, , mptcp_rbs_value_divide, )
		APPLY_PRINT_VALUE(VALUE_KIND_REMAINDER, ,
				  mptcp_rbs_value_remainder, )
		APPLY_PRINT_VALUE(VALUE_KIND_IS_NULL, ,
				  mptcp_rbs_value_is_null, )
		APPLY_PRINT_VALUE(VALUE_KIND_IS_NOT_NULL, ,
				  mptcp_rbs_value_is_not_null, )
		APPLY_PRINT_VALUE(VALUE_KIND_REG, , mptcp_rbs_value_reg, )
		APPLY_PRINT_VALUE(VALUE_KIND_SBFLIST_NEXT, ,
				  mptcp_rbs_value_sbf_list_next, )
		APPLY_PRINT_VALUE(VALUE_KIND_SKBLIST_NEXT, ,
				  mptcp_rbs_value_skb_list_next, )

/* Custom values */
#define RBS_APPLY(ENUM, STR, STRUCT, RETURNTYPE)                               \
	APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SBF_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB(ENUM, STR, STRUCT, RETURNTYPE)                        \
	APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
#define RBS_APPLY_ON_SKB_LIST(ENUM, STR, STRUCT, RETURNTYPE)                   \
	APPLY_PRINT_VALUE(ENUM, STR, STRUCT, RETURNTYPE)
		MPTCP_RBS_VALUE_INFO
#undef RBS_APPLY
#undef RBS_APPLY_ON_SBF
#undef RBS_APPLY_ON_SBF_LIST
#undef RBS_APPLY_ON_SKB
#undef RBS_APPLY_ON_SKB_LIST
	}
}
#pragma GCC diagnostic pop
