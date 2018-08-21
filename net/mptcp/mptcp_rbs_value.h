#ifndef _MPTCP_RBS_AST_H
#define _MPTCP_RBS_AST_H

#include "mptcp_rbs_type.h"
#include <linux/types.h>

struct mptcp_rbs_eval_ctx;
struct mptcp_rbs_sbf_cb;
struct mptcp_rbs_value_clone_ctx;
struct sk_buff_head;

/*
 * The following macro describes all values that can be parsed.
 * To add a value add a new line to the macro with the following content:
 * <RBS_APPLY macro>(
 *   <enum item of the value (see mptcp_rbs_value_kind)>,
 *   <string for the parser>,
 *   <name of the struct the value needs>,
 *   <return type of the value (see mptcp_rbs_type_kind)>
 * )
 *
 * The <RBS_APPLY macro> determines the value on which the new value can be
 * applied. For example RQ.getvalue has the macro RBS_APPLY_ON_SKB_LIST because
 * getvalue is applied on RQ of type sockbuffer list. Possible macros are:
 * RBS_APPLY if the value needs no other value to be applied
 * RBS_APPLY_ON_SBF
 * RBS_APPLY_ON_SBF_LIST
 * RBS_APPLY_ON_SKB
 * RBS_APPLY_ON_SKB_LIST
 */
#define MPTCP_RBS_VALUE_INFO                                                   \
	RBS_APPLY(VALUE_KIND_Q, "Q", mptcp_rbs_value_q, TYPE_KIND_SKBLIST)     \
	RBS_APPLY(VALUE_KIND_QU, "QU", mptcp_rbs_value_qu, TYPE_KIND_SKBLIST)  \
	RBS_APPLY(VALUE_KIND_RQ, "RQ", mptcp_rbs_value_rq, TYPE_KIND_SKBLIST)  \
	RBS_APPLY(VALUE_KIND_SUBFLOWS, "SUBFLOWS", mptcp_rbs_value_subflows,   \
		  TYPE_KIND_SBFLIST)                                           \
	RBS_APPLY(VALUE_KIND_CURRENT_TIME_MS, "CURRENT_TIME_MS",               \
		  mptcp_rbs_value_current_time_ms, TYPE_KIND_INT)              \
	RBS_APPLY(VALUE_KIND_RANDOM, "RANDOM", mptcp_rbs_value_random,         \
		  TYPE_KIND_INT)                                               \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_RTT, "RTT", mptcp_rbs_value_sbf_rtt,   \
			 TYPE_KIND_INT)                                        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_RTT_MS, "RTT_MS", mptcp_rbs_value_sbf_rtt_ms,   \
			 TYPE_KIND_INT)                                        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_RTT_VAR, "RTT_VAR", mptcp_rbs_value_sbf_rtt_var,   \
			 TYPE_KIND_INT)                                        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_USER, "USER", mptcp_rbs_value_sbf_user,   \
			 TYPE_KIND_INT)        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_IS_BACKUP, "IS_BACKUP",                \
			 mptcp_rbs_value_sbf_is_backup, TYPE_KIND_BOOL)        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_CWND, "CWND",                          \
			 mptcp_rbs_value_sbf_cwnd, TYPE_KIND_INT)              \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_QUEUED, "QUEUED",		       \
			 mptcp_rbs_value_sbf_queued, TYPE_KIND_INT)            \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_SKBS_IN_FLIGHT, "SKBS_IN_FLIGHT",      \
			 mptcp_rbs_value_sbf_skbs_in_flight, TYPE_KIND_INT)    \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_LOST_SKBS, "LOST_SKBS",                \
			 mptcp_rbs_value_sbf_lost_skbs, TYPE_KIND_INT)         \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_HAS_WINDOW_FOR, "HAS_WINDOW_FOR",      \
			 mptcp_rbs_value_sbf_has_window_for, TYPE_KIND_BOOL)   \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_ID, "ID", mptcp_rbs_value_sbf_id,      \
			 TYPE_KIND_INT)                                        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_DELAY_IN, "DELAY_IN",                  \
			 mptcp_rbs_value_sbf_delay_in, TYPE_KIND_INT)          \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_DELAY_OUT, "DELAY_OUT",                \
			 mptcp_rbs_value_sbf_delay_out, TYPE_KIND_INT)         \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_BW_OUT_ACK, "BW_OUT_ACK",              \
			 mptcp_rbs_value_sbf_bw_out_ack, TYPE_KIND_INT)        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_BW_OUT_SEND, "BW_OUT_SEND",            \
			 mptcp_rbs_value_sbf_bw_out_send, TYPE_KIND_INT)       \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_SSTHRESH, "SSTHRESH",                  \
			 mptcp_rbs_value_sbf_ssthresh, TYPE_KIND_INT)          \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_THROTTLED, "THROTTLED",                \
			 mptcp_rbs_value_sbf_throttled, TYPE_KIND_BOOL)        \
	RBS_APPLY_ON_SBF(VALUE_KIND_SBF_LOSSY, "LOSSY",                        \
			 mptcp_rbs_value_sbf_lossy, TYPE_KIND_BOOL)            \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_EMPTY, "EMPTY",               \
			      mptcp_rbs_value_sbf_list_empty, TYPE_KIND_BOOL)  \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_FILTER, "FILTER",             \
			      mptcp_rbs_value_sbf_list_filter,                 \
			      TYPE_KIND_SBFLIST)                               \
	RBS_APPLY(VALUE_KIND_SBFLIST_FILTER_SBF, "",                           \
		  mptcp_rbs_value_sbf_list_filter_sbf, TYPE_KIND_SBF)          \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_MAX, "MAX",                   \
			      mptcp_rbs_value_sbf_list_max, TYPE_KIND_SBF)     \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_MIN, "MIN",                   \
			      mptcp_rbs_value_sbf_list_min, TYPE_KIND_SBF)     \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_GET, "GET",                   \
			      mptcp_rbs_value_sbf_list_get, TYPE_KIND_SBF)     \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_COUNT, "COUNT",               \
			      mptcp_rbs_value_sbf_list_count, TYPE_KIND_INT)   \
	RBS_APPLY_ON_SBF_LIST(VALUE_KIND_SBFLIST_SUM, "SUM",                   \
			      mptcp_rbs_value_sbf_list_sum, TYPE_KIND_INT)     \
	RBS_APPLY_ON_SKB(VALUE_KIND_SKB_SENT_ON, "SENT_ON",                    \
			 mptcp_rbs_value_skb_sent_on, TYPE_KIND_BOOL)          \
	RBS_APPLY_ON_SKB(VALUE_KIND_SKB_SENT_ON_ALL, "SENT_ON_ALL",            \
			 mptcp_rbs_value_skb_sent_on_all, TYPE_KIND_BOOL)      \
	RBS_APPLY_ON_SKB(VALUE_KIND_SKB_USER, "USER",                          \
			 mptcp_rbs_value_skb_user, TYPE_KIND_INT)              \
	RBS_APPLY_ON_SKB(VALUE_KIND_SKB_SEQ, "SEQ",                          \
			 mptcp_rbs_value_skb_seq, TYPE_KIND_INT)              \
    RBS_APPLY_ON_SKB(VALUE_KIND_SKB_PSH, "PSH",                          \
			 mptcp_rbs_value_skb_psh, TYPE_KIND_BOOL)              \
	RBS_APPLY_ON_SKB(VALUE_KIND_SKB_LENGTH, "LENGTH",                          \
			 mptcp_rbs_value_skb_length, TYPE_KIND_INT)              \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_EMPTY, "EMPTY",               \
			      mptcp_rbs_value_skb_list_empty, TYPE_KIND_BOOL)  \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_POP, "POP",                   \
			      mptcp_rbs_value_skb_list_pop, TYPE_KIND_SKB)     \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_FILTER, "FILTER",             \
			      mptcp_rbs_value_skb_list_filter,                 \
			      TYPE_KIND_SKBLIST)                               \
	RBS_APPLY(VALUE_KIND_SKBLIST_FILTER_SKB, "",                           \
		  mptcp_rbs_value_skb_list_filter_skb, TYPE_KIND_SKB)          \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_COUNT, "COUNT",               \
			      mptcp_rbs_value_skb_list_count, TYPE_KIND_INT)   \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_TOP, "TOP",                   \
			      mptcp_rbs_value_skb_list_top, TYPE_KIND_SKB)     \
	RBS_APPLY_ON_SKB_LIST(VALUE_KIND_SKBLIST_GET, "GET",		       \
			      mptcp_rbs_value_skb_list_get, TYPE_KIND_SKB)

enum mptcp_rbs_value_kind {
	/* Literals */
	VALUE_KIND_CONSTINT,
	VALUE_KIND_CONSTSTRING,
	VALUE_KIND_NULL,

	/* Used variables */
	VALUE_KIND_BOOL_VAR,
	VALUE_KIND_INT_VAR,
	VALUE_KIND_STRING_VAR,
	VALUE_KIND_SBF_VAR,
	VALUE_KIND_SBFLIST_VAR,
	VALUE_KIND_SKB_VAR,
	VALUE_KIND_SKBLIST_VAR,

	/* Operators */
	VALUE_KIND_NOT,
	VALUE_KIND_EQUAL,
	VALUE_KIND_UNEQUAL,
	VALUE_KIND_LESS,
	VALUE_KIND_LESS_EQUAL,
	VALUE_KIND_GREATER,
	VALUE_KIND_GREATER_EQUAL,
	VALUE_KIND_AND,
	VALUE_KIND_OR,
	VALUE_KIND_ADD,
	VALUE_KIND_SUBTRACT,
	VALUE_KIND_MULTIPLY,
	VALUE_KIND_DIVIDE,
	VALUE_KIND_REMAINDER,
	VALUE_KIND_IS_NULL,
	VALUE_KIND_IS_NOT_NULL,

	/* Registers */
	VALUE_KIND_REG,

	/* Functions & properties */
	VALUE_KIND_Q,
	VALUE_KIND_QU,
	VALUE_KIND_RQ,
	VALUE_KIND_SUBFLOWS,
	VALUE_KIND_CURRENT_TIME_MS,
	VALUE_KIND_RANDOM,

	/* Functions & properties on subflows */
	VALUE_KIND_SBF_RTT,
	VALUE_KIND_SBF_RTT_MS,
	VALUE_KIND_SBF_RTT_VAR,
	VALUE_KIND_SBF_USER,
	VALUE_KIND_SBF_IS_BACKUP,
	VALUE_KIND_SBF_CWND,
	VALUE_KIND_SBF_QUEUED,
	VALUE_KIND_SBF_SKBS_IN_FLIGHT,
	VALUE_KIND_SBF_LOST_SKBS,
	VALUE_KIND_SBF_HAS_WINDOW_FOR,
	VALUE_KIND_SBF_ID,
	VALUE_KIND_SBF_DELAY_IN,
	VALUE_KIND_SBF_DELAY_OUT,
	VALUE_KIND_SBF_BW_OUT_SEND,
	VALUE_KIND_SBF_BW_OUT_ACK,
	VALUE_KIND_SBF_SSTHRESH,
	VALUE_KIND_SBF_THROTTLED,
	VALUE_KIND_SBF_LOSSY,

	/* Functions & properties on subflow lists */
	VALUE_KIND_SBFLIST_NEXT,
	VALUE_KIND_SBFLIST_EMPTY,
	VALUE_KIND_SBFLIST_FILTER,
	VALUE_KIND_SBFLIST_FILTER_SBF,
	VALUE_KIND_SBFLIST_MAX,
	VALUE_KIND_SBFLIST_MIN,
	VALUE_KIND_SBFLIST_GET,
	VALUE_KIND_SBFLIST_COUNT,
	VALUE_KIND_SBFLIST_SUM,

	/* Functions & properties on sockbuffers */
	VALUE_KIND_SKB_SENT_ON,
	VALUE_KIND_SKB_SENT_ON_ALL,
	VALUE_KIND_SKB_USER,
	VALUE_KIND_SKB_SEQ,
    VALUE_KIND_SKB_PSH,
	VALUE_KIND_SKB_LENGTH,

	/* Functions & properties on sockbuffer lists */
	VALUE_KIND_SKBLIST_NEXT,
	VALUE_KIND_SKBLIST_EMPTY,
	VALUE_KIND_SKBLIST_POP,
	VALUE_KIND_SKBLIST_FILTER,
	VALUE_KIND_SKBLIST_FILTER_SKB,
	VALUE_KIND_SKBLIST_COUNT,
	VALUE_KIND_SKBLIST_TOP,
	VALUE_KIND_SKBLIST_GET
};

/* Macro to release values */
#define MPTCP_RBS_VALUE_FREE(val)                                              \
	if (val)                                                               \
		val->free(val);

/*
 * Base struct for all values
 */
struct mptcp_rbs_value {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value *self);
};

/*
 * Base struct for boolean values. The execute function returns -1 on null, 0 on
 * false and 1 on true
 */
struct mptcp_rbs_value_bool {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_bool *self);
	s32 (*execute)(struct mptcp_rbs_value_bool *self,
		       struct mptcp_rbs_eval_ctx *ctx);
};

/*
 * Base struct for integer values. The execute function returns -1 on null and
 * positive values < 2^32 on success
 */
struct mptcp_rbs_value_int {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_int *self);
	s64 (*execute)(struct mptcp_rbs_value_int *self,
		       struct mptcp_rbs_eval_ctx *ctx);
};

/*
 * Base struct for string values. The execute function returns NULL on null
 */
struct mptcp_rbs_value_string {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_string *self);
	char *(*execute)(struct mptcp_rbs_value_string *self,
			 struct mptcp_rbs_eval_ctx *ctx);
};

/*
 * Base struct for subflow values. The execute function returns NULL on null
 */
struct mptcp_rbs_value_sbf {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf *self,
				    struct mptcp_rbs_eval_ctx *ctx);
};

/*
 * Base struct for subflow list values
 */
struct mptcp_rbs_value_sbf_list {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list *self,
				    struct mptcp_rbs_eval_ctx *ctx, void **prev,
				    bool *is_null);
};

/*
 * Base struct for sockbuffer values. The execute function returns NULL on null
 */
struct mptcp_rbs_value_skb {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
};

/*
 * Base struct for sockbuffer list values
 */
struct mptcp_rbs_value_skb_list {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
};

/*
 * Integer literal value
 */
struct mptcp_rbs_value_constint {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_constint *self);
	s64 (*execute)(struct mptcp_rbs_value_constint *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	unsigned int value;
};

struct mptcp_rbs_value_constint *mptcp_rbs_value_constint_new(unsigned int num);
void mptcp_rbs_value_constint_free(struct mptcp_rbs_value_constint *self);
s64 mptcp_rbs_value_constint_execute(struct mptcp_rbs_value_constint *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_constint *mptcp_rbs_value_constint_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_constint *value);
int mptcp_rbs_value_constint_print(const struct mptcp_rbs_value_constint *value,
				   char *buffer);

/*
 * String literal value
 */
struct mptcp_rbs_value_conststring {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_conststring *self);
	char *(*execute)(struct mptcp_rbs_value_conststring *self,
			 struct mptcp_rbs_eval_ctx *ctx);
	char *value;
};

struct mptcp_rbs_value_conststring *mptcp_rbs_value_conststring_new(char *str);
void mptcp_rbs_value_conststring_free(struct mptcp_rbs_value_conststring *self);
char *mptcp_rbs_value_conststring_execute(
    struct mptcp_rbs_value_conststring *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_conststring *mptcp_rbs_value_conststring_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_conststring *value);
int mptcp_rbs_value_conststring_print(
    const struct mptcp_rbs_value_conststring *value, char *buffer);

/*
 * NULL literal value
 */
struct mptcp_rbs_value_null {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_null *self);
	s32 (*execute)(struct mptcp_rbs_value_null *self,
		       struct mptcp_rbs_eval_ctx *ctx);
};

struct mptcp_rbs_value_null *mptcp_rbs_value_null_new(void);
void mptcp_rbs_value_null_free(struct mptcp_rbs_value_null *self);
s32 mptcp_rbs_value_null_execute(struct mptcp_rbs_value_null *self,
				 struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_null *mptcp_rbs_value_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_null *value);
int mptcp_rbs_value_null_print(const struct mptcp_rbs_value_null *value,
			       char *buffer);

/*
 * Boolean variable value
 */
struct mptcp_rbs_value_bool_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_bool_var *self);
	s32 (*execute)(struct mptcp_rbs_value_bool_var *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	int var_number;
};

struct mptcp_rbs_value_bool_var *mptcp_rbs_value_bool_var_new(int var_number);
void mptcp_rbs_value_bool_var_free(struct mptcp_rbs_value_bool_var *self);
s32 mptcp_rbs_value_bool_var_execute(struct mptcp_rbs_value_bool_var *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_bool_var *mptcp_rbs_value_bool_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_bool_var *value);
int mptcp_rbs_value_bool_var_print(const struct mptcp_rbs_value_bool_var *value,
				   char *buffer);

/*
 * Integer variable value
 */
struct mptcp_rbs_value_int_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_int_var *self);
	s64 (*execute)(struct mptcp_rbs_value_int_var *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	int var_number;
};

struct mptcp_rbs_value_int_var *mptcp_rbs_value_int_var_new(int var_number);
void mptcp_rbs_value_int_var_free(struct mptcp_rbs_value_int_var *self);
s64 mptcp_rbs_value_int_var_execute(struct mptcp_rbs_value_int_var *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_int_var *mptcp_rbs_value_int_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_int_var *value);
int mptcp_rbs_value_int_var_print(const struct mptcp_rbs_value_int_var *value,
				  char *buffer);

/*
 * String variable value
 */
struct mptcp_rbs_value_string_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_string_var *self);
	char *(*execute)(struct mptcp_rbs_value_string_var *self,
			 struct mptcp_rbs_eval_ctx *ctx);
	int var_number;
};

struct mptcp_rbs_value_string_var *mptcp_rbs_value_string_var_new(
    int var_number);
void mptcp_rbs_value_string_var_free(struct mptcp_rbs_value_string_var *self);
char *mptcp_rbs_value_string_var_execute(
    struct mptcp_rbs_value_string_var *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_string_var *mptcp_rbs_value_string_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_string_var *value);
int mptcp_rbs_value_string_var_print(
    const struct mptcp_rbs_value_string_var *value, char *buffer);

/*
 * Subflow variable value
 */
struct mptcp_rbs_value_sbf_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_var *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_var *self,
				    struct mptcp_rbs_eval_ctx *ctx);
	int var_number;
};

struct mptcp_rbs_value_sbf_var *mptcp_rbs_value_sbf_var_new(int var_number);
void mptcp_rbs_value_sbf_var_free(struct mptcp_rbs_value_sbf_var *self);
struct tcp_sock *mptcp_rbs_value_sbf_var_execute(
    struct mptcp_rbs_value_sbf_var *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_var *mptcp_rbs_value_sbf_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_var *value);
int mptcp_rbs_value_sbf_var_print(const struct mptcp_rbs_value_sbf_var *value,
				  char *buffer);

/*
 * Subflow list variable value
 */
struct mptcp_rbs_value_sbf_list_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_var *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list_var *self,
				    struct mptcp_rbs_eval_ctx *ctx, void **prev,
				    bool *is_null);
	int var_number;
};

struct mptcp_rbs_value_sbf_list_var *mptcp_rbs_value_sbf_list_var_new(
    int var_number);
void mptcp_rbs_value_sbf_list_var_free(
    struct mptcp_rbs_value_sbf_list_var *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_var_execute(
    struct mptcp_rbs_value_sbf_list_var *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null);
struct mptcp_rbs_value_sbf_list_var *mptcp_rbs_value_sbf_list_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_var *value);
int mptcp_rbs_value_sbf_list_var_print(
    const struct mptcp_rbs_value_sbf_list_var *value, char *buffer);

/*
 * Sockbuffer variable value
 */
struct mptcp_rbs_value_skb_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_var *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_var *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
	int var_number;
};

struct mptcp_rbs_value_skb_var *mptcp_rbs_value_skb_var_new(int var_number,
							    bool reinject);
void mptcp_rbs_value_skb_var_free(struct mptcp_rbs_value_skb_var *self);
struct sk_buff *mptcp_rbs_value_skb_var_execute(
    struct mptcp_rbs_value_skb_var *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_var *mptcp_rbs_value_skb_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_var *value);
int mptcp_rbs_value_skb_var_print(const struct mptcp_rbs_value_skb_var *value,
				  char *buffer);

/*
 * Sockbuffer list variable value
 */
struct mptcp_rbs_value_skb_list_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_var *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_var *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
	int var_number;
};

struct mptcp_rbs_value_skb_list_var *mptcp_rbs_value_skb_list_var_new(
    int var_number, enum mptcp_rbs_value_kind underlying_queue_kind);
void mptcp_rbs_value_skb_list_var_free(
    struct mptcp_rbs_value_skb_list_var *self);
struct sk_buff *mptcp_rbs_value_skb_list_var_execute(
    struct mptcp_rbs_value_skb_list_var *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null);
struct mptcp_rbs_value_skb_list_var *mptcp_rbs_value_skb_list_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_var *value);
int mptcp_rbs_value_skb_list_var_print(
    const struct mptcp_rbs_value_skb_list_var *value, char *buffer);

/*
 * NOT operator value
 */
struct mptcp_rbs_value_not {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_not *self);
	s32 (*execute)(struct mptcp_rbs_value_not *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_bool *operand;
};

struct mptcp_rbs_value_not *mptcp_rbs_value_not_new(
    struct mptcp_rbs_value_bool *operand);
void mptcp_rbs_value_not_free(struct mptcp_rbs_value_not *self);
s32 mptcp_rbs_value_not_execute(struct mptcp_rbs_value_not *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_not *mptcp_rbs_value_not_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_not *value);
int mptcp_rbs_value_not_print(const struct mptcp_rbs_value_not *value,
			      char *buffer);

/*
 * == operator value
 */
struct mptcp_rbs_value_equal {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_equal *self);
	s32 (*execute)(struct mptcp_rbs_value_equal *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_equal *mptcp_rbs_value_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_equal_free(struct mptcp_rbs_value_equal *self);
s32 mptcp_rbs_value_equal_execute(struct mptcp_rbs_value_equal *self,
				  struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_equal *mptcp_rbs_value_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_equal *value);
int mptcp_rbs_value_equal_print(const struct mptcp_rbs_value_equal *value,
				char *buffer);

/*
 * != operator value
 */
struct mptcp_rbs_value_unequal {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_unequal *self);
	s32 (*execute)(struct mptcp_rbs_value_unequal *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_unequal *mptcp_rbs_value_unequal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_unequal_free(struct mptcp_rbs_value_unequal *self);
s32 mptcp_rbs_value_unequal_execute(struct mptcp_rbs_value_unequal *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_unequal *mptcp_rbs_value_unequal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_unequal *value);
int mptcp_rbs_value_unequal_print(const struct mptcp_rbs_value_unequal *value,
				  char *buffer);

/*
 * < operator value
 */
struct mptcp_rbs_value_less {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_less *self);
	s32 (*execute)(struct mptcp_rbs_value_less *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_less *mptcp_rbs_value_less_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_less_free(struct mptcp_rbs_value_less *self);
s32 mptcp_rbs_value_less_execute(struct mptcp_rbs_value_less *self,
				 struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_less *mptcp_rbs_value_less_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_less *value);
int mptcp_rbs_value_less_print(const struct mptcp_rbs_value_less *value,
			       char *buffer);

/*
 * <= operator value
 */
struct mptcp_rbs_value_less_equal {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_less_equal *self);
	s32 (*execute)(struct mptcp_rbs_value_less_equal *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_less_equal *mptcp_rbs_value_less_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_less_equal_free(struct mptcp_rbs_value_less_equal *self);
s32 mptcp_rbs_value_less_equal_execute(struct mptcp_rbs_value_less_equal *self,
				       struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_less_equal *mptcp_rbs_value_less_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_less_equal *value);
int mptcp_rbs_value_less_equal_print(
    const struct mptcp_rbs_value_less_equal *value, char *buffer);

/*
 * > operator value
 */
struct mptcp_rbs_value_greater {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_greater *self);
	s32 (*execute)(struct mptcp_rbs_value_greater *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_greater *mptcp_rbs_value_greater_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_greater_free(struct mptcp_rbs_value_greater *self);
s32 mptcp_rbs_value_greater_execute(struct mptcp_rbs_value_greater *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_greater *mptcp_rbs_value_greater_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_greater *value);
int mptcp_rbs_value_greater_print(const struct mptcp_rbs_value_greater *value,
				  char *buffer);

/*
 * >= operator value
 */
struct mptcp_rbs_value_greater_equal {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_greater_equal *self);
	s32 (*execute)(struct mptcp_rbs_value_greater_equal *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_greater_equal *mptcp_rbs_value_greater_equal_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_greater_equal_free(
    struct mptcp_rbs_value_greater_equal *self);
s32 mptcp_rbs_value_greater_equal_execute(
    struct mptcp_rbs_value_greater_equal *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_greater_equal *mptcp_rbs_value_greater_equal_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_greater_equal *value);
int mptcp_rbs_value_greater_equal_print(
    const struct mptcp_rbs_value_greater_equal *value, char *buffer);

/*
 * AND operator value
 */
struct mptcp_rbs_value_and {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_and *self);
	s32 (*execute)(struct mptcp_rbs_value_and *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_bool *left_operand;
	struct mptcp_rbs_value_bool *right_operand;
};

struct mptcp_rbs_value_and *mptcp_rbs_value_and_new(
    struct mptcp_rbs_value_bool *left_operand,
    struct mptcp_rbs_value_bool *right_operand);
void mptcp_rbs_value_and_free(struct mptcp_rbs_value_and *self);
s32 mptcp_rbs_value_and_execute(struct mptcp_rbs_value_and *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_and *mptcp_rbs_value_and_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_and *value);
int mptcp_rbs_value_and_print(const struct mptcp_rbs_value_and *value,
			      char *buffer);

/*
 * OR operator value
 */
struct mptcp_rbs_value_or {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_or *self);
	s32 (*execute)(struct mptcp_rbs_value_or *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_bool *left_operand;
	struct mptcp_rbs_value_bool *right_operand;
};

struct mptcp_rbs_value_or *mptcp_rbs_value_or_new(
    struct mptcp_rbs_value_bool *left_operand,
    struct mptcp_rbs_value_bool *right_operand);
void mptcp_rbs_value_or_free(struct mptcp_rbs_value_or *self);
s32 mptcp_rbs_value_or_execute(struct mptcp_rbs_value_or *self,
			       struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_or *mptcp_rbs_value_or_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_or *value);
int mptcp_rbs_value_or_print(const struct mptcp_rbs_value_or *value,
			     char *buffer);

/*
 * + operator value
 */
struct mptcp_rbs_value_add {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_add *self);
	s64 (*execute)(struct mptcp_rbs_value_add *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_add *mptcp_rbs_value_add_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_add_free(struct mptcp_rbs_value_add *self);
s64 mptcp_rbs_value_add_execute(struct mptcp_rbs_value_add *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_add *mptcp_rbs_value_add_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_add *value);
int mptcp_rbs_value_add_print(const struct mptcp_rbs_value_add *value,
			      char *buffer);

/*
 * - operator value
 */
struct mptcp_rbs_value_subtract {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_subtract *self);
	s64 (*execute)(struct mptcp_rbs_value_subtract *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_subtract *mptcp_rbs_value_subtract_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_subtract_free(struct mptcp_rbs_value_subtract *self);
s64 mptcp_rbs_value_subtract_execute(struct mptcp_rbs_value_subtract *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_subtract *mptcp_rbs_value_subtract_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_subtract *value);
int mptcp_rbs_value_subtract_print(const struct mptcp_rbs_value_subtract *value,
				   char *buffer);

/*
 * * operator value
 */
struct mptcp_rbs_value_multiply {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_multiply *self);
	s64 (*execute)(struct mptcp_rbs_value_multiply *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_multiply *mptcp_rbs_value_multiply_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_multiply_free(struct mptcp_rbs_value_multiply *self);
s64 mptcp_rbs_value_multiply_execute(struct mptcp_rbs_value_multiply *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_multiply *mptcp_rbs_value_multiply_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_multiply *value);
int mptcp_rbs_value_multiply_print(const struct mptcp_rbs_value_multiply *value,
				   char *buffer);

/*
 * / operator value
 */
struct mptcp_rbs_value_divide {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_divide *self);
	s64 (*execute)(struct mptcp_rbs_value_divide *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_divide *mptcp_rbs_value_divide_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_divide_free(struct mptcp_rbs_value_divide *self);
s64 mptcp_rbs_value_divide_execute(struct mptcp_rbs_value_divide *self,
				   struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_divide *mptcp_rbs_value_divide_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_divide *value);
int mptcp_rbs_value_divide_print(const struct mptcp_rbs_value_divide *value,
				 char *buffer);

/*
 * % operator value
 */
struct mptcp_rbs_value_remainder {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_remainder *self);
	s64 (*execute)(struct mptcp_rbs_value_remainder *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_int *left_operand;
	struct mptcp_rbs_value_int *right_operand;
};

struct mptcp_rbs_value_remainder *mptcp_rbs_value_remainder_new(
    struct mptcp_rbs_value_int *left_operand,
    struct mptcp_rbs_value_int *right_operand);
void mptcp_rbs_value_remainder_free(struct mptcp_rbs_value_remainder *self);
s64 mptcp_rbs_value_remainder_execute(struct mptcp_rbs_value_remainder *self,
				      struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_remainder *mptcp_rbs_value_remainder_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_remainder *value);
int mptcp_rbs_value_remainder_print(
    const struct mptcp_rbs_value_remainder *value, char *buffer);

/*
 * == null operator value
 */
struct mptcp_rbs_value_is_null {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_is_null *self);
	s32 (*execute)(struct mptcp_rbs_value_is_null *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value *operand;
};

struct mptcp_rbs_value_is_null *mptcp_rbs_value_is_null_new(
    struct mptcp_rbs_value *operand);
void mptcp_rbs_value_is_null_free(struct mptcp_rbs_value_is_null *self);
s32 mptcp_rbs_value_is_null_execute(struct mptcp_rbs_value_is_null *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_is_null *mptcp_rbs_value_is_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_is_null *value);
int mptcp_rbs_value_is_null_print(const struct mptcp_rbs_value_is_null *value,
				  char *buffer);

/*
 * != null operator value
 */
struct mptcp_rbs_value_is_not_null {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_is_not_null *self);
	s32 (*execute)(struct mptcp_rbs_value_is_not_null *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value *operand;
};

struct mptcp_rbs_value_is_not_null *mptcp_rbs_value_is_not_null_new(
    struct mptcp_rbs_value *operand);
void mptcp_rbs_value_is_not_null_free(struct mptcp_rbs_value_is_not_null *self);
s32 mptcp_rbs_value_is_not_null_execute(
    struct mptcp_rbs_value_is_not_null *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_is_not_null *mptcp_rbs_value_is_not_null_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_is_not_null *value);
int mptcp_rbs_value_is_not_null_print(
    const struct mptcp_rbs_value_is_not_null *value, char *buffer);

/*
 * R1-6 integer values
 */
struct mptcp_rbs_value_reg {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_reg *self);
	s64 (*execute)(struct mptcp_rbs_value_reg *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	int reg_number;
};

struct mptcp_rbs_value_reg *mptcp_rbs_value_reg_new(int reg_number);
void mptcp_rbs_value_reg_free(struct mptcp_rbs_value_reg *self);
s64 mptcp_rbs_value_reg_execute(struct mptcp_rbs_value_reg *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_reg *mptcp_rbs_value_reg_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_reg *value);
int mptcp_rbs_value_reg_print(const struct mptcp_rbs_value_reg *value,
			      char *buffer);

/*
 * Q sockbuffer list value
 */
struct mptcp_rbs_value_q {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_q *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_q *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
};

struct mptcp_rbs_value_q *mptcp_rbs_value_q_new(void);
void mptcp_rbs_value_q_free(struct mptcp_rbs_value_q *self);
struct sk_buff *mptcp_rbs_value_q_execute(struct mptcp_rbs_value_q *self,
					  struct mptcp_rbs_eval_ctx *ctx,
					  void **prev, bool *is_null);
struct mptcp_rbs_value_q *mptcp_rbs_value_q_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_q *value);
int mptcp_rbs_value_q_print(const struct mptcp_rbs_value_q *value,
			    char *buffer);

/*
 * QU sockbuffer list value
 */
struct mptcp_rbs_value_qu {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_qu *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_qu *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
};

struct mptcp_rbs_value_qu *mptcp_rbs_value_qu_new(void);
void mptcp_rbs_value_qu_free(struct mptcp_rbs_value_qu *self);
struct sk_buff *mptcp_rbs_value_qu_execute(struct mptcp_rbs_value_qu *self,
					   struct mptcp_rbs_eval_ctx *ctx,
					   void **prev, bool *is_null);
struct mptcp_rbs_value_qu *mptcp_rbs_value_qu_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_qu *value);
int mptcp_rbs_value_qu_print(const struct mptcp_rbs_value_qu *value,
			     char *buffer);

/*
 * RQ sockbuffer list value
 */
struct mptcp_rbs_value_rq {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_rq *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_rq *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
};

struct mptcp_rbs_value_rq *mptcp_rbs_value_rq_new(void);
void mptcp_rbs_value_rq_free(struct mptcp_rbs_value_rq *self);
struct sk_buff *mptcp_rbs_value_rq_execute(struct mptcp_rbs_value_rq *self,
					   struct mptcp_rbs_eval_ctx *ctx,
					   void **prev, bool *is_null);
struct mptcp_rbs_value_rq *mptcp_rbs_value_rq_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_rq *value);
int mptcp_rbs_value_rq_print(const struct mptcp_rbs_value_rq *value,
			     char *buffer);

/*
 * SUBFLOWS subflow list value
 */
struct mptcp_rbs_value_subflows {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_subflows *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_subflows *self,
				    struct mptcp_rbs_eval_ctx *ctx, void **prev,
				    bool *is_null);
};

struct mptcp_rbs_value_subflows *mptcp_rbs_value_subflows_new(void);
void mptcp_rbs_value_subflows_free(struct mptcp_rbs_value_subflows *self);
struct tcp_sock *mptcp_rbs_value_subflows_execute(
    struct mptcp_rbs_value_subflows *self, struct mptcp_rbs_eval_ctx *ctx,
    void **prev, bool *is_null);
struct mptcp_rbs_value_subflows *mptcp_rbs_value_subflows_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_subflows *value);
int mptcp_rbs_value_subflows_print(const struct mptcp_rbs_value_subflows *value,
				   char *buffer);

/*
 * CURRENT_TIME_MS integer value
 */
struct mptcp_rbs_value_current_time_ms {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_current_time_ms *self);
	s64 (*execute)(struct mptcp_rbs_value_current_time_ms *self,
		       struct mptcp_rbs_eval_ctx *ctx);
};

struct mptcp_rbs_value_current_time_ms *mptcp_rbs_value_current_time_ms_new(
    void);
void mptcp_rbs_value_current_time_ms_free(
    struct mptcp_rbs_value_current_time_ms *self);
s64 mptcp_rbs_value_current_time_ms_execute(
    struct mptcp_rbs_value_current_time_ms *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_current_time_ms *mptcp_rbs_value_current_time_ms_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_current_time_ms *value);
int mptcp_rbs_value_current_time_ms_print(
    const struct mptcp_rbs_value_current_time_ms *value, char *buffer);

/*
 * RANDOM integer value
 */
struct mptcp_rbs_value_random {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_random *self);
	s64 (*execute)(struct mptcp_rbs_value_random *self,
		       struct mptcp_rbs_eval_ctx *ctx);
};

struct mptcp_rbs_value_random *mptcp_rbs_value_random_new(void);
void mptcp_rbs_value_random_free(struct mptcp_rbs_value_random *self);
s64 mptcp_rbs_value_random_execute(struct mptcp_rbs_value_random *self,
				   struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_random *mptcp_rbs_value_random_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_random *value);
int mptcp_rbs_value_random_print(const struct mptcp_rbs_value_random *value,
				 char *buffer);

/*
 * <subflow>.RTT integer value
 */
struct mptcp_rbs_value_sbf_rtt {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_rtt *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_rtt *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_rtt *mptcp_rbs_value_sbf_rtt_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_rtt_free(struct mptcp_rbs_value_sbf_rtt *self);
s64 mptcp_rbs_value_sbf_rtt_execute(struct mptcp_rbs_value_sbf_rtt *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_rtt *mptcp_rbs_value_sbf_rtt_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt *value);
int mptcp_rbs_value_sbf_rtt_print(const struct mptcp_rbs_value_sbf_rtt *value,
				  char *buffer);

/*
 * <subflow>.RTT_MS integer value
 */
struct mptcp_rbs_value_sbf_rtt_ms {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_rtt_ms *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_rtt_ms *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_rtt_ms *mptcp_rbs_value_sbf_rtt_ms_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_rtt_ms_free(struct mptcp_rbs_value_sbf_rtt_ms *self);
s64 mptcp_rbs_value_sbf_rtt_ms_execute(struct mptcp_rbs_value_sbf_rtt_ms *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_rtt_ms *mptcp_rbs_value_sbf_rtt_ms_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt_ms *value);
int mptcp_rbs_value_sbf_rtt_ms_print(const struct mptcp_rbs_value_sbf_rtt_ms *value,
				  char *buffer);

/*
 * <subflow>.RTT_VAR integer value
 */
struct mptcp_rbs_value_sbf_rtt_var {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_rtt_var *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_rtt_var *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_rtt_var *mptcp_rbs_value_sbf_rtt_var_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_rtt_var_free(struct mptcp_rbs_value_sbf_rtt_var *self);
s64 mptcp_rbs_value_sbf_rtt_var_execute(struct mptcp_rbs_value_sbf_rtt_var *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_rtt_var *mptcp_rbs_value_sbf_rtt_var_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_rtt_var *value);
int mptcp_rbs_value_sbf_rtt_var_print(const struct mptcp_rbs_value_sbf_rtt_var *value,
				  char *buffer);
                  
                  /*
 * <subflow>.USER integer value
 */
struct mptcp_rbs_value_sbf_user {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_user *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_user *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_user *mptcp_rbs_value_sbf_user_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_user_free(struct mptcp_rbs_value_sbf_user *self);
s64 mptcp_rbs_value_sbf_user_execute(struct mptcp_rbs_value_sbf_user *self,
				    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_user *mptcp_rbs_value_sbf_user_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_user *value);
int mptcp_rbs_value_sbf_user_print(const struct mptcp_rbs_value_sbf_user *value,
				  char *buffer);

/*
 * <subflow>.IS_BACKUP boolean value
 */
struct mptcp_rbs_value_sbf_is_backup {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_is_backup *self);
	s32 (*execute)(struct mptcp_rbs_value_sbf_is_backup *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_is_backup *mptcp_rbs_value_sbf_is_backup_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_is_backup_free(
    struct mptcp_rbs_value_sbf_is_backup *self);
s32 mptcp_rbs_value_sbf_is_backup_execute(
    struct mptcp_rbs_value_sbf_is_backup *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_is_backup *mptcp_rbs_value_sbf_is_backup_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_is_backup *value);
int mptcp_rbs_value_sbf_is_backup_print(
    const struct mptcp_rbs_value_sbf_is_backup *value, char *buffer);
/*
 * <subflow>.THROTTLED boolean value
 */
struct mptcp_rbs_value_sbf_throttled {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_throttled *self);
	s32 (*execute)(struct mptcp_rbs_value_sbf_throttled *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_throttled *mptcp_rbs_value_sbf_throttled_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_throttled_free(
    struct mptcp_rbs_value_sbf_throttled *self);
s32 mptcp_rbs_value_sbf_throttled_execute(
    struct mptcp_rbs_value_sbf_throttled *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_throttled *mptcp_rbs_value_sbf_throttled_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_throttled *value);
int mptcp_rbs_value_sbf_throttled_print(
    const struct mptcp_rbs_value_sbf_throttled *value, char *buffer);

/*
 * <subflow>.CWND integer value
 */
struct mptcp_rbs_value_sbf_cwnd {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_cwnd *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_cwnd *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_cwnd *mptcp_rbs_value_sbf_cwnd_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_cwnd_free(struct mptcp_rbs_value_sbf_cwnd *self);
s64 mptcp_rbs_value_sbf_cwnd_execute(struct mptcp_rbs_value_sbf_cwnd *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_cwnd *mptcp_rbs_value_sbf_cwnd_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_cwnd *value);
int mptcp_rbs_value_sbf_cwnd_print(const struct mptcp_rbs_value_sbf_cwnd *value,
				   char *buffer);

/*
 * <subflow>.QUEUED integer value
 */
struct mptcp_rbs_value_sbf_queued {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_queued *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_queued *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_queued *mptcp_rbs_value_sbf_queued_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_queued_free(struct mptcp_rbs_value_sbf_queued *self);
s64 mptcp_rbs_value_sbf_queued_execute(struct mptcp_rbs_value_sbf_queued *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_queued *mptcp_rbs_value_sbf_queued_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_queued *value);
int mptcp_rbs_value_sbf_queued_print(const struct mptcp_rbs_value_sbf_queued *value,
				   char *buffer);

/*
 * <subflow>.SKBS_IN_FLIGHT integer value
 */
struct mptcp_rbs_value_sbf_skbs_in_flight {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_skbs_in_flight *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_skbs_in_flight *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_skbs_in_flight *
mptcp_rbs_value_sbf_skbs_in_flight_new(struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_skbs_in_flight_free(
    struct mptcp_rbs_value_sbf_skbs_in_flight *self);
s64 mptcp_rbs_value_sbf_skbs_in_flight_execute(
    struct mptcp_rbs_value_sbf_skbs_in_flight *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_skbs_in_flight *
mptcp_rbs_value_sbf_skbs_in_flight_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_skbs_in_flight *value);
int mptcp_rbs_value_sbf_skbs_in_flight_print(
    const struct mptcp_rbs_value_sbf_skbs_in_flight *value, char *buffer);

/*
 * <subflow>.LOST_SKBS integer value
 */
struct mptcp_rbs_value_sbf_lost_skbs {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_lost_skbs *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_lost_skbs *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_lost_skbs *mptcp_rbs_value_sbf_lost_skbs_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_lost_skbs_free(
    struct mptcp_rbs_value_sbf_lost_skbs *self);
s64 mptcp_rbs_value_sbf_lost_skbs_execute(
    struct mptcp_rbs_value_sbf_lost_skbs *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_lost_skbs *mptcp_rbs_value_sbf_lost_skbs_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_lost_skbs *value);
int mptcp_rbs_value_sbf_lost_skbs_print(
    const struct mptcp_rbs_value_sbf_lost_skbs *value, char *buffer);

/*
 * <subflow>.HAS_WINDOW_FOR boolean value
 */
struct mptcp_rbs_value_sbf_has_window_for {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_has_window_for *self);
	s32 (*execute)(struct mptcp_rbs_value_sbf_has_window_for *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_value_sbf_has_window_for *
mptcp_rbs_value_sbf_has_window_for_new(struct mptcp_rbs_value_sbf *sbf,
				       struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_sbf_has_window_for_free(
    struct mptcp_rbs_value_sbf_has_window_for *self);
s32 mptcp_rbs_value_sbf_has_window_for_execute(
    struct mptcp_rbs_value_sbf_has_window_for *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_has_window_for *
mptcp_rbs_value_sbf_has_window_for_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_has_window_for *value);
int mptcp_rbs_value_sbf_has_window_for_print(
    const struct mptcp_rbs_value_sbf_has_window_for *value, char *buffer);

/*
 * <subflow>.ID integer value
 */
struct mptcp_rbs_value_sbf_id {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_id *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_id *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_id *mptcp_rbs_value_sbf_id_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_id_free(struct mptcp_rbs_value_sbf_id *self);
s64 mptcp_rbs_value_sbf_id_execute(struct mptcp_rbs_value_sbf_id *self,
				   struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_id *mptcp_rbs_value_sbf_id_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_id *value);
int mptcp_rbs_value_sbf_id_print(const struct mptcp_rbs_value_sbf_id *value,
				 char *buffer);

/*
 * <subflow>.DELAY_IN integer value
 */
struct mptcp_rbs_value_sbf_delay_in {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_delay_in *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_delay_in *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_delay_in *mptcp_rbs_value_sbf_delay_in_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_delay_in_free(
    struct mptcp_rbs_value_sbf_delay_in *self);
s64 mptcp_rbs_value_sbf_delay_in_execute(
    struct mptcp_rbs_value_sbf_delay_in *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_delay_in *mptcp_rbs_value_sbf_delay_in_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_delay_in *value);
int mptcp_rbs_value_sbf_delay_in_print(
    const struct mptcp_rbs_value_sbf_delay_in *value, char *buffer);

/*
 * <subflow>.DELAY_OUT integer value
 */
struct mptcp_rbs_value_sbf_delay_out {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_delay_out *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_delay_out *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_delay_out *mptcp_rbs_value_sbf_delay_out_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_delay_out_free(
    struct mptcp_rbs_value_sbf_delay_out *self);
s64 mptcp_rbs_value_sbf_delay_out_execute(
    struct mptcp_rbs_value_sbf_delay_out *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_delay_out *mptcp_rbs_value_sbf_delay_out_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_delay_out *value);
int mptcp_rbs_value_sbf_delay_out_print(
    const struct mptcp_rbs_value_sbf_delay_out *value, char *buffer);

/* some  helper */

void mptcp_rbs_sbf_delay_update(struct tcp_sock *tp, const struct sk_buff *skb);

void mptcp_rbs_sbf_bw_ack_add(struct tcp_sock *tp, unsigned int bytes);

void mptcp_rbs_sbf_bw_send_add(struct tcp_sock *tp, unsigned int bytes);

/*
 * <subflow>.BW_OUT_SEND integer value
 */
struct mptcp_rbs_value_sbf_bw_out_send {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_bw_out_send *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_bw_out_send *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_bw_out_send *mptcp_rbs_value_sbf_bw_out_send_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_bw_out_send_free(
    struct mptcp_rbs_value_sbf_bw_out_send *self);
s64 mptcp_rbs_value_sbf_bw_out_send_execute(
    struct mptcp_rbs_value_sbf_bw_out_send *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_bw_out_send *mptcp_rbs_value_sbf_bw_out_send_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_bw_out_send *value);
int mptcp_rbs_value_sbf_bw_out_send_print(
    const struct mptcp_rbs_value_sbf_bw_out_send *value, char *buffer);

/*
 * <subflow>.BW_OUT_ACK integer value
 */
struct mptcp_rbs_value_sbf_bw_out_ack {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_bw_out_ack *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_bw_out_ack *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_bw_out_ack *mptcp_rbs_value_sbf_bw_out_ack_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_bw_out_ack_free(
    struct mptcp_rbs_value_sbf_bw_out_ack *self);
s64 mptcp_rbs_value_sbf_bw_out_ack_execute(
    struct mptcp_rbs_value_sbf_bw_out_ack *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_bw_out_ack *mptcp_rbs_value_sbf_bw_out_ack_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_bw_out_ack *value);
int mptcp_rbs_value_sbf_bw_out_ack_print(
    const struct mptcp_rbs_value_sbf_bw_out_ack *value, char *buffer);

/*
 * <subflow>.SSTHRESH integer value
 */
struct mptcp_rbs_value_sbf_ssthresh {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_ssthresh *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_ssthresh *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_ssthresh *mptcp_rbs_value_sbf_ssthresh_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_ssthresh_free(
    struct mptcp_rbs_value_sbf_ssthresh *self);
s64 mptcp_rbs_value_sbf_ssthresh_execute(
    struct mptcp_rbs_value_sbf_ssthresh *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_ssthresh *mptcp_rbs_value_sbf_ssthresh_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_ssthresh *value);
int mptcp_rbs_value_sbf_ssthresh_print(
    const struct mptcp_rbs_value_sbf_ssthresh *value, char *buffer);

/*
 * <subflow>.LOSSY boolean value
 */
struct mptcp_rbs_value_sbf_lossy {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_lossy *self);
	s32 (*execute)(struct mptcp_rbs_value_sbf_lossy *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_sbf_lossy *mptcp_rbs_value_sbf_lossy_new(
    struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_sbf_lossy_free(struct mptcp_rbs_value_sbf_lossy *self);
s32 mptcp_rbs_value_sbf_lossy_execute(struct mptcp_rbs_value_sbf_lossy *self,
				      struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_lossy *mptcp_rbs_value_sbf_lossy_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_lossy *value);
int mptcp_rbs_value_sbf_lossy_print(
    const struct mptcp_rbs_value_sbf_lossy *value, char *buffer);

/*
 * <subflow list>.NEXT subflow value
 */
struct mptcp_rbs_value_sbf_list_next {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_next *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list_next *self,
				    struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
	void *prev;
	/*
	 * The next 2 fields ensure that prev is correctly reset after the
	 * foreach loop finished
	 */
	u32 exec_count;
	bool is_null;
};

struct mptcp_rbs_value_sbf_list_next *mptcp_rbs_value_sbf_list_next_new(
    struct mptcp_rbs_value_sbf_list *list);
void mptcp_rbs_value_sbf_list_next_free(
    struct mptcp_rbs_value_sbf_list_next *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_next_execute(
    struct mptcp_rbs_value_sbf_list_next *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_next *mptcp_rbs_value_sbf_list_next_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_next *value);
int mptcp_rbs_value_sbf_list_next_print(
    const struct mptcp_rbs_value_sbf_list_next *value, char *buffer);

/*
 * <subflow list>.EMPTY boolean value
 */
struct mptcp_rbs_value_sbf_list_empty {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_empty *self);
	s32 (*execute)(struct mptcp_rbs_value_sbf_list_empty *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
};

struct mptcp_rbs_value_sbf_list_empty *mptcp_rbs_value_sbf_list_empty_new(
    struct mptcp_rbs_value_sbf_list *list);
void mptcp_rbs_value_sbf_list_empty_free(
    struct mptcp_rbs_value_sbf_list_empty *self);
s32 mptcp_rbs_value_sbf_list_empty_execute(
    struct mptcp_rbs_value_sbf_list_empty *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_empty *mptcp_rbs_value_sbf_list_empty_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_empty *value);
int mptcp_rbs_value_sbf_list_empty_print(
    const struct mptcp_rbs_value_sbf_list_empty *value, char *buffer);

/*
 * <subflow list>.FILTER subflow list value
 */
struct mptcp_rbs_value_sbf_list_filter {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_filter *self);
	struct tcp_sock *(*execute)(
	    struct mptcp_rbs_value_sbf_list_filter *self,
	    struct mptcp_rbs_eval_ctx *ctx, void **prev, bool *is_null);
	struct mptcp_rbs_value_sbf_list *list;
	struct mptcp_rbs_value_bool *cond;
	struct tcp_sock *cur;
};

struct mptcp_rbs_value_sbf_list_filter *mptcp_rbs_value_sbf_list_filter_new(
    void);
void mptcp_rbs_value_sbf_list_filter_free(
    struct mptcp_rbs_value_sbf_list_filter *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_filter_execute(
    struct mptcp_rbs_value_sbf_list_filter *self,
    struct mptcp_rbs_eval_ctx *ctx, void **prev, bool *is_null);
struct mptcp_rbs_value_sbf_list_filter *mptcp_rbs_value_sbf_list_filter_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_filter *value);
int mptcp_rbs_value_sbf_list_filter_print(
    const struct mptcp_rbs_value_sbf_list_filter *value, char *buffer);

/*
 * Special value holding the actual subflow for FILTER subflow list value
 */
struct mptcp_rbs_value_sbf_list_filter_sbf {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_filter_sbf *self);
	struct tcp_sock *(*execute)(
	    struct mptcp_rbs_value_sbf_list_filter_sbf *self,
	    struct mptcp_rbs_eval_ctx *ctx);
	struct tcp_sock **cur;
};

struct mptcp_rbs_value_sbf_list_filter_sbf *
mptcp_rbs_value_sbf_list_filter_sbf_new(struct tcp_sock **cur);
void mptcp_rbs_value_sbf_list_filter_sbf_free(
    struct mptcp_rbs_value_sbf_list_filter_sbf *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_filter_sbf_execute(
    struct mptcp_rbs_value_sbf_list_filter_sbf *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_filter_sbf *
mptcp_rbs_value_sbf_list_filter_sbf_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_filter_sbf *value);
int mptcp_rbs_value_sbf_list_filter_sbf_print(
    const struct mptcp_rbs_value_sbf_list_filter_sbf *value, char *buffer);

/*
 * <subflow list>.MAX subflow value
 */
struct mptcp_rbs_value_sbf_list_max {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_max *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list_max *self,
				    struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
	struct mptcp_rbs_value_int *cond;
	struct tcp_sock *cur;
};

struct mptcp_rbs_value_sbf_list_max *mptcp_rbs_value_sbf_list_max_new(void);
void mptcp_rbs_value_sbf_list_max_free(
    struct mptcp_rbs_value_sbf_list_max *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_max_execute(
    struct mptcp_rbs_value_sbf_list_max *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_max *mptcp_rbs_value_sbf_list_max_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_max *value);
int mptcp_rbs_value_sbf_list_max_print(
    const struct mptcp_rbs_value_sbf_list_max *value, char *buffer);

/*
 * <subflow list>.MIN subflow value
 */
struct mptcp_rbs_value_sbf_list_min {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_min *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list_min *self,
				    struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
	struct mptcp_rbs_value_int *cond;
	struct tcp_sock *cur;
};

struct mptcp_rbs_value_sbf_list_min *mptcp_rbs_value_sbf_list_min_new(void);
void mptcp_rbs_value_sbf_list_min_free(
    struct mptcp_rbs_value_sbf_list_min *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_min_execute(
    struct mptcp_rbs_value_sbf_list_min *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_min *mptcp_rbs_value_sbf_list_min_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_min *value);
int mptcp_rbs_value_sbf_list_min_print(
    const struct mptcp_rbs_value_sbf_list_min *value, char *buffer);

/*
 * <subflow list>.GET subflow value
 */
struct mptcp_rbs_value_sbf_list_get {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_get *self);
	struct tcp_sock *(*execute)(struct mptcp_rbs_value_sbf_list_get *self,
				    struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
	struct mptcp_rbs_value_int *index;
};

struct mptcp_rbs_value_sbf_list_get *mptcp_rbs_value_sbf_list_get_new(
    struct mptcp_rbs_value_sbf_list *list, struct mptcp_rbs_value_int *index);
void mptcp_rbs_value_sbf_list_get_free(
    struct mptcp_rbs_value_sbf_list_get *self);
struct tcp_sock *mptcp_rbs_value_sbf_list_get_execute(
    struct mptcp_rbs_value_sbf_list_get *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_get *mptcp_rbs_value_sbf_list_get_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_get *value);
int mptcp_rbs_value_sbf_list_get_print(
    const struct mptcp_rbs_value_sbf_list_get *value, char *buffer);

/*
 * <subflow list>.COUNT integer value
 */
struct mptcp_rbs_value_sbf_list_count {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_count *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_list_count *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
};

struct mptcp_rbs_value_sbf_list_count *mptcp_rbs_value_sbf_list_count_new(
    struct mptcp_rbs_value_sbf_list *list);
void mptcp_rbs_value_sbf_list_count_free(
    struct mptcp_rbs_value_sbf_list_count *self);
s64 mptcp_rbs_value_sbf_list_count_execute(
    struct mptcp_rbs_value_sbf_list_count *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_count *mptcp_rbs_value_sbf_list_count_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_count *value);
int mptcp_rbs_value_sbf_list_count_print(
    const struct mptcp_rbs_value_sbf_list_count *value, char *buffer);

/*
 * <subflow list>.SUM integer value
 */
struct mptcp_rbs_value_sbf_list_sum {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_sbf_list_sum *self);
	s64 (*execute)(struct mptcp_rbs_value_sbf_list_sum *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf_list *list;
	struct mptcp_rbs_value_int *cond;
	struct tcp_sock *cur;
};

struct mptcp_rbs_value_sbf_list_sum *mptcp_rbs_value_sbf_list_sum_new(void);
void mptcp_rbs_value_sbf_list_sum_free(
    struct mptcp_rbs_value_sbf_list_sum *self);
s64 mptcp_rbs_value_sbf_list_sum_execute(
    struct mptcp_rbs_value_sbf_list_sum *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_sbf_list_sum *mptcp_rbs_value_sbf_list_sum_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_sbf_list_sum *value);
int mptcp_rbs_value_sbf_list_sum_print(
    const struct mptcp_rbs_value_sbf_list_sum *value, char *buffer);

/*
 * <sockbuffer list>.NEXT sockbuffer value
 */
struct mptcp_rbs_value_skb_list_next {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_next *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_next *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
	struct mptcp_rbs_value_skb_list *list;
	void *prev;
	/*
	 * The next 2 fields ensure that prev is correctly reset after the
	 * foreach loop finished
	 */
	u32 exec_count;
	bool is_null;
};

struct mptcp_rbs_value_skb_list_next *mptcp_rbs_value_skb_list_next_new(
    struct mptcp_rbs_value_skb_list *list);
void mptcp_rbs_value_skb_list_next_free(
    struct mptcp_rbs_value_skb_list_next *self);
struct sk_buff *mptcp_rbs_value_skb_list_next_execute(
    struct mptcp_rbs_value_skb_list_next *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_next *mptcp_rbs_value_skb_list_next_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_next *value);
int mptcp_rbs_value_skb_list_next_print(
    const struct mptcp_rbs_value_skb_list_next *value, char *buffer);

/*
 * <sockbuffer>.SENT_ON boolean value
 */
struct mptcp_rbs_value_skb_sent_on {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_sent_on *self);
	s32 (*execute)(struct mptcp_rbs_value_skb_sent_on *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_skb_sent_on *mptcp_rbs_value_skb_sent_on_new(
    struct mptcp_rbs_value_skb *skb, struct mptcp_rbs_value_sbf *sbf);
void mptcp_rbs_value_skb_sent_on_free(struct mptcp_rbs_value_skb_sent_on *self);
s32 mptcp_rbs_value_skb_sent_on_execute(
    struct mptcp_rbs_value_skb_sent_on *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_sent_on *mptcp_rbs_value_skb_sent_on_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_sent_on *value);
int mptcp_rbs_value_skb_sent_on_print(
    const struct mptcp_rbs_value_skb_sent_on *value, char *buffer);

/*
 * <sockbuffer>.SENT_ON_ALL boolean value
 */
struct mptcp_rbs_value_skb_sent_on_all {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_sent_on_all *self);
	s32 (*execute)(struct mptcp_rbs_value_skb_sent_on_all *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_value_skb_sent_on_all *mptcp_rbs_value_skb_sent_on_all_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_skb_sent_on_all_free(
    struct mptcp_rbs_value_skb_sent_on_all *self);
s32 mptcp_rbs_value_skb_sent_on_all_execute(
    struct mptcp_rbs_value_skb_sent_on_all *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_sent_on_all *mptcp_rbs_value_skb_sent_on_all_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_sent_on_all *value);
int mptcp_rbs_value_skb_sent_on_all_print(
    const struct mptcp_rbs_value_skb_sent_on_all *value, char *buffer);

/*
 * <sockbuffer>.USER integer value
 */
struct mptcp_rbs_value_skb_user {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_user *self);
	s64 (*execute)(struct mptcp_rbs_value_skb_user *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_value_skb_user *mptcp_rbs_value_skb_user_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_skb_user_free(struct mptcp_rbs_value_skb_user *self);
s64 mptcp_rbs_value_skb_user_execute(struct mptcp_rbs_value_skb_user *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_user *mptcp_rbs_value_skb_user_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_user *value);
int mptcp_rbs_value_skb_user_print(const struct mptcp_rbs_value_skb_user *value,
				   char *buffer);

/*
 * <sockbuffer>.SEQ integer value
 */
struct mptcp_rbs_value_skb_seq {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_seq *self);
	s64 (*execute)(struct mptcp_rbs_value_skb_seq *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_value_skb_seq *mptcp_rbs_value_skb_seq_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_skb_seq_free(struct mptcp_rbs_value_skb_seq *self);
s64 mptcp_rbs_value_skb_seq_execute(struct mptcp_rbs_value_skb_seq *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_seq *mptcp_rbs_value_skb_seq_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_seq *value);
int mptcp_rbs_value_skb_seq_print(const struct mptcp_rbs_value_skb_seq *value,
				   char *buffer);

/*
 * <sockbuffer>.PSH boolean value
 */
struct mptcp_rbs_value_skb_psh {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_psh *self);
	s32 (*execute)(struct mptcp_rbs_value_skb_psh *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
	struct mptcp_rbs_value_sbf *sbf;
};

struct mptcp_rbs_value_skb_psh *mptcp_rbs_value_skb_psh_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_skb_psh_free(struct mptcp_rbs_value_skb_psh *self);
s32 mptcp_rbs_value_skb_psh_execute(
    struct mptcp_rbs_value_skb_psh *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_psh *mptcp_rbs_value_skb_psh_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_psh *value);
int mptcp_rbs_value_skb_psh_print(
    const struct mptcp_rbs_value_skb_psh *value, char *buffer);
    
/*
 * <sockbuffer>.LENGTH integer value
 */
struct mptcp_rbs_value_skb_length {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_length *self);
	s64 (*execute)(struct mptcp_rbs_value_skb_length *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_value_skb_length *mptcp_rbs_value_skb_length_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_value_skb_length_free(struct mptcp_rbs_value_skb_length *self);
s64 mptcp_rbs_value_skb_length_execute(struct mptcp_rbs_value_skb_length *self,
				     struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_length *mptcp_rbs_value_skb_length_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_length *value);
int mptcp_rbs_value_skb_length_print(const struct mptcp_rbs_value_skb_length *value,
				   char *buffer);

/*
 * <sockbuffer list>.EMPTY boolean value
 */
struct mptcp_rbs_value_skb_list_empty {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_empty *self);
	s32 (*execute)(struct mptcp_rbs_value_skb_list_empty *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb_list *list;
};

struct mptcp_rbs_value_skb_list_empty *mptcp_rbs_value_skb_list_empty_new(
    struct mptcp_rbs_value_skb_list *list);
void mptcp_rbs_value_skb_list_empty_free(
    struct mptcp_rbs_value_skb_list_empty *self);
s32 mptcp_rbs_value_skb_list_empty_execute(
    struct mptcp_rbs_value_skb_list_empty *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_empty *mptcp_rbs_value_skb_list_empty_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_empty *value);
int mptcp_rbs_value_skb_list_empty_print(
    const struct mptcp_rbs_value_skb_list_empty *value, char *buffer);

/*
 * <sockbuffer list>.POP() sockbuffer value
 */
struct mptcp_rbs_value_skb_list_pop {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_pop *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_pop *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
	struct mptcp_rbs_value_skb_list *list;
};

struct mptcp_rbs_value_skb_list_pop *mptcp_rbs_value_skb_list_pop_new(
    struct mptcp_rbs_value_skb_list *list);
void mptcp_rbs_value_skb_list_pop_free(
    struct mptcp_rbs_value_skb_list_pop *self);
struct sk_buff *mptcp_rbs_value_skb_list_pop_execute(
    struct mptcp_rbs_value_skb_list_pop *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_pop *mptcp_rbs_value_skb_list_pop_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_pop *value);
int mptcp_rbs_value_skb_list_pop_print(
    const struct mptcp_rbs_value_skb_list_pop *value, char *buffer);

/*
 * <sockbuffer list>.FILTER sockbuffer list value
 */

struct mptcp_rbs_value_skb_list_filter_progress {
	struct sk_buff *cur;
	bool reinject;
};

struct mptcp_rbs_value_skb_list_filter {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_filter *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_filter *self,
				   struct mptcp_rbs_eval_ctx *ctx, void **prev,
				   bool *is_null);
	enum mptcp_rbs_value_kind underlying_queue_kind;
	struct mptcp_rbs_value_skb_list *list;
	struct mptcp_rbs_value_bool *cond;
	struct mptcp_rbs_value_skb_list_filter_progress progress;
};

struct mptcp_rbs_value_skb_list_filter *mptcp_rbs_value_skb_list_filter_new(
    void);
void mptcp_rbs_value_skb_list_filter_free(
    struct mptcp_rbs_value_skb_list_filter *self);
struct sk_buff *mptcp_rbs_value_skb_list_filter_execute(
    struct mptcp_rbs_value_skb_list_filter *self,
    struct mptcp_rbs_eval_ctx *ctx, void **prev, bool *is_null);
struct mptcp_rbs_value_skb_list_filter *mptcp_rbs_value_skb_list_filter_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_filter *value);
int mptcp_rbs_value_skb_list_filter_print(
    const struct mptcp_rbs_value_skb_list_filter *value, char *buffer);

/*
 * Special value holding the actual sockbuffer for FILTER sockbuffer list value
 */
struct mptcp_rbs_value_skb_list_filter_skb {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_filter_skb *self);
	struct sk_buff *(*execute)(
	    struct mptcp_rbs_value_skb_list_filter_skb *self,
	    struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
	struct mptcp_rbs_value_skb_list_filter_progress *progress;
};

struct mptcp_rbs_value_skb_list_filter_skb *
mptcp_rbs_value_skb_list_filter_skb_new(
    struct mptcp_rbs_value_skb_list_filter_progress *progress);
void mptcp_rbs_value_skb_list_filter_skb_free(
    struct mptcp_rbs_value_skb_list_filter_skb *self);
struct sk_buff *mptcp_rbs_value_skb_list_filter_skb_execute(
    struct mptcp_rbs_value_skb_list_filter_skb *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_filter_skb *
mptcp_rbs_value_skb_list_filter_skb_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_filter_skb *value);
int mptcp_rbs_value_skb_list_filter_skb_print(
    const struct mptcp_rbs_value_skb_list_filter_skb *value, char *buffer);

/*
 * <sockbuffer list>.COUNT integer value
 */
struct mptcp_rbs_value_skb_list_count {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_count *self);
	s64 (*execute)(struct mptcp_rbs_value_skb_list_count *self,
		       struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb_list *list;
};

struct mptcp_rbs_value_skb_list_count *mptcp_rbs_value_skb_list_count_new(
    struct mptcp_rbs_value_skb_list *list);
void mptcp_rbs_value_skb_list_count_free(
    struct mptcp_rbs_value_skb_list_count *self);
s64 mptcp_rbs_value_skb_list_count_execute(
    struct mptcp_rbs_value_skb_list_count *self,
    struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_count *mptcp_rbs_value_skb_list_count_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_count *value);
int mptcp_rbs_value_skb_list_count_print(
    const struct mptcp_rbs_value_skb_list_count *value, char *buffer);

/*
 * <sockbuffer list>.TOP sockbuffer value
 */
struct mptcp_rbs_value_skb_list_top {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_top *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_top *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	bool reinject;
	struct mptcp_rbs_value_skb_list *list;
};

struct mptcp_rbs_value_skb_list_top *mptcp_rbs_value_skb_list_top_new(
    struct mptcp_rbs_value_skb_list *list);
void mptcp_rbs_value_skb_list_top_free(
    struct mptcp_rbs_value_skb_list_top *self);
struct sk_buff *mptcp_rbs_value_skb_list_top_execute(
    struct mptcp_rbs_value_skb_list_top *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_top *mptcp_rbs_value_skb_list_top_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_top *value);
int mptcp_rbs_value_skb_list_top_print(
    const struct mptcp_rbs_value_skb_list_top *value, char *buffer);

/*
 * <sockbuffer list>.GET sockbuffer value
 */
struct mptcp_rbs_value_skb_list_get {
	enum mptcp_rbs_value_kind kind;
	void (*free)(struct mptcp_rbs_value_skb_list_get *self);
	struct sk_buff *(*execute)(struct mptcp_rbs_value_skb_list_get *self,
				   struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb_list *list;
	struct mptcp_rbs_value_int *index;
};

struct mptcp_rbs_value_skb_list_get *mptcp_rbs_value_skb_list_get_new(
    struct mptcp_rbs_value_skb_list *list, struct mptcp_rbs_value_int *index);
void mptcp_rbs_value_skb_list_get_free(
    struct mptcp_rbs_value_skb_list_get *self);
struct sk_buff *mptcp_rbs_value_skb_list_get_execute(
    struct mptcp_rbs_value_skb_list_get *self, struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_value_skb_list_get *mptcp_rbs_value_skb_list_get_clone(
    struct mptcp_rbs_value_clone_ctx *ctx,
    const struct mptcp_rbs_value_skb_list_get *value);
int mptcp_rbs_value_skb_list_get_print(
    const struct mptcp_rbs_value_skb_list_get *value, char *buffer);

/*
 * Returns the returned type of a given value kind
 */
enum mptcp_rbs_type_kind mptcp_rbs_value_get_type(
    enum mptcp_rbs_value_kind kind);

#ifndef MPTCP_RBS_CLONE_USER_FUNC_DEFINED
#define MPTCP_RBS_CLONE_USER_FUNC_DEFINED
typedef struct mptcp_rbs_value *(*mptcp_rbs_value_clone_user_func)(
    void *user_ctx, const struct mptcp_rbs_value *value);
#endif

/*
 * Creates a copy of a value and all its subvalues
 * @value: The value to copy
 * @user_ctx: User context for the user function or NULL
 * @user_func: Function that is executed for each value or NULL. If this
 * function returns a value other than NULL the current value is replaced with
 * it instead of cloned
 * Return: The new instance
 */
struct mptcp_rbs_value *mptcp_rbs_value_clone(
    const struct mptcp_rbs_value *value, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/*
 * Writes a string representation of a value to the given buffer
 * @value: The value
 * @buffer: Pointer to the buffer where the string should be stored or NULL
 * Return: Number of written characters
 */
int mptcp_rbs_value_print(const struct mptcp_rbs_value *value, char *buffer);

/* some helper for bw calculation */

u64 mptcp_rbs_sbf_get_bw_send(struct mptcp_rbs_sbf_cb *sbf_cb);
u64 mptcp_rbs_sbf_get_bw_ack(struct mptcp_rbs_sbf_cb *sbf_cb);

struct sk_buff *mptcp_rbs_next_in_queue(struct sk_buff_head *queue,
					struct sk_buff *skb);

#endif
