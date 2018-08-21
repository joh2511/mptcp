#ifndef _MPTCP_RBS_SMT_H
#define _MPTCP_RBS_SMT_H

#include <linux/types.h>

struct bpf_prog;
struct mptcp_rbs_eval_ctx;

#ifndef MPTCP_RBS_CLONE_USER_FUNC_DEFINED
#define MPTCP_RBS_CLONE_USER_FUNC_DEFINED
typedef struct mptcp_rbs_value *(*mptcp_rbs_value_clone_user_func)(
    void *user_ctx, const struct mptcp_rbs_value *value);
#endif

/* Enumeration of statement kinds */
enum mptcp_rbs_smt_kind {
	SMT_KIND_DROP,
	SMT_KIND_PRINT,
	SMT_KIND_PUSH,
    SMT_KIND_SET_USER,
	SMT_KIND_SET,
	SMT_KIND_VAR,
	SMT_KIND_VOID,
	SMT_KIND_EBPF
};

/* Base struct to store a single statement */
struct mptcp_rbs_smt {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt *self);
	void (*execute)(struct mptcp_rbs_smt *self,
			struct mptcp_rbs_eval_ctx *ctx);
};

/* Struct to store a drop statement */
struct mptcp_rbs_smt_drop {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_drop *self);
	void (*execute)(struct mptcp_rbs_smt_drop *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_smt_drop *mptcp_rbs_smt_drop_new(
    struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_smt_drop_free(struct mptcp_rbs_smt_drop *self);
void mptcp_rbs_smt_drop_execute(struct mptcp_rbs_smt_drop *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_drop *mptcp_rbs_smt_drop_clone(
    const struct mptcp_rbs_smt_drop *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store a print statement */
struct mptcp_rbs_smt_print {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_print *self);
	void (*execute)(struct mptcp_rbs_smt_print *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_string *msg;
	struct mptcp_rbs_value *arg;
};

struct mptcp_rbs_smt_print *mptcp_rbs_smt_print_new(
    struct mptcp_rbs_value_string *msg, struct mptcp_rbs_value *arg);
void mptcp_rbs_smt_print_free(struct mptcp_rbs_smt_print *self);
void mptcp_rbs_smt_print_execute(struct mptcp_rbs_smt_print *self,
				 struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_print *mptcp_rbs_smt_print_clone(
    const struct mptcp_rbs_smt_print *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store a push statement */
struct mptcp_rbs_smt_push {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_push *self);
	void (*execute)(struct mptcp_rbs_smt_push *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
	struct mptcp_rbs_value_skb *skb;
};

struct mptcp_rbs_smt_push *mptcp_rbs_smt_push_new(
    struct mptcp_rbs_value_sbf *sbf, struct mptcp_rbs_value_skb *skb);
void mptcp_rbs_smt_push_free(struct mptcp_rbs_smt_push *self);
void mptcp_rbs_smt_push_execute(struct mptcp_rbs_smt_push *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_push *mptcp_rbs_smt_push_clone(
    const struct mptcp_rbs_smt_push *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);
    
/* Struct to store a set_user statement */
struct mptcp_rbs_smt_set_user {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_set_user *self);
	void (*execute)(struct mptcp_rbs_smt_set_user *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value_sbf *sbf;
	struct mptcp_rbs_value_int *value;
};

struct mptcp_rbs_smt_set_user *mptcp_rbs_smt_set_user_new(
    struct mptcp_rbs_value_sbf *sbf, struct mptcp_rbs_value_int *value);
void mptcp_rbs_smt_set_user_free(struct mptcp_rbs_smt_set_user *self);
void mptcp_rbs_smt_set_user_execute(struct mptcp_rbs_smt_set_user *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_set_user *mptcp_rbs_smt_set_user_clone(
    const struct mptcp_rbs_smt_set_user *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store a set statement */
struct mptcp_rbs_smt_set {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_set *self);
	void (*execute)(struct mptcp_rbs_smt_set *self,
			struct mptcp_rbs_eval_ctx *ctx);
	int reg_number;
	struct mptcp_rbs_value_int *value;
};

struct mptcp_rbs_smt_set *mptcp_rbs_smt_set_new(
    int reg_number, struct mptcp_rbs_value_int *value);
void mptcp_rbs_smt_set_free(struct mptcp_rbs_smt_set *self);
void mptcp_rbs_smt_set_execute(struct mptcp_rbs_smt_set *self,
			       struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_set *mptcp_rbs_smt_set_clone(
    const struct mptcp_rbs_smt_set *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store a var statement */
struct mptcp_rbs_smt_var {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_var *self);
	void (*execute)(struct mptcp_rbs_smt_var *self,
			struct mptcp_rbs_eval_ctx *ctx);
	int var_number;
	bool is_lazy;
	struct mptcp_rbs_value *value;
};

struct mptcp_rbs_smt_var *mptcp_rbs_smt_var_new(int var_number, bool is_lazy,
						struct mptcp_rbs_value *value);
void mptcp_rbs_smt_var_free(struct mptcp_rbs_smt_var *self);
void mptcp_rbs_smt_var_execute(struct mptcp_rbs_smt_var *self,
			       struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_var *mptcp_rbs_smt_var_clone(
    const struct mptcp_rbs_smt_var *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store a void statement. This statement is only used for
 * measurements!
 */
struct mptcp_rbs_smt_void {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_void *self);
	void (*execute)(struct mptcp_rbs_smt_void *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct mptcp_rbs_value *value;
};

struct mptcp_rbs_smt_void *mptcp_rbs_smt_void_new(
    struct mptcp_rbs_value *value);
void mptcp_rbs_smt_void_free(struct mptcp_rbs_smt_void *self);
void mptcp_rbs_smt_void_execute(struct mptcp_rbs_smt_void *self,
				struct mptcp_rbs_eval_ctx *ctx);
struct mptcp_rbs_smt_void *mptcp_rbs_smt_void_clone(
    const struct mptcp_rbs_smt_void *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/* Struct to store generated eBPF code */
struct mptcp_rbs_smt_ebpf {
	struct mptcp_rbs_smt *next;
	enum mptcp_rbs_smt_kind kind;
	void (*free)(struct mptcp_rbs_smt_ebpf *self);
	void (*execute)(struct mptcp_rbs_smt_ebpf *self,
			struct mptcp_rbs_eval_ctx *ctx);
	struct bpf_prog *prog;
	char **strs;
	int strs_len;
};

struct mptcp_rbs_smt_ebpf *mptcp_rbs_smt_ebpf_new(struct bpf_prog *prog,
						  char **strs, int strs_len);
void mptcp_rbs_smt_ebpf_free(struct mptcp_rbs_smt_ebpf *self);
void mptcp_rbs_smt_ebpf_execute(struct mptcp_rbs_smt_ebpf *self,
				struct mptcp_rbs_eval_ctx *ctx);

/*
 * Releases all statements starting with the given one
 */
void mptcp_rbs_smts_free(struct mptcp_rbs_smt *smt);

/*
 * Creates a copy of a statement and all its subvalues
 * @smt: The statement to copy
 * @user_ctx: User context for the user function or NULL
 * @user_func: Function that is executed for each value or NULL. If this
 * function returns a value other than NULL the current value is replaced with
 * it instead of cloned
 * Return: The new instance
 */
struct mptcp_rbs_smt *mptcp_rbs_smt_clone(
    const struct mptcp_rbs_smt *smt, void *user_ctx,
    mptcp_rbs_value_clone_user_func user_func);

/*
 * Writes a string representation of a statement to the given buffer
 * @smt: The statement
 * @buffer: Pointer to the buffer where the string should be stored or NULL
 * @return: Number of written characters
 */
int mptcp_rbs_smt_print(const struct mptcp_rbs_smt *smt, char *buffer);

#endif
