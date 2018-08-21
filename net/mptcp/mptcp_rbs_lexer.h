#ifndef _MPTCP_RBS_LEXER_H
#define _MPTCP_RBS_LEXER_H

#include <linux/types.h>

#define TOKEN_BUFFER_LEN 64

/* Enumeration of possible token kinds */
enum mptcp_rbs_token_kind {
	/* End of data */
	TOKEN_KIND_EOD,
	/* Number literal */
	TOKEN_KIND_NUMBER,
	/* String literal */
	TOKEN_KIND_STRING,
	/* Identifier */
	TOKEN_KIND_IDENT,

	TOKEN_KIND_NOT,
	TOKEN_KIND_ASSIGN,
	TOKEN_KIND_EQUAL,
	TOKEN_KIND_UNEQUAL,
	TOKEN_KIND_LESS,
	TOKEN_KIND_LESS_EQUAL,
	TOKEN_KIND_GREATER,
	TOKEN_KIND_GREATER_EQUAL,
	TOKEN_KIND_ADD,
	TOKEN_KIND_SUB,
	TOKEN_KIND_MUL,
	TOKEN_KIND_DIV,
	TOKEN_KIND_REM,
	TOKEN_KIND_DOT,
	TOKEN_KIND_COMMA,
	TOKEN_KIND_SEMICOLON,
	TOKEN_KIND_OPEN_BRACKET,
	TOKEN_KIND_CLOSE_BRACKET,
	TOKEN_KIND_OPEN_CURLY,
	TOKEN_KIND_CLOSE_CURLY,
	TOKEN_KIND_AND,
	TOKEN_KIND_DROP,
	TOKEN_KIND_ELSE,
	TOKEN_KIND_FOREACH,
	TOKEN_KIND_IF,
	TOKEN_KIND_IN,
	TOKEN_KIND_NULL,
	TOKEN_KIND_OR,
	TOKEN_KIND_PRINT,
	TOKEN_KIND_PUSH,
    TOKEN_KIND_SET_USER,
	TOKEN_KIND_RETURN,
	TOKEN_KIND_SCHEDULER,
	TOKEN_KIND_SET,
	TOKEN_KIND_VAR,
	TOKEN_KIND_VOID
};

/* Struct for a single token */
struct mptcp_rbs_token {
	enum mptcp_rbs_token_kind kind;
	int position;
	int line;
	int line_position;
	union {
		unsigned int number;
		char string[TOKEN_BUFFER_LEN];
	};
};

/*
 * Returns the next token in a string
 * @str: Pointer to the string
 * @position: Pointer to the actual position in the string
 * @token: Pointer to the token which should be filled
 * @return: false if an error occurred. In this case call
 * mptcp_rbs_get_last_error to get the error message
 */
bool mptcp_rbs_get_next_token(char const **str, int *position,
		int *line, int *line_position, struct mptcp_rbs_token *token);

/*
 * Like mptcp_rbs_get_next_token but does not move to the next token
 */
bool mptcp_rbs_get_next_token_lookahead(const char *str, int position,
		int line, int line_position, struct mptcp_rbs_token *token);

/*
 * Returns the last error message of the lexer
 */
const char *mptcp_rbs_get_last_error(void);

void mptcp_rbs_token_kind_to_string(enum mptcp_rbs_token_kind kind,
				    char *buffer);

void mptcp_rbs_token_to_string(const struct mptcp_rbs_token *token,
			       char *buffer);

/*
 * Replaces escape characters like \n with the actual characters inplace
 */
void replace_escape_chars(char *buffer);

/*
 * Replaces invisible characters like newline with escape characters inplace.
 * If write is false the function only computes the length the buffer must have
 * and returns it
 */
int replace_with_escape_chars(char *buffer, bool write);

#endif
