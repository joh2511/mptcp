#include "mptcp_rbs_lexer.h"
#include <linux/kernel.h>
#include <linux/string.h>

static bool inline is_whitespace(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool inline is_linebreak(char c)
{
	return c == '\n';
}

static bool inline is_number(char c)
{
	return c >= '0' && c <= '9';
}

static bool inline is_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static char last_error[64];

bool mptcp_rbs_get_next_token(char const **str, int *position,
				  int *line, int *line_position, struct mptcp_rbs_token *token)
{
	char c;

	/* Jump over whitespaces */
	while (true) {
		c = **str;

		if (c == 0) {
			/* End of data found */
			token->kind = TOKEN_KIND_EOD;
			token->position = *position;
			return true;
		} else if (!is_whitespace(c))
			break;

		++*str;
		++*position;
		++*line_position;

		if (is_linebreak(c)) {
			++*line;
			*line_position = 0;
		}
	}

	/* Store the position of this token and increase it for future calls */
	token->position = *position;
	token->line = *line;
	token->line_position = *line_position;
	++*str;
	++*position;
	++*line_position;

	switch (c) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9': {
		/* Must be a number literal */
		int value = c - '0';

		while (true) {
			c = **str;

			if (!is_number(c))
				break;

			value = value * 10 + c - '0';
			++*str;
			++*position;
			++*line_position;
		}

		token->kind = TOKEN_KIND_NUMBER;
		token->number = value;
		return true;
	}
	case '"': {
		/* Must be a string literal */
		const char *start = *str;
		int len;

		while (true) {
			c = **str;

			if (c == 0 || c == '\n' || c == '\r') {
				/* String was not terminated */
				memset(last_error, 0, sizeof(last_error));
				sprintf(last_error, "%d: string exceeds line",
					*position);
				return false;
			}

			++*str;
			++*position;
			++*line_position;

			if (c == '"')
				break;
		}

		len = *str - start - 1;

		/* Check if string is too long */
		if (len >= TOKEN_BUFFER_LEN) {
			memset(last_error, 0, sizeof(last_error));
			sprintf(last_error, "%d: string is too long",
				*position);
			return false;
		}

		token->kind = TOKEN_KIND_STRING;
		memset(token->string, 0, TOKEN_BUFFER_LEN);
		memcpy(token->string, start, len);
		replace_escape_chars(token->string);
		return true;
	}
	case '.': {
		/* Must be . */
		token->kind = TOKEN_KIND_DOT;
		return true;
	}
	case ',': {
		/* Must be , */
		token->kind = TOKEN_KIND_COMMA;
		return true;
	}
	case ';': {
		/* Must be ; */
		token->kind = TOKEN_KIND_SEMICOLON;
		return true;
	}
	case '!': {
		/* Must be ! or != */
		if (**str == '=') {
			++*str;
			++*position;
			++*line_position;

			token->kind = TOKEN_KIND_UNEQUAL;
			return true;
		}

		token->kind = TOKEN_KIND_NOT;
		return true;
	}
	case '(': {
		/* Must be ( */
		token->kind = TOKEN_KIND_OPEN_BRACKET;
		return true;
	}
	case ')': {
		/* Must be ) */
		token->kind = TOKEN_KIND_CLOSE_BRACKET;
		return true;
	}
	case '{': {
		/* Must be { */
		token->kind = TOKEN_KIND_OPEN_CURLY;
		return true;
	}
	case '}': {
		/* Must be } */
		token->kind = TOKEN_KIND_CLOSE_CURLY;
		return true;
	}
	case '=': {
		/* Must be = or == */
		if (**str == '=') {
			++*str;
			++*position;
			++*line_position;

			token->kind = TOKEN_KIND_EQUAL;
			return true;
		}

		token->kind = TOKEN_KIND_ASSIGN;
		return true;
	}
	case '<': {
		/* Must be < or <= */
		if (**str == '=') {
			++*str;
			++*position;
			++*line_position;

			token->kind = TOKEN_KIND_LESS_EQUAL;
			return true;
		}

		token->kind = TOKEN_KIND_LESS;
		return true;
	}
	case '>': {
		/* Must be > or >= */
		if (**str == '=') {
			++*str;
			++*position;
			++*line_position;

			token->kind = TOKEN_KIND_GREATER_EQUAL;
			return true;
		}

		token->kind = TOKEN_KIND_GREATER;
		return true;
	}
	case '+': {
		/* Must be + */
		token->kind = TOKEN_KIND_ADD;
		return true;
	}
	case '-': {
		/* Must be - */
		token->kind = TOKEN_KIND_SUB;
		return true;
	}
	case '*': {
		/* Must be * */
		token->kind = TOKEN_KIND_MUL;
		return true;
	}
	case '/': {
		/* Might be a comment or / */
		if (**str == '*') {
			int start_position = *position;
			++*str;
			++*position;
			++*line_position;

			while (true) {
				c = **str;
				++*str;
				++*position;
				++*line_position;

				if (c == 0) {
					/* End of comment is missing */
					memset(last_error, 0,
					       sizeof(last_error));
					sprintf(last_error,
						"%d: Comment is not closed",
						start_position);
					return false;
				} else if (is_linebreak(c)) {
					++*line;
					*line_position = 0;
				} else if (c == '*' && **str == '/')
					break;
			}

			++*str;
			++*position;
			++*line_position;
			return mptcp_rbs_get_next_token(str, position, line, line_position, token);
		}

		token->kind = TOKEN_KIND_DIV;
		return true;
	}
	case '%': {
		/* Must be % */
		token->kind = TOKEN_KIND_REM;
		return true;
	}
	default: {
		const char *start = *str - 1;
		int len;

		if (!is_char(c)) {
			/* Illegal character found */
			memset(last_error, 0, sizeof(last_error));
			sprintf(last_error, "%d: illegal character %c",
				*position, c);
			return false;
		}

		/* Must be keyword or identifier */
		while (true) {
			c = **str;

			if (!is_char(c) && !is_number(c))
				break;

			++*str;
			++*position;
		}

		len = *str - start;
		if (len == 2) {
			if (!strncmp(start, "IF", len)) {
				token->kind = TOKEN_KIND_IF;
				return true;
			}
			if (!strncmp(start, "IN", len)) {
				token->kind = TOKEN_KIND_IN;
				return true;
			}
			if (!strncmp(start, "OR", len)) {
				token->kind = TOKEN_KIND_OR;
				return true;
			}
		} else if (len == 3) {
			if (!strncmp(start, "AND", len)) {
				token->kind = TOKEN_KIND_AND;
				return true;
			}
			if (!strncmp(start, "SET", len)) {
				token->kind = TOKEN_KIND_SET;
				return true;
			}
			if (!strncmp(start, "VAR", len)) {
				token->kind = TOKEN_KIND_VAR;
				return true;
			}
		} else if (len == 4) {
			if (!strncmp(start, "DROP", len)) {
				token->kind = TOKEN_KIND_DROP;
				return true;
			}
			if (!strncmp(start, "ELSE", len)) {
				token->kind = TOKEN_KIND_ELSE;
				return true;
			}
			if (!strncmp(start, "NULL", len)) {
				token->kind = TOKEN_KIND_NULL;
				return true;
			}
			if (!strncmp(start, "PUSH", len)) {
				token->kind = TOKEN_KIND_PUSH;
				return true;
			}
			if (!strncmp(start, "VOID", len)) {
				token->kind = TOKEN_KIND_VOID;
				return true;
			}
		} else if (len == 5) {
			if (!strncmp(start, "PRINT", len)) {
				token->kind = TOKEN_KIND_PRINT;
				return true;
			}
		} else if (len == 6) {
			if (!strncmp(start, "RETURN", len)) {
				token->kind = TOKEN_KIND_RETURN;
				return true;
			}
		} else if (len == 7) {
			if (!strncmp(start, "FOREACH", len)) {
				token->kind = TOKEN_KIND_FOREACH;
				return true;
			}
        } else if (len == 8) {
			if (!strncmp(start, "SET_USER", len)) {
				token->kind = TOKEN_KIND_SET_USER;
				return true;
			}
		} else if (len == 9) {
			if (!strncmp(start, "SCHEDULER", len)) {
				token->kind = TOKEN_KIND_SCHEDULER;
				return true;
			}
		} else if (len >= TOKEN_BUFFER_LEN) {
			/* Identifier is too long */
			memset(last_error, 0, sizeof(last_error));
			sprintf(last_error, "%d: identifier is too long",
				*position);
			return false;
		}

		/* Must be identifier */
		token->kind = TOKEN_KIND_IDENT;
		memset(token->string, 0, TOKEN_BUFFER_LEN);
		memcpy(token->string, start, len);
		return true;
	}
	}
}

bool mptcp_rbs_get_next_token_lookahead(const char *str, int position,
					int line, int line_position, struct mptcp_rbs_token *token)
{
	return mptcp_rbs_get_next_token(&str, &position, &line, &line_position, token);
}

const char *mptcp_rbs_get_last_error(void)
{
	return last_error;
}

void mptcp_rbs_token_kind_to_string(enum mptcp_rbs_token_kind kind,
				    char *buffer)
{
	switch (kind) {
	case TOKEN_KIND_EOD: {
		strcpy(buffer, "end of data");
		break;
	}
	case TOKEN_KIND_NUMBER: {
		strcpy(buffer, "number");
		break;
	}
	case TOKEN_KIND_STRING: {
		strcpy(buffer, "string");
		break;
	}
	case TOKEN_KIND_IDENT: {
		strcpy(buffer, "identifier");
		break;
	}
	case TOKEN_KIND_NOT: {
		strcpy(buffer, "!");
		break;
	}
	case TOKEN_KIND_ASSIGN: {
		strcpy(buffer, "=");
		break;
	}
	case TOKEN_KIND_EQUAL: {
		strcpy(buffer, "==");
		break;
	}
	case TOKEN_KIND_UNEQUAL: {
		strcpy(buffer, "!=");
		break;
	}
	case TOKEN_KIND_LESS: {
		strcpy(buffer, "<");
		break;
	}
	case TOKEN_KIND_LESS_EQUAL: {
		strcpy(buffer, "<=");
		break;
	}
	case TOKEN_KIND_GREATER: {
		strcpy(buffer, ">");
		break;
	}
	case TOKEN_KIND_GREATER_EQUAL: {
		strcpy(buffer, ">=");
		break;
	}
	case TOKEN_KIND_ADD: {
		strcpy(buffer, "+");
		break;
	}
	case TOKEN_KIND_SUB: {
		strcpy(buffer, "-");
		break;
	}
	case TOKEN_KIND_MUL: {
		strcpy(buffer, "*");
		break;
	}
	case TOKEN_KIND_DIV: {
		strcpy(buffer, "/");
		break;
	}
	case TOKEN_KIND_REM: {
		strcpy(buffer, "%");
		break;
	}
	case TOKEN_KIND_DOT: {
		strcpy(buffer, ".");
		break;
	}
	case TOKEN_KIND_COMMA: {
		strcpy(buffer, ",");
		break;
	}
	case TOKEN_KIND_SEMICOLON: {
		strcpy(buffer, ";");
		break;
	}
	case TOKEN_KIND_OPEN_BRACKET: {
		strcpy(buffer, "(");
		break;
	}
	case TOKEN_KIND_CLOSE_BRACKET: {
		strcpy(buffer, ")");
		break;
	}
	case TOKEN_KIND_OPEN_CURLY: {
		strcpy(buffer, "{");
		break;
	}
	case TOKEN_KIND_CLOSE_CURLY: {
		strcpy(buffer, "}");
		break;
	}
	case TOKEN_KIND_AND: {
		strcpy(buffer, "AND");
		break;
	}
	case TOKEN_KIND_DROP: {
		strcpy(buffer, "DROP");
		break;
	}
	case TOKEN_KIND_ELSE: {
		strcpy(buffer, "ELSE");
		break;
	}
	case TOKEN_KIND_FOREACH: {
		strcpy(buffer, "FOREACH");
		break;
	}
	case TOKEN_KIND_IF: {
		strcpy(buffer, "IF");
		break;
	}
	case TOKEN_KIND_IN: {
		strcpy(buffer, "IN");
		break;
	}
	case TOKEN_KIND_NULL: {
		strcpy(buffer, "NULL");
		break;
	}
	case TOKEN_KIND_OR: {
		strcpy(buffer, "OR");
		break;
	}
	case TOKEN_KIND_PRINT: {
		strcpy(buffer, "PRINT");
		break;
	}
	case TOKEN_KIND_PUSH: {
		strcpy(buffer, "PUSH");
		break;
	}
    case TOKEN_KIND_SET_USER: {
		strcpy(buffer, "SET_USER");
		break;
	}
	case TOKEN_KIND_RETURN: {
		strcpy(buffer, "RETURN");
		break;
	}
	case TOKEN_KIND_SCHEDULER: {
		strcpy(buffer, "SCHEDULER");
		break;
	}
	case TOKEN_KIND_SET: {
		strcpy(buffer, "SET");
		break;
	}
	case TOKEN_KIND_VAR: {
		strcpy(buffer, "VAR");
		break;
	}
	case TOKEN_KIND_VOID: {
		strcpy(buffer, "VOID");
		break;
	}
	}
}

void mptcp_rbs_token_to_string(const struct mptcp_rbs_token *token,
			       char *buffer)
{
	switch (token->kind) {
	case TOKEN_KIND_NUMBER: {
		sprintf(buffer, "%d", token->number);
		break;
	}
	case TOKEN_KIND_STRING: {
		sprintf(buffer, "\"%s\"", token->string);
		break;
	}
	case TOKEN_KIND_IDENT: {
		sprintf(buffer, "%s", token->string);
		break;
	}
	default: {
		mptcp_rbs_token_kind_to_string(token->kind, buffer);
		break;
	}
	}
}

void replace_escape_chars(char *buffer)
{
	char *pos = buffer;
	int remaining = strlen(buffer);

	while (remaining) {
		char c = *pos;
		++pos;
		--remaining;

		if (c == '\\' && remaining) {
			bool is_escape = false;

			switch (*pos) {
			case '\\': {
				is_escape = true;
				break;
			}
			case '\"': {
				*(pos - 1) = '\"';
				is_escape = true;
				break;
			}
			case 'n': {
				*(pos - 1) = '\n';
				is_escape = true;
				break;
			}
			case 'r': {
				*(pos - 1) = '\r';
				is_escape = true;
				break;
			}
			case 't': {
				*(pos - 1) = '\t';
				is_escape = true;
				break;
			}
			}

			if (is_escape) {
				--remaining;

				if (remaining)
					memcpy(pos, pos + 1, remaining);
				*(pos + remaining) = 0;
			}
		}
	}
}

int replace_with_escape_chars(char *buffer, bool write)
{
	char *pos = buffer;
	int len = strlen(buffer);
	int remaining = len;

	while (remaining) {
		char c = *pos;
		++pos;
		--remaining;

		switch (c) {
		case '\\': {
			if (write) {
				memmove(pos + 1, pos, remaining + 1);
				*(pos - 1) = '\\';
				*pos = '\\';
				++pos;
			}
			++len;
			break;
		}
		case '\"': {
			if (write) {
				memmove(pos + 1, pos, remaining + 1);
				*(pos - 1) = '\\';
				*pos = '\"';
				++pos;
			}
			++len;
			break;
		}
		case '\n': {
			if (write) {
				memmove(pos + 1, pos, remaining + 1);
				*(pos - 1) = '\\';
				*pos = 'n';
				++pos;
			}
			++len;
			break;
		}
		case '\r': {
			if (write) {
				memmove(pos + 1, pos, remaining + 1);
				*(pos - 1) = '\\';
				*pos = 'r';
				++pos;
			}
			++len;
			break;
		}
		case '\t': {
			if (write) {
				memmove(pos + 1, pos, remaining + 1);
				*(pos - 1) = '\\';
				*pos = 't';
				++pos;
			}
			++len;
			break;
		}
		}
	}

	return len;
}
