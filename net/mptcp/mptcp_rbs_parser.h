#ifndef _MPTCP_RBS_PARSER_H
#define _MPTCP_RBS_PARSER_H

/* Define this macro to enable VOID statements */
#define MPTCP_RBS_MEASURE

struct mptcp_rbs_scheduler;

/*
 * Formats a given string with arguments, stores it inside of the given
 * buffer and returns the number of written characters. The buffer pointer is
 * enhanced to the next character after the last written character. If NULL or
 * a pointer to NULL is passed the function only calculates the length
 */
int sprintf_null(char **buf, const char *fmt, ...);

/*
 * Tries to build a scheduler from a string
 * @return: The parsed scheduler or NULL
 */
struct mptcp_rbs_scheduler *mptcp_rbs_scheduler_parse(const char *str);

#endif
