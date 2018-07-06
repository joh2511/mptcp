#ifndef _MPTCP_RBS_TYPE_H
#define _MPTCP_RBS_TYPE_H

/* Enumeration of type kinds */
enum mptcp_rbs_type_kind {
	TYPE_KIND_NULL,
	TYPE_KIND_BOOL,
	TYPE_KIND_INT,
	TYPE_KIND_STRING,
	TYPE_KIND_SBF,
	TYPE_KIND_SBFLIST,
	TYPE_KIND_SKB,
	TYPE_KIND_SKBLIST
};

/*
 * Returns the name of a type
 */
const char *mptcp_rbs_type_get_name(enum mptcp_rbs_type_kind type);

#endif
