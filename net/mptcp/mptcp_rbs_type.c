#include "mptcp_rbs_type.h"

/* Array to map mptcp_rbs_type_kind items to their names */
static const char *type_names[] = {
	"null",
	"boolean",
	"integer",
	"string",
	"subflow",
	"subflow list",
	"sockbuffer",
	"sockbuffer list"
};

const char *mptcp_rbs_type_get_name(enum mptcp_rbs_type_kind type)
{
	return type_names[type];
}
