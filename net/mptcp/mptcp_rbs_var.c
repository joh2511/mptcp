#include "mptcp_rbs_var.h"
#include <linux/slab.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
void mptcp_rbs_var_free(struct mptcp_rbs_var *self)
{
	if (self->is_lazy)
		return;

	switch (self->type) {
	case TYPE_KIND_NULL:
	case TYPE_KIND_BOOL:
	case TYPE_KIND_INT:
	case TYPE_KIND_STRING:
	case TYPE_KIND_SBF:
	case TYPE_KIND_SKB:
		break;
	case TYPE_KIND_SBFLIST: {
		kfree(self->sbf_list_value);
		break;
	}
	case TYPE_KIND_SKBLIST: {
		kfree(self->skb_list_value);
		break;
	}
	}
}
#pragma GCC diagnostic pop
