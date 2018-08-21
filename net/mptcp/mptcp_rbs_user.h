#ifndef _MPTCP_RBS_USER_H
#define _MPTCP_RBS_USER_H

#include <linux/types.h>

/* Variable to indicate that optimizations are enabled.
 * 0: Optimizations are disabled
 * 1: CFG based optimizations enabled
 * 2: CFG based optimizations + eBPF code generation enabled
 */
extern int mptcp_rbs_opts_enabled;

/*
 * Initializes the user proc interface
 * @return: false if an error occurred
 */
bool mptcp_rbs_user_interface_init(void);

#endif
