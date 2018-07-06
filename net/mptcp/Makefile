#
## Makefile for MultiPath TCP support code.
#
#

obj-$(CONFIG_MPTCP) += mptcp.o

mptcp-y := mptcp_ctrl.o mptcp_ipv4.o mptcp_pm.o \
	   mptcp_output.o mptcp_input.o mptcp_sched.o

obj-$(CONFIG_TCP_CONG_LIA) += mptcp_coupled.o
obj-$(CONFIG_TCP_CONG_OLIA) += mptcp_olia.o
obj-$(CONFIG_TCP_CONG_WVEGAS) += mptcp_wvegas.o
obj-$(CONFIG_TCP_CONG_BALIA) += mptcp_balia.o
obj-$(CONFIG_MPTCP_FULLMESH) += mptcp_fullmesh.o
obj-$(CONFIG_MPTCP_NDIFFPORTS) += mptcp_ndiffports.o
obj-$(CONFIG_MPTCP_BINDER) += mptcp_binder.o
obj-$(CONFIG_MPTCP_ROUNDROBIN) += mptcp_rr.o
obj-$(CONFIG_MPTCP_REDUNDANT) += mptcp_redundant.o
obj-$(CONFIG_MPTCP_RBS) += mptcp_rbs_sched.o mptcp_rbs_parser.o mptcp_rbs_queue.o mptcp_rbs_lexer.o mptcp_rbs_user.o mptcp_rbs_cfg.o mptcp_rbs_smt.o mptcp_rbs_value.o mptcp_rbs_var.o mptcp_rbs_exec.o mptcp_rbs_ctx.o mptcp_rbs_type.o mptcp_rbs_scheduler.o mptcp_rbs_optimizer.o mptcp_rbs_optimizer_bm.o mptcp_rbs_optimizer_cf.o mptcp_rbs_optimizer_cve.o mptcp_rbs_optimizer_dce.o mptcp_rbs_optimizer_ebpf.o mptcp_rbs_optimizer_ebpf_disasm.o mptcp_rbs_optimizer_ebpf_regalloc.o mptcp_rbs_optimizer_ebpf_lse.o mptcp_rbs_optimizer_lu.o mptcp_rbs_optimizer_vi.o mptcp_rbs_action.o

mptcp-$(subst m,y,$(CONFIG_IPV6)) += mptcp_ipv6.o

