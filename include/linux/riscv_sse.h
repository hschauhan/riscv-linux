/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#ifndef __LINUX_RISCV_SSE_H
#define __LINUX_RISCV_SSE_H

#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/ptrace.h>

struct sse_interrupted_state;

typedef int (sse_event_handler)(u32 event_num, void *arg,
				struct sse_interrupted_state *i_state);

#ifdef CONFIG_RISCV_SSE

struct ghes;

int sse_register_event(u32 event_num, u32 priority,
		       sse_event_handler *handler, void *arg);
void sse_unregister_event(u32 event_num);

void sse_get_pt_regs(struct sse_interrupted_state *i_state,
		     struct pt_regs *regs);

int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
		      sse_event_handler *hi_cb);
int sse_unregister_ghes(struct ghes *ghes);
#else
static inline int sse_register_event(u32 event_num, u32 priority,
				     sse_event_handler *handler, void *arg)
{
	return -EOPNOTSUPP;
}

static inline void sse_unregister_event(u32 event_num) {}

int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
		      sse_event_handler *hi_cb)
{
	return -EOPNOTSUPP;
}

int sse_unregister_ghes(struct ghes *ghes)
{
	return -EOPNOTSUPP;
}

#endif

#endif /* __LINUX_RISCV_SSE_H */
