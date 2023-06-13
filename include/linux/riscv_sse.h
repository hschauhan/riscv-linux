/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#ifndef __LINUX_RISCV_SSE_H
#define __LINUX_RISCV_SSE_H

#include <linux/types.h>
#include <linux/linkage.h>

struct sse_interrupted_state;

typedef int (sse_event_handler)(u32 event_num, void *arg,
				struct sse_interrupted_state *i_state);

#ifdef CONFIG_RISCV_SSE

int sse_register_event(u32 event_num, u32 priority,
		       sse_event_handler *handler, void *arg);
void sse_unregister_event(u32 event_num);

void sse_get_pt_regs(struct sse_interrupted_state *i_state,
		     struct pt_regs *regs);

#else
static inline int sse_register_event(u32 event_num, u32 priority,
				     sse_event_handler *handler, void *arg)
{
	return -EOPNOTSUPP;
}

static inline void sse_unregister_event(u32 event_num) {}

#endif

#endif /* __LINUX_RISCV_SSE_H */
