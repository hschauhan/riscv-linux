#ifndef SSE_GHES_H
#define SSE_GHES_H

#ifdef CONFIG_RISCV_SSE
int sse_register_hart_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb);
int sse_register_device_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb);
int sse_unregister_ghes(struct ghes *ghes);

#else
int sse_register_hart_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb)
{
	return -EOPNOTSUPP;
}

int sse_register_device_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb)
{
	return -EOPNOTSUPP;
}

int sse_unregister_ghes(struct ghes *ghes)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_RISCV_SSE */

#endif /* SSE_GHES_H */
