
#include <linux/nmi.h>
#include <linux/bitfield.h>
#include <linux/riscv_sse.h>

#include <asm/irq_stack.h>
#include <asm/sbi.h>
#include <asm/sse.h>

#define SSE_PRIVILEGE_MODE_BIT			BIT(0)
#define SSE_SPIE_BIT				BIT(1)

#define sse_privilege_mode(exec_mode)	((exec_mode) & SSE_PRIVILEGE_MODE_BIT)
#define sse_spie(exec_mode)		((exec_mode) & SSE_SPIE_BIT)

register unsigned long gp_in_global __asm__("gp");

extern asmlinkage void handle_exception(void);
extern asmlinkage void handle_sse(unsigned long evt,
				  struct sse_interrupted_state *i_state,
				  sse_event_handler *handler, void *arg);

void sse_get_pt_regs(struct sse_interrupted_state *i_state,
		     struct pt_regs *regs)
{
	memcpy(regs, i_state, offsetof(struct sse_interrupted_state, exec_mode));
	regs->status = FIELD_PREP(SR_SPP, sse_privilege_mode(i_state->exec_mode));
	regs->status |= FIELD_PREP(SR_SPIE, sse_spie(i_state->exec_mode));
}

unsigned long do_sse(unsigned long evt, struct sse_interrupted_state *i_state,
		     sse_event_handler *handler, void *arg)
{
	int ret;

	nmi_enter();

	ret = handler(evt, arg, i_state);
	if (ret)
		pr_warn("event %lx handler failed with error %d\n", evt, ret);

	if (sse_privilege_mode(i_state->exec_mode) &&
	    sse_spie(i_state->exec_mode)) {
		goto sse_event_complete;
	}

	/* If coming from kernel with interrupts enabled or userspace,
	 * simulate an interrupt to allow signal delivery and softirqs
	 * processing. Indeed, the SSE delivery path does not actually uses
	 * the "standard" exception path and thus does not process any pending
	 * signal/softirqs which is needed for some of the handling part.
	 *
	 * Since we are "faking" an interrupt, we want to divert the execution
	 * and enter the exception path with interrupts disabled. The SBI
	 * actually restore status.SIE from sstatus.SIE, thus disable it before
	 * entering exceptions path.
	 */
	// csr_clear(CSR_SSTATUS, SR_SPIE);
	// csr_write(CSR_SEPC, i_state->pc);
	// csr_write(CSR_CAUSE, CAUSE_IRQ_FLAG);

	// i_state->exec_mode |= SSE_PRIVILEGE_MODE_BIT;
	// i_state->pc = (unsigned long)handle_exception;

sse_event_complete:
	nmi_exit();

	return ret ? SBI_SSE_HANDLER_FAILED : SBI_SSE_HANDLER_SUCCESS;
}

#ifdef CONFIG_VMAP_STACK
unsigned long *sse_stack_alloc(unsigned int cpu, unsigned int size)
{
	return arch_alloc_vmap_stack(size, cpu_to_node(cpu));
}

void sse_stack_free(unsigned long *stack)
{
	vfree(stack);
}
#else /* CONFIG_VMAP_STACK */

unsigned long *sse_stack_alloc(unsigned int cpu, unsigned int size)
{
	return kmalloc(size, GFP_KERNEL);
}

void sse_stack_free(unsigned long *stack)
{
	kfree(stack);
}

#endif /* CONFIG_VMAP_STACK */

void sse_handler_context_init(struct sse_handler_context *ctx, void *stack,
			      u32 evt, sse_event_handler *handler, void *arg)
{
	ctx->e_state.pc = (unsigned long)handle_sse;
	ctx->e_state.gp = gp_in_global;
	ctx->e_state.sp = (unsigned long)stack + THREAD_SIZE;

	/* This must match handle_sse expected parameter order */
	ctx->e_state.a0 = evt;
	ctx->e_state.a1 = (unsigned long)&ctx->i_state;
	ctx->e_state.a2 = (unsigned long)handler;
	ctx->e_state.a3 = (unsigned long)arg;
}
