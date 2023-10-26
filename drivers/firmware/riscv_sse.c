// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#define pr_fmt(fmt) "sse: " fmt

#include <linux/cpu.h>
#include <acpi/ghes.h>
#include <linux/acpi.h>
#include <linux/cpuhotplug.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include <linux/riscv_sse.h>
#include <linux/slab.h>

#include <asm/sbi.h>
#include <asm/sse.h>

struct sse_registered_event {
	struct sse_handler_context ctx;
	unsigned long *stack;
};

struct sse_event {
	struct list_head list;
	u32 evt;
	u32 priority;
	unsigned int cpu;

	union {
		struct sse_registered_event *global;
		struct sse_registered_event __percpu *local;
	};
};

static bool sse_available;
static DEFINE_SPINLOCK(events_list_lock);
static LIST_HEAD(events);
static DEFINE_MUTEX(sse_mutex);

static struct sbiret sbi_sse_ecall(int fid, unsigned long arg0,
				   unsigned long arg1, unsigned long arg2)
{
	return sbi_ecall(SBI_EXT_SSE, fid, arg0, arg1, arg2, 0, 0, 0);
}

static bool sse_event_is_global(u32 evt)
{
	return !!(evt & SBI_SSE_EVENT_GLOBAL_MASK);
}

static
struct sse_event *sse_event_get(u32 evt)
{
	struct sse_event *sse_evt = NULL, *tmp;

	spin_lock(&events_list_lock);
	list_for_each_entry(tmp, &events, list) {
		if (tmp->evt == evt) {
			sse_evt = tmp;
			break;
		}
	}
	spin_unlock(&events_list_lock);

	return sse_evt;
}

static int sse_event_set_target_cpu(struct sse_event *sse_evt,
				    unsigned int cpu)
{
	unsigned int hart_id = cpuid_to_hartid_map(cpu);
	u32 evt = sse_evt->evt;
	struct sbiret ret;

	if (!sse_event_is_global(evt))
		return -EINVAL;

	do {
		ret = sbi_sse_ecall(SBI_SSE_EVENT_ATTR_SET, evt,
				SBI_SSE_EVENT_ATTR_HART_ID, hart_id);
		if (ret.error && ret.error != SBI_ERR_BUSY) {
			pr_err("Failed to set event %x hart id, error %ld\n", evt,
			       ret.error);
			return sbi_err_map_linux_errno(ret.error);
		}
	} while (ret.error);

	sse_evt->cpu = cpu;
	return 0;
}

static int sse_event_init_registered(unsigned int cpu, u32 evt,
				     struct sse_registered_event *reg_evt,
				     sse_event_handler *handler, void *arg)
{
	unsigned long *stack;

	stack = sse_stack_alloc(cpu, THREAD_SIZE);
	if (!stack)
		return -ENOMEM;

	reg_evt->stack = stack;

	sse_handler_context_init(&reg_evt->ctx, stack, evt, handler, arg);

	return 0;
}

static struct sse_event *sse_event_alloc(u32 evt,
					 u32 priority,
					 sse_event_handler *handler, void *arg)
{
	int err;
	unsigned int cpu;
	struct sse_event *sse_evt;
	struct sse_registered_event __percpu *reg_evts;
	struct sse_registered_event *reg_evt;

	sse_evt = kzalloc(sizeof(*sse_evt), GFP_KERNEL);
	if (!sse_evt)
		return ERR_PTR(-ENOMEM);

	sse_evt->evt = evt;
	sse_evt->priority = priority;

	if (sse_event_is_global(evt)) {
		reg_evt = kzalloc(sizeof(*reg_evt), GFP_KERNEL);
		if (!reg_evt) {
			err = -ENOMEM;
			goto err_alloc_reg_evt;
		}

		sse_evt->global = reg_evt;
		err = sse_event_init_registered(smp_processor_id(), evt,
						reg_evt, handler, arg);
		if (err)
			goto err_alloc_reg_evt;


	} else {
		reg_evts = alloc_percpu(struct sse_registered_event);
		if (!reg_evts) {
			err = -ENOMEM;
			goto err_alloc_reg_evt;
		}

		sse_evt->local = reg_evts;

		for_each_possible_cpu(cpu) {
			reg_evt = per_cpu_ptr(reg_evts, cpu);

			err = sse_event_init_registered(cpu, evt, reg_evt,
							handler, arg);
			if (err)
				goto err_alloc_reg_evt;

		}
	}

	return sse_evt;

err_alloc_reg_evt:
	kfree(sse_evt);

	return ERR_PTR(err);
}

static int sse_sbi_register_event(struct sse_event *sse_evt,
				  struct sse_registered_event *reg_evt)
{
	struct sbiret ret;
	phys_addr_t phys;
	u32 evt = sse_evt->evt;

	ret = sbi_sse_ecall(SBI_SSE_EVENT_ATTR_SET, evt,
			    SBI_SSE_EVENT_ATTR_PRIORITY, sse_evt->priority);
	if (ret.error) {
		pr_err("Failed to set event %x priority, error %ld\n", evt,
		       ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	if (sse_event_is_global(sse_evt->evt)) {
		phys = virt_to_phys(&reg_evt->ctx);
	} else {
		phys = per_cpu_ptr_to_phys(&reg_evt->ctx);
	}

	ret = sbi_sse_ecall(SBI_SSE_EVENT_REGISTER, evt, phys, 0);
	if (ret.error) {
		pr_err("Failed to register event %d, error %ld\n", evt,
		       ret.error);
		return sbi_err_map_linux_errno(ret.error);
	}

	ret = sbi_sse_ecall(SBI_SSE_EVENT_ENABLE, evt, 0, 0);
	if (ret.error)
		sbi_sse_ecall(SBI_SSE_EVENT_UNREGISTER, evt, 0, 0);

	return sbi_err_map_linux_errno(ret.error);
}


static int sse_event_register_local(struct sse_event *sse_evt)
{
	int ret;
	struct sse_registered_event *reg_evt = per_cpu_ptr(sse_evt->local,
							   smp_processor_id());

	ret = sse_sbi_register_event(sse_evt, reg_evt);
	if (ret)
		pr_err("Failed to register event %x: err %d\n", sse_evt->evt,
		       ret);

	return ret;
}

struct sse_per_cpu_evt_register {
	struct sse_event *sse_evt;
	int error;
};

static void sse_event_register_local_cpu(void *info)
{
	int ret;
	struct sse_per_cpu_evt_register *cpu_evt = info;

	ret = sse_event_register_local(cpu_evt->sse_evt);
	if (ret)
		WRITE_ONCE(cpu_evt->error, 1);
}

static void sse_event_free(struct sse_event *sse_evt)
{
	unsigned int cpu;
	struct sse_registered_event *reg_evt;

	if (sse_event_is_global(sse_evt->evt)) {
		sse_stack_free(sse_evt->global->stack);
	} else {
		for_each_possible_cpu(cpu) {
			reg_evt = per_cpu_ptr(sse_evt->local, cpu);
			sse_stack_free(reg_evt->stack);
		}
		free_percpu(sse_evt->local);
	}

	kfree(sse_evt);
}

static void sse_sbi_unregister_event(u32 evt)
{
	struct sbiret ret;

	ret = sbi_sse_ecall(SBI_SSE_EVENT_DISABLE, evt, 0, 0);
	if (ret.error) {
		pr_err("Failed to disable event %x: err %ld\n", evt, ret.error);
		return;
	}

	ret = sbi_sse_ecall(SBI_SSE_EVENT_UNREGISTER, evt, 0, 0);
	if (ret.error)
		pr_err("Failed to unregister event %x: err %ld\n", evt,
		       ret.error);
}

static void sse_event_unregister_local_cpu(void *info)
{
	u32 *evt = info;

	sse_sbi_unregister_event(*evt);
}

int sse_register_event(u32 evt, u32 priority,
		       sse_event_handler *handler, void *arg)
{
	struct sse_per_cpu_evt_register cpu_evt;
	struct sse_event *sse_evt;
	int ret = 0;

	mutex_lock(&sse_mutex);
	if (sse_event_get(evt)) {
		pr_err("Event %d already registered\n", evt);
		ret = -EEXIST;
		goto out_unlock;
	}

	sse_evt = sse_event_alloc(evt, priority, handler, arg);
	if (IS_ERR(sse_evt)) {
		ret = PTR_ERR(sse_evt);
		goto out_unlock;
	}

	cpus_read_lock();
	if (sse_event_is_global(evt)) {
		/* SSE spec mandates that the CPU registering the global event be the
		* one set as the target hart, plus we don't know initial value
		*/
		ret = sse_event_set_target_cpu(sse_evt, smp_processor_id());
		if (ret)
			goto err_event_free;

		ret = sse_sbi_register_event(sse_evt, sse_evt->global);
		if (ret)
			goto err_event_free;

	} else {
		cpu_evt.sse_evt = sse_evt;
		cpu_evt.error = 0;
		on_each_cpu(sse_event_register_local_cpu, &cpu_evt, 1);
		if (READ_ONCE(cpu_evt.error)) {
			on_each_cpu(sse_event_unregister_local_cpu, &evt, 1);
			goto err_event_free;
		}
	}
	cpus_read_unlock();

	spin_lock(&events_list_lock);
	list_add(&sse_evt->list, &events);
	spin_unlock(&events_list_lock);

	mutex_unlock(&sse_mutex);

	return 0;

err_event_free:
	cpus_read_unlock();
	sse_event_free(sse_evt);
out_unlock:
	mutex_unlock(&sse_mutex);

	return ret;
}

void sse_unregister_event(u32 evt)
{
	struct sse_event *sse_evt;

	mutex_lock(&sse_mutex);

	sse_evt = sse_event_get(evt);
	if (!sse_evt)
		goto out;

	if (sse_event_is_global(evt)) {
		/* Global events can only be unregister from target hart */
		sse_event_set_target_cpu(sse_evt, smp_processor_id());
		sse_sbi_unregister_event(evt);
	} else {
		on_each_cpu(sse_event_unregister_local_cpu, &evt, 1);
	}

	spin_lock(&events_list_lock);
	list_del(&sse_evt->list);
	spin_unlock(&events_list_lock);

	sse_event_free(sse_evt);

out:
	mutex_unlock(&sse_mutex);
}

static int sse_cpu_online(unsigned int cpu)
{
	struct sse_event *sse_evt;

	spin_lock(&events_list_lock);
	list_for_each_entry(sse_evt, &events, list) {
		if (sse_event_is_global(sse_evt->evt))
			continue;

		sse_event_register_local(sse_evt);
	}

	spin_unlock(&events_list_lock);

	return 0;
}

static int sse_cpu_teardown(unsigned int cpu)
{
	unsigned int next_cpu;
	struct sse_event *sse_evt;

	spin_lock(&events_list_lock);
	list_for_each_entry(sse_evt, &events, list) {
		if (!sse_event_is_global(sse_evt->evt)) {
			sse_sbi_unregister_event(sse_evt->evt);
			continue;
		}

		if (sse_evt->cpu != smp_processor_id())
			continue;

		/* Update destination hart */
		next_cpu = cpumask_any_but(cpu_online_mask, cpu);
		sse_event_set_target_cpu(sse_evt, next_cpu);
	}
	spin_unlock(&events_list_lock);

	return 0;
}

static int __init sse_init(void)
{
	int cpu, ret;

	if (sbi_probe_extension(SBI_EXT_SSE) <= 0) {
		pr_err("Missing SBI SSE extension\n");
		return -EOPNOTSUPP;
	}
	pr_info("SBI SSE extension detected\n");

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&events);

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "riscv/sse:online",
					sse_cpu_online, sse_cpu_teardown);
	if (ret < 0)
		return ret;

	sse_available = true;

	return 0;
}
core_initcall(sse_init);

int sse_register_ghes(struct ghes *ghes, sse_event_handler *lo_cb,
		      sse_event_handler *hi_cb)
{
	int err;
	u32 event_num;
	sse_event_handler *cb;

	if (!IS_ENABLED(CONFIG_ACPI_APEI_GHES))
		return -EOPNOTSUPP;

	if (!sse_available)
		return -EOPNOTSUPP;

	event_num = ghes->generic->notify.vector;
	if (event_num > SBI_SSE_EVENT_LOCAL_RAS_RSVD)
		return -EINVAL;

	/* TODO: Decide callback on priority */
	cb = lo_cb;
	err = sse_register_event(event_num, 0, cb, ghes);

	return err;
}

int sse_unregister_ghes(struct ghes *ghes)
{
	u32 event_num = ghes->generic->notify.vector;

	might_sleep();

	if (!IS_ENABLED(CONFIG_ACPI_APEI_GHES))
		return -EOPNOTSUPP;

	if (!sse_available)
		return -EOPNOTSUPP;

	event_num = ghes->generic->notify.vector;
	if (event_num > SBI_SSE_EVENT_LOCAL_RAS_RSVD)
		return -EINVAL;

	sse_unregister_event(event_num);

	return 0;
}
