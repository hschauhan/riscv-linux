#include <linux/cpu.h>
#include <acpi/ghes.h>
#include <linux/acpi.h>
#include <linux/cpuhotplug.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include <linux/reboot.h>
#include <linux/riscv_sse.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/bitops.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>

#include <asm/sbi.h>
#include <asm/sse.h>
#include <asm/sse_ghes.h>

struct sse_event_data {
	struct list_head head;
	struct ghes *ghes;
	u32 event_num;
	u32 reg_done;
	struct sse_event *event;
	sse_event_handler *cb;
};

extern bool sse_available;

static DEFINE_PER_CPU(struct sse_event_data, reri_hart_ghes);

static LIST_HEAD(sse_event_list);

static int ghes_handler(u32 event_num, void *arg, struct pt_regs *regs)
{
	struct sse_event_data *data = (struct sse_event_data *)arg;
	struct ghes *ghes = data->ghes;

	if (ghes && data->cb)
		return data->cb(event_num, ghes, regs);

	return -EINVAL;
}

static struct sse_event_data *ghes_to_event_data(struct ghes *ghes)
{
	u32 event_num;
	struct sse_event_data *ev_data;

	event_num = ghes->generic->notify.vector;
	list_for_each_entry(ev_data, &sse_event_list, head) {
		if (ev_data->event_num == event_num)
			return ev_data;
	}

	return NULL;
}

static int initialize_event_data(struct sse_event_data *ev_data, struct ghes *ghes,
				  sse_event_handler *lo_cb, sse_event_handler *hi_cb)
{
	u32 event_num;

	event_num = ghes->generic->notify.vector;
	if (event_num > SBI_SSE_EVENT_LOCAL_RAS_RSVD)
		return -EINVAL;

	ev_data->event_num = event_num;
	ev_data->cb = lo_cb;
	ev_data->ghes = ghes;
	ev_data->reg_done = 0;

	return 0;
}

static inline int sse_register_ghes(struct sse_event_data *ev_data)
{
	int err;
 
	ev_data->event = sse_event_register(ev_data->event_num, 0, ghes_handler,
					    ev_data);

	if (ev_data->event) {
		if ((err = sse_event_enable(ev_data->event)) != 0) {
			pr_err("%s: Couldn't enable event %u\n", __func__, ev_data->event_num);
		}
	}

	return err;
}

int sse_unregister_ghes(struct ghes *ghes)
{
	struct sse_event_data *ev_data;

	might_sleep();

	if (!IS_ENABLED(CONFIG_ACPI_APEI_GHES))
		return -EOPNOTSUPP;

	if (!sse_available)
		return -EOPNOTSUPP;

	ev_data = ghes_to_event_data(ghes);
	if (ev_data == NULL)
		return -EBADF;

	sse_event_unregister(ev_data->event);

	list_del(&ev_data->head);

	kfree(ev_data);

	return 0;
}

int sse_register_hart_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb)
{
	int this_cpu, target_cpu;
	unsigned long hart_id;
	struct sse_event_data *ev_data;
	unsigned long src_id = ghes->generic_v2->header.source_id;

	this_cpu = get_cpu();
	hart_id = cpuid_to_hartid_map(this_cpu);
	put_cpu();

	target_cpu = riscv_hartid_to_cpuid(src_id);

	/* For HARTs the error source ID is same as HART id */
	ev_data = per_cpu_ptr(&reri_hart_ghes, riscv_hartid_to_cpuid(src_id));

	initialize_event_data(ev_data, ghes, lo_cb, hi_cb);

	/* If the ghes of this cpu, register event */
	if (src_id == hart_id) {
		ev_data->reg_done = 1;
		return sse_register_ghes(ev_data);
	} else {
		pr_warn("CPU: %d (%lu) skipping event registration for cpu %d (%lu)\n",
			this_cpu, hart_id, target_cpu, src_id);
	}

	return 0;
}

int sse_register_device_ghes(struct ghes *ghes, sse_event_handler *lo_cb, sse_event_handler *hi_cb)
{
	struct sse_event_data *ev_data;
	int err;

	ev_data = kzalloc(sizeof(struct sse_event_data), GFP_KERNEL);
	if (!ev_data)
		return -ENOMEM;

	initialize_event_data(ev_data, ghes, lo_cb, hi_cb);

	if ((err = sse_register_ghes(ev_data)) != 0) {
		kfree(ev_data);
		return err;
	}

	INIT_LIST_HEAD(&ev_data->head);

	list_add(&ev_data->head, &sse_event_list);

	return 0;
}

static int smp_ghes_init(unsigned int cpu)
{
	unsigned long hart_id;
	struct sse_event_data *ev_data;

	hart_id = cpuid_to_hartid_map(cpu);

	ev_data = per_cpu_ptr(&reri_hart_ghes, cpu);

	if (ev_data->reg_done)
		return 0;

	if (ev_data->ghes->generic_v2->header.source_id != hart_id) {
		pr_warn("Hart ID (%lu) of cpu %u doesn't match with source id in GHES\n",
			hart_id, cpu);
		return 0;
	}

	pr_warn("Registering GHES on cpu %u (hart: %lu)\n", cpu, hart_id);

	return sse_event_enable(ev_data->event);
}

static int smp_ghes_uninit(unsigned int cpu)
{
	return 0;
}

static int __init _smp_ghes_init(void)
{
	int rc = 0;

	//	for_each_possible_cpu(cpu)
	//	raw_spin_lock_init(&per_cpu(ecall_lock, cpu));


	/* Hotplug handler to register/unregister shared memory with SBI */
	rc = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			       "riscv/sse_ghes:prepare",
			       smp_ghes_init,
			       smp_ghes_uninit);

	if (rc < 0) {
		pr_warn("%s: Failed to setup CPU hotplug state\n", __func__);
		return rc;
	}

	return rc;
}
device_initcall(_smp_ghes_init);
