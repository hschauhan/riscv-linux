// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implement ACPI based cpuidle (LPI)
 *
 * Copyright (c) 2023 Ventana Micro Systems Inc.
 */

#ifdef CONFIG_ACPI
#include <linux/acpi.h>
#include <linux/cpuidle.h>
#include <linux/cpu_pm.h>
#include <acpi/processor.h>
#include <asm/sbi.h>
#include <asm/cpuidle.h>
#include <asm/suspend.h>

static int acpi_cpu_init_idle(unsigned int cpu)
{
	int i, count;
	struct acpi_lpi_state *lpi;
	struct acpi_processor *pr = per_cpu(processors, cpu);

	if (unlikely(!pr || !pr->flags.has_lpi))
		return -EINVAL;

	count = pr->power.count - 1;
	if (count <= 0)
		return -ENODEV;

	for (i = 0; i < count; i++) {
		u32 state;

		lpi = &pr->power.lpi_states[i + 1];
		/*
		 * Only bits[31:0] represent a SBI power_state
		 */
		state = lpi->address;
		if (!sbi_suspend_state_is_valid(state)) {
			pr_warn("Invalid SBI power state %#x\n", state);
			return -EINVAL;
		}
	}

	return 0;
}

int acpi_processor_ffh_lpi_probe(unsigned int cpu)
{
	return acpi_cpu_init_idle(cpu);
}

int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
{
	u32 state = lpi->address;

	if (state & SBI_HSM_SUSP_NON_RET_BIT)
		return CPU_PM_CPU_IDLE_ENTER_PARAM(sbi_suspend,
						   lpi->index,
						   state);
	else
		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(sbi_suspend,
							     lpi->index,
							     state);
}

#endif
