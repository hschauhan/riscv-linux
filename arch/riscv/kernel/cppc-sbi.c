// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implement CPPC FFH helper routines which use SBI CPPC extension
 *
 * Copyright (C) 2023 Ventana Micro Systems Inc.
 */

#ifdef CONFIG_ACPI_CPPC_LIB
#include <asm/sbi.h>
#include <acpi/cppc_acpi.h>
#include <asm/csr.h>

static int cppc_ext_present = -1;

/*
 * Refer to drivers/acpi/cppc_acpi.c for the description of the functions
 * below.
 */
bool cpc_ffh_supported(void)
{
	return true;
}

int cpc_read_ffh(int cpu, struct cpc_reg *reg, u64 *val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	if (cppc_ext_present < 0) {
		if (!sbi_spec_is_0_1() && sbi_probe_extension(SBI_EXT_CPPC) > 0) {
			pr_info("SBI CPPC extension detected\n");
			cppc_ext_present = 1;
		} else {
			pr_err("SBI CPPC extension NOT detected!!\n");
			cppc_ext_present = 0;
		}
	}

	if (!cppc_ext_present)
		return -EINVAL;

	if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_SBI) {
		data.reg = FFH_CPPC_SBI_REG(reg->address);

		smp_call_function_single(cpu, sbi_cppc_read, &data, 1);

		*val = data.ret.value;

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	}

	/* TODO: CSR access */

	return -EINVAL;
}

int cpc_write_ffh(int cpu, struct cpc_reg *reg, u64 val)
{
	struct sbi_cppc_data data;

	if (WARN_ON_ONCE(irqs_disabled()))
		return -EPERM;

	if (cppc_ext_present < 0) {
		if (!sbi_spec_is_0_1() && sbi_probe_extension(SBI_EXT_CPPC) > 0) {
			pr_info("SBI CPPC extension detected\n");
			cppc_ext_present = 1;
		} else {
			pr_err("SBI CPPC extension NOT detected!!\n");
			cppc_ext_present = 0;
		}
	}

	if (!cppc_ext_present)
		return -EINVAL;

	if (FFH_CPPC_TYPE(reg->address) == FFH_CPPC_SBI) {
		data.reg = FFH_CPPC_SBI_REG(reg->address);
		data.val = val;

		smp_call_function_single(cpu, sbi_cppc_write, &data, 1);

		return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
	}

	/* TODO: CSR access */

	return -EINVAL;
}

int cpc_ffh_transition_latency(int cpu, u32 *val)
{
	struct sbi_cppc_data data;

	data.reg = FFH_CPPC_SBI_TRANS_LATENCY;

	smp_call_function_single(cpu, sbi_cppc_read, &data, 1);

	*val = (u32) data.ret.value;

	return (data.ret.error) ? sbi_err_map_linux_errno(data.ret.error) : 0;
}

#endif /* CONFIG_ACPI_CPPC_LIB */
