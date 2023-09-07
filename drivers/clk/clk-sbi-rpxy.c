// SPDX-License-Identifier: GPL-2.0
/*
 * RISC-V RPXY Based Clock Driver
 *
 * Copyright (C) 2023 Ventana Micro Systems Ltd.
 */

#define pr_fmt(fmt) "sbi-rpxy-clock: " fmt

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/clk-provider.h>
#include <asm/sbi.h>

#define RPMI_SRVGRP_CLOCK	0x00007

enum rpmi_clock_service_id {
	RPMI_CLK_SRV_ENABLE_NOTIFICATION = 0x01,
	RPMI_CLK_SRV_GET_SYSTEM_CLOCKS = 0x02,
	RPMI_CLK_SRV_GET_ATTRIBUTES = 0x03,
	RPMI_CLK_SRV_GET_SUPPORTED_RATES = 0x04,
	RPMI_CLK_SRV_SET_CONFIG = 0x05,
	RPMI_CLK_SRV_GET_CONFIG = 0x06,
	RPMI_CLK_SRV_SET_RATE = 0x07,
	RPMI_CLK_SRV_GET_RATE = 0x08,
	RPMI_CLK_SRV_ID_MAX_COUNT,
};

#define SBI_RPXY_CLK_MAX_NUM_RATES	16
#define SBI_RPXY_CLK_NAME_LEN		16

#define GET_RATE_LO_U32(rate_u64)	((u32)rate_u64)
#define GET_RATE_HI_U32(rate_u64)	((u32)(rate_u64 >> 32))
#define GET_RATE_U64(hi_u32, lo_u32)	((u64)hi_u32 << 32 | lo_u32)

#define to_rpxy_clk(clk) container_of(clk, struct sbi_rpxy_clk, hw)

enum sbi_rpxy_clock_config {
	SBI_RPXY_CLK_DISABLE = 0,
	SBI_RPXY_CLK_ENABLE = 1,
};

enum sbi_rpxy_clk_type {
	SBI_RPXY_CLK_DISCRETE = 0,
	SBI_RPXY_CLK_LINEAR = 1,
	SBI_RPXY_CLK_TYPE_MAX_IDX,
};

struct sbi_rpxy_ctx {
	/* transport id */
	u32 tpid;
	u32 max_msg_len;
};
static struct sbi_rpxy_ctx rpxy_ctx;

union rpmi_clk_rate {
	struct {
		u32 lo;
		u32 hi;
	} discrete[SBI_RPXY_CLK_MAX_NUM_RATES];
	struct {
		u32 min_lo;
		u32 min_hi;
		u32 max_lo;
		u32 max_hi;
		u32 step_lo;
		u32 step_hi;
	} linear;
};

union sbi_rpxy_clk_rates {
	u64 discrete[SBI_RPXY_CLK_MAX_NUM_RATES];
	struct {
		u64 min;
		u64 max;
		u64 step;
	} linear;
};

struct sbi_rpxy_clk {
	u32 id;
	u32 num_rates;
	u32 transition_latency;
	enum sbi_rpxy_clk_type type;
	union sbi_rpxy_clk_rates *rates;
	char name[SBI_RPXY_CLK_NAME_LEN];
	struct clk_hw hw;
};

struct rpmi_get_num_clocks_rx {
	s32 status;
	u32 num_clocks;
};

struct rpmi_get_attrs_tx {
	u32 clkid;
};

struct rpmi_get_attrs_rx {
	s32 status;
	u32 flags;
	u32 num_rates;
	u32 transition_latency;
	char name[SBI_RPXY_CLK_NAME_LEN];
};

struct rpmi_get_supp_rates_tx {
	u32 clkid;
	u32 clk_rate_idx;
};

struct rpmi_get_supp_rates_rx {
	u32 status;
	u32 flags;
	u32 remaining;
	u32 returned;
	union rpmi_clk_rate rates;
};

struct rpmi_get_rate_tx {
	u32 clkid;
};

struct rpmi_get_rate_rx {
	u32 status;
	u32 lo;
	u32 hi;
};

struct rpmi_set_rate_tx {
	u32 clkid;
	u32 lo;
	u32 hi;
};

struct rpmi_set_rate_rx {
	u32 status;
};

struct rpmi_set_config_tx {
	u32 clkid;
	u32 config;
};

struct rpmi_set_config_rx {
	u32 status;
};

static int sbi_rpxy_clk_get_num_clocks(void)
{
	int ret;
	struct rpmi_get_num_clocks_rx rx;

	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					   RPMI_SRVGRP_CLOCK,
					   RPMI_CLK_SRV_GET_SYSTEM_CLOCKS,
					   NULL, 0, &rx, NULL);
	if (ret)
		return ret;
	if (rx.status)
		return rx.status;

	return rx.num_clocks;
}

static int sbi_rpxy_clk_get_attrs(u32 clkid, struct sbi_rpxy_clk *rpxy_clk)
{
	int ret;
	u8 format;
	unsigned long rxmsg_len;
	struct rpmi_get_attrs_tx tx;
	struct rpmi_get_attrs_rx rx;

	tx.clkid = cpu_to_le32(clkid);
	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					RPMI_SRVGRP_CLOCK,
					RPMI_CLK_SRV_GET_ATTRIBUTES,
					&tx, sizeof(struct rpmi_get_attrs_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;
	if (rx.status)
		return rx.status;

	rpxy_clk->id = clkid;
	rpxy_clk->num_rates = rx.num_rates;
	rpxy_clk->transition_latency = rx.transition_latency;
	strscpy(rpxy_clk->name, rx.name, SBI_RPXY_CLK_NAME_LEN);

	format = rx.flags >> 30;
	if (format >= SBI_RPXY_CLK_TYPE_MAX_IDX)
		return -EINVAL;

	rpxy_clk->type = format;

	return 0;
}

static int sbi_rpxy_clk_get_supported_rates(u32 clkid,
					    struct sbi_rpxy_clk *rpxy_clk)
{
	int ret, rateidx, j = 0;
	unsigned long rxmsg_len;
	size_t clk_rate_idx = 0;
	struct rpmi_get_supp_rates_tx tx;
	struct rpmi_get_supp_rates_rx rx;

	tx.clkid = cpu_to_le32(clkid);
	tx.clk_rate_idx = 0;
	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					RPMI_SRVGRP_CLOCK,
					RPMI_CLK_SRV_GET_SUPPORTED_RATES,
					&tx, sizeof(struct rpmi_get_supp_rates_tx),
					&rx, &rxmsg_len);
	if (ret)
		return ret;

	if (rx.status)
		return rx.status;

	if (!rx.returned)
		return -EINVAL;

	if (rpxy_clk->type == SBI_RPXY_CLK_DISCRETE) {
		for (rateidx = 0; rateidx < rx.returned; rateidx++) {
			rpxy_clk->rates->discrete[rateidx] =
				GET_RATE_U64(rx.rates.discrete[rateidx].hi,
					     rx.rates.discrete[rateidx].lo);
		}

		if (rx.remaining) {
			while (rx.remaining) {
				clk_rate_idx += rx.returned;
				tx.clk_rate_idx = clk_rate_idx;
				ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					RPMI_SRVGRP_CLOCK,
					RPMI_CLK_SRV_GET_SUPPORTED_RATES,
					&tx, sizeof(struct rpmi_get_supp_rates_tx),
					&rx, &rxmsg_len);
				for (j = 0; rateidx < (clk_rate_idx+rx.returned) &&
						j < rx.returned; rateidx++, j++) {
					rpxy_clk->rates->discrete[rateidx] =
					GET_RATE_U64(rx.rates.discrete[j].hi,
					     rx.rates.discrete[j].lo);
				}
			}
		}
	} else if (rpxy_clk->type == SBI_RPXY_CLK_LINEAR) {
		rpxy_clk->rates->linear.min =
				GET_RATE_U64(rx.rates.linear.min_hi,
					     rx.rates.linear.min_lo);
		rpxy_clk->rates->linear.max =
				GET_RATE_U64(rx.rates.linear.max_hi,
					     rx.rates.linear.max_lo);
		rpxy_clk->rates->linear.step =
				GET_RATE_U64(rx.rates.linear.step_hi,
					     rx.rates.linear.step_lo);
	}

	return 0;
}

static unsigned long sbi_rpxy_clk_recalc_rate(struct clk_hw *hw,
					      unsigned long parent_rate)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_get_rate_tx tx;
	struct rpmi_get_rate_rx rx;
	struct sbi_rpxy_clk *rpxy_clk = to_rpxy_clk(hw);

	tx.clkid = cpu_to_le32(rpxy_clk->id);

	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					   RPMI_SRVGRP_CLOCK,
					   RPMI_CLK_SRV_GET_RATE,
					   &tx, sizeof(struct rpmi_get_rate_tx),
					   &rx, &rxmsg_len);
	if (ret)
		return ret;
	if (rx.status)
		return rx.status;

	return GET_RATE_U64(rx.hi, rx.lo);
}

static long sbi_rpxy_clk_round_rate(struct clk_hw *hw,
				    unsigned long rate,
				    unsigned long *parent_rate)
{
	u64 fmin, fmax, ftmp;
	struct sbi_rpxy_clk *rpxy_clk = to_rpxy_clk(hw);

	if (rpxy_clk->type == SBI_RPXY_CLK_DISCRETE)
		return rate;

	fmin = rpxy_clk->rates->linear.min;
	fmax = rpxy_clk->rates->linear.max;

	if (rate <= fmin)
		return fmin;
	else if (rate >=  fmax)
		return fmax;

	ftmp = rate - fmin;
	ftmp += rpxy_clk->rates->linear.step - 1;
	do_div(ftmp, rpxy_clk->rates->linear.step);

	return ftmp * rpxy_clk->rates->linear.step + fmin;
}

static int sbi_rpxy_clk_set_rate(struct clk_hw *hw,
				 unsigned long rate,
				 unsigned long parent_rate)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_set_rate_tx tx;
	struct rpmi_set_rate_rx rx;
	struct sbi_rpxy_clk *rpxy_clk = to_rpxy_clk(hw);

	tx.clkid = cpu_to_le32(rpxy_clk->id);
	tx.lo = cpu_to_le32(GET_RATE_LO_U32(rate));
	tx.hi = cpu_to_le32(GET_RATE_HI_U32(rate));

	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					   RPMI_SRVGRP_CLOCK,
					   RPMI_CLK_SRV_SET_RATE,
					   &tx, sizeof(struct rpmi_set_rate_tx),
					   &rx, &rxmsg_len);
	if (ret)
		return ret;

	return rx.status;
}

static int sbi_rpxy_clk_enable(struct clk_hw *hw)
{
	int ret;
	unsigned long rxmsg_len;
	struct rpmi_set_config_tx tx;
	struct rpmi_set_config_rx rx;
	struct sbi_rpxy_clk *rpxy_clk = to_rpxy_clk(hw);

	tx.config = cpu_to_le32(SBI_RPXY_CLK_ENABLE);
	tx.clkid = cpu_to_le32(rpxy_clk->id);

	ret = sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					   RPMI_SRVGRP_CLOCK,
					   RPMI_CLK_SRV_SET_CONFIG,
					   &tx, sizeof(struct rpmi_set_config_tx),
					   &rx, &rxmsg_len);
	if (ret)
		return ret;

	return rx.status;
}

static void sbi_rpxy_clk_disable(struct clk_hw *hw)
{
	unsigned long rxmsg_len;
	struct rpmi_set_config_tx tx;
	struct rpmi_set_config_rx rx;
	struct sbi_rpxy_clk *rpxy_clk = to_rpxy_clk(hw);

	tx.config = cpu_to_le32(SBI_RPXY_CLK_DISABLE);
	tx.clkid = cpu_to_le32(rpxy_clk->id);

	sbi_rpxy_send_normal_message(rpxy_ctx.tpid,
					   RPMI_SRVGRP_CLOCK,
					   RPMI_CLK_SRV_SET_CONFIG,
					   &tx, sizeof(struct rpmi_set_config_tx),
					   &rx, &rxmsg_len);
}

static const struct clk_ops sbi_rpxy_clk_ops = {
	.recalc_rate = sbi_rpxy_clk_recalc_rate,
	.round_rate = sbi_rpxy_clk_round_rate,
	.set_rate = sbi_rpxy_clk_set_rate,
	.prepare = sbi_rpxy_clk_enable,
	.unprepare = sbi_rpxy_clk_disable,
};

static struct clk_hw *sbi_rpxy_clk_enumerate(struct device *dev, u32 clkid)
{
	int ret;
	struct clk_hw *clk_hw;
	struct sbi_rpxy_clk *rpxy_clk;
	union sbi_rpxy_clk_rates *rates;
	struct clk_init_data init;
	unsigned long min_rate, max_rate;

	rates = devm_kzalloc(dev, sizeof(union sbi_rpxy_clk_rates), GFP_KERNEL);
	rpxy_clk = devm_kzalloc(dev, sizeof(struct sbi_rpxy_clk), GFP_KERNEL);
	rpxy_clk->rates = rates;

	ret = sbi_rpxy_clk_get_attrs(clkid, rpxy_clk);
	if (ret) {
		dev_err(dev, "Failed to get clk-%u attributes\n", clkid);
		return ERR_PTR(ret);
	}

	ret = sbi_rpxy_clk_get_supported_rates(clkid, rpxy_clk);
	if (ret) {
		dev_err(dev, "Error in getting the rates %d\n", ret);
		return ERR_PTR(ret);
	}

	init.flags = CLK_GET_RATE_NOCACHE;
	init.num_parents = 0;
	init.ops = &sbi_rpxy_clk_ops;
	init.name = rpxy_clk->name;
	clk_hw = &rpxy_clk->hw;
	clk_hw->init = &init;

	ret = devm_clk_hw_register(dev, clk_hw);
	if (ret) {
		dev_err(dev, "Unable to register clock-%u\n, %d", clkid, ret);
		return ERR_PTR(ret);
	}

	if (rpxy_clk->type == SBI_RPXY_CLK_DISCRETE) {
		min_rate = rpxy_clk->rates->discrete[0];
		max_rate = rpxy_clk->rates->discrete[rpxy_clk->num_rates - 1];
	} else {
		min_rate = rpxy_clk->rates->linear.min;
		max_rate = rpxy_clk->rates->linear.max;
	}

	clk_hw_set_rate_range(clk_hw, min_rate, max_rate);

	return clk_hw;
}

static int sbi_rpxy_clk_probe(struct platform_device *pdev)
{
	u32 tpid;
	long max_msg_len;
	int ret, num_clocks, clkid;
	struct clk_hw *hw_ptr;
	struct clk_hw_onecell_data *clk_data;

	if ((sbi_spec_version < sbi_mk_version(1, 0)) ||
		sbi_probe_extension(SBI_EXT_RPXY) <= 0) {
		dev_err(&pdev->dev, "sbi rpxy extension not present\n");
		return -ENODEV;
	}

	ret = of_property_read_u32(pdev->dev.of_node,
				   "riscv,sbi-rpxy-transport-id",
				   &tpid);
	if (ret)
		return -EINVAL;

	ret = sbi_rpxy_srvgrp_probe(tpid, RPMI_SRVGRP_CLOCK, &max_msg_len);
	if (!max_msg_len) {
		dev_err(&pdev->dev, "RPMI Clock Service Group Probe Failed\n");
		return -ENODEV;
	}

	rpxy_ctx.tpid = tpid;
	rpxy_ctx.max_msg_len = max_msg_len;

	num_clocks = sbi_rpxy_clk_get_num_clocks();
	if (!num_clocks) {
		dev_err(&pdev->dev, "No clocks found\n");
		return -ENODEV;
	}

	dev_err(&pdev->dev, "clocks found - %d\n", num_clocks);

	clk_data = devm_kzalloc(&pdev->dev,
				struct_size(clk_data, hws, num_clocks),
				GFP_KERNEL);
	clk_data->num = num_clocks;
	if (!clk_data)
		return -ENOMEM;

	for (clkid = 0; clkid < clk_data->num; clkid++) {
		hw_ptr = sbi_rpxy_clk_enumerate(&pdev->dev, clkid);
		if (IS_ERR(hw_ptr))
			dev_err(&pdev->dev, "failed to register clock - %d\n",
				clkid);
		clk_data->hws[clkid] = hw_ptr;
	}

	ret = devm_of_clk_add_hw_provider(&pdev->dev, of_clk_hw_onecell_get,
					  clk_data);
	return ret;
}

static const struct of_device_id sbi_rpxy_clk_of_match[] = {
	{ .compatible = "riscv,sbi-rpxy-clock" },
	{ },
};

MODULE_DEVICE_TABLE(of, sbi_rpxy_clk_of_match);

#define DRIVER_NAME	"clk-sbi-rpxy"

static struct platform_driver sbi_rpxy_clk_platdrv = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = sbi_rpxy_clk_of_match,
	},
	.probe = sbi_rpxy_clk_probe,
};

static int __init sbi_rpxy_clk_driver_init(void)
{
	int ret;

	ret = platform_driver_register(&sbi_rpxy_clk_platdrv);
	if (ret)
		platform_driver_unregister(&sbi_rpxy_clk_platdrv);

	return ret;
}

device_initcall(sbi_rpxy_clk_driver_init);

MODULE_AUTHOR("Rahul Pathak <rpathak@ventanamicro.com>");
MODULE_AUTHOR("Mayuresh Chitale <mchitale@ventanamicro.com>");
MODULE_DESCRIPTION("Clock Driver based on SBI RPXY extension");
MODULE_LICENSE("GPL");
