/*
 *	xt_mark - Netfilter module to match NFMARK value
 *
 *	(C) 1999-2001 Marc Boucher <marc@mbsi.ca>
 *	Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *	Jan Engelhardt <jengelh@medozas.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>

#include <linux/netfilter/xt_mark.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marc Boucher <marc@mbsi.ca>");
MODULE_DESCRIPTION("Xtables: packet mark operations");
MODULE_ALIAS("ipt_mark");
MODULE_ALIAS("ip6t_mark");
MODULE_ALIAS("ipt_MARK");
MODULE_ALIAS("ip6t_MARK");

#if 1 /* ZyXEL QoS, John (porting from MSTC) */
#include "skb_defines.h"
#endif

#if 1 /* ZyXEL QoS, John */
static unsigned int
mark_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
        const struct xt_mark_tginfo2 *markinfo = par->targinfo;
	int mark = 0;

	switch (markinfo->mode) {
                case XT_MARK_SET:
                        mark = markinfo->mark;
                        break;

                case XT_MARK_AND:
                        mark = skb->mark & markinfo->mark;
                        break;

                case XT_MARK_OR:
                        mark = skb->mark | markinfo->mark;
                        break;

                case XT_MARK_VTAG_SET:
                        mark = skb->mark;
                        skb->vtag = (unsigned short)(markinfo->mark);
                        break;
        }

#if defined(CONFIG_BCM_KF_BLOG) && defined(CONFIG_BLOG_FEATURE)
        skb->ipt_check |= IPT_TARGET_MARK;
        skb->ipt_log.u32[BLOG_ORIGINAL_MARK_INDEX] = skb->mark;
	skb->ipt_log.u32[BLOG_TARGET_MARK_INDEX] = mark;
        if ( skb->ipt_check & IPT_TARGET_CHECK )
                return XT_CONTINUE;
#endif

        skb->mark = mark;
        return XT_CONTINUE;
}

#else
static unsigned int
mark_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_mark_tginfo2 *info = par->targinfo;
    
#if defined(CONFIG_BCM_KF_BLOG) && defined(CONFIG_BLOG_FEATURE)
	skb->ipt_check |= IPT_TARGET_MARK;
	skb->ipt_log.u32[BLOG_ORIGINAL_MARK_INDEX] = skb->mark;
	skb->ipt_log.u32[BLOG_TARGET_MARK_INDEX] = (skb->mark & ~info->mask) ^
	   info->mark;
	if ( skb->ipt_check & IPT_TARGET_CHECK )
		return XT_CONTINUE;
#endif

	skb->mark = (skb->mark & ~info->mask) ^ info->mark;
	return XT_CONTINUE;
}
#endif

static bool
mark_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_mark_mtinfo1 *info = par->matchinfo;

	return ((skb->mark & info->mask) == info->mark) ^ info->invert;
}

static struct xt_target mark_tg_reg __read_mostly = {
	.name           = "MARK",
	.revision       = 2,
	.family         = NFPROTO_UNSPEC,
	.target         = mark_tg,
	.targetsize     = sizeof(struct xt_mark_tginfo2),
	.me             = THIS_MODULE,
};

static struct xt_match mark_mt_reg __read_mostly = {
	.name           = "mark",
	.revision       = 1,
	.family         = NFPROTO_UNSPEC,
	.match          = mark_mt,
	.matchsize      = sizeof(struct xt_mark_mtinfo1),
	.me             = THIS_MODULE,
};

static int __init mark_mt_init(void)
{
	int ret;

	ret = xt_register_target(&mark_tg_reg);
	if (ret < 0)
		return ret;
	ret = xt_register_match(&mark_mt_reg);
	if (ret < 0) {
		xt_unregister_target(&mark_tg_reg);
		return ret;
	}
	return 0;
}

static void __exit mark_mt_exit(void)
{
	xt_unregister_match(&mark_mt_reg);
	xt_unregister_target(&mark_tg_reg);
}

module_init(mark_mt_init);
module_exit(mark_mt_exit);
