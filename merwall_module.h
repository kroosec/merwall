#ifndef __MER_MODULE_H__
#define __MER_MODULE_H__

#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/sysfs.h>

#include "merwall_common.h"

/* Function prototypes */

static int rule_show(struct mer_rule *, char *, int);

static void rule_free(struct mer_rule *);

static int parse_packet(const struct sk_buff *, struct mer_rule *);

static int rule_match(const struct mer_rule *, const struct mer_rule *);

static int rules_index_exists(unsigned int);

static unsigned int rules_index_new(void);

static unsigned int packet_handle(const struct sk_buff *, __u8);

#endif
