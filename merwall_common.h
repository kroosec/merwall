/*
 * Merwal common. Code shared between userspace admin and kernelspace
 * module.
 */

#ifndef __MER_COMMON_H__
#define __MER_COMMON_H__

#include <linux/types.h>

struct mer_rule {
	__u8    direction;  /* 0: ALL. 1: IN. 2: OUT. */
	__u8    proto;      /* 0: ALL. 1: TCP. 2: UDP. */
	__u32   srcip;      /* Source IP address. */
	__u32   dstip;      /* Destination IP address. */
	__u16   srcport;    /* Source port number. */
	__u16   dstport;    /* Destination port number. */
	__u8    action;     /* 0: DROP. 1: LOG. */
	__u32   index;      /* Rule index. Must be > 0 */
/* For rules list in module. */
#ifdef MER_KERNELSPACE
	struct list_head list;
#endif
};

/* Command values: Add rule, Delete rule, Flush rules etc,. */
enum {
	CMD_ADD = 0,
	CMD_DEL,
	CMD_FLUSH,
	CMD_MAX
};

/* Action values: Drop, Pass, Log etc,. */
enum {
	ACT_DROP = 0,
	ACT_PASS,
	ACT_LOG,
	ACT_MAX
};

/* Traffic direction: All (Both), In or Out. */
enum {
	DIRECTION_ALL = 0,
	DIRECTION_IN,
	DIRECTION_OUT,
	DIRECTION_MAX
};

/* Network protocol: All, TCP, UDP etc,. */
enum {
	PROTO_ALL = 0,
	PROTO_TCP,
	PROTO_UDP,
	PROTO_MAX
};

/* Max network port value */
#define PORT_MAX 65535

/* Command strings */
#define CMD_ADD_STR "ADD"
#define CMD_DEL_STR "DELETE"
#define CMD_FLUSH_STR "FLUSH"

/* Action strings */
#define ACT_DROP_STR "DROP"
#define ACT_PASS_STR "PASS"
#define ACT_LOG_STR "LOG"

/* Direction strings */
#define DIRECTION_ALL_STR "ALL"
#define DIRECTION_IN_STR "IN"
#define DIRECTION_OUT_STR "OUT"

/* Protocol strings */
#define PROTO_ALL_STR "ALL"
#define PROTO_TCP_STR "TCP"
#define PROTO_UDP_STR "UDP"

/* Function prototypes */
char* cmd_to_str(int cmd);

char* action_to_str(int action);

char* direction_to_str(int direction);

char* proto_to_str(int proto);

#endif
