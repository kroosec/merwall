
/*
 * Merwal common. Code shared between userspace admin and kernelspace
 * module.
 */

#include "merwall_common.h"

char* cmd_to_str(int cmd)
{
	switch (cmd) {
	case CMD_ADD:
		return CMD_ADD_STR;
	case CMD_DEL:
		return CMD_DEL_STR;
	case CMD_FLUSH:
		return CMD_FLUSH_STR;
	default:
		return "Unknown command!";
	}
}

char* action_to_str(int action)
{
	switch (action) {
	case ACT_DROP:
		return ACT_DROP_STR;
	case ACT_PASS:
		return ACT_PASS_STR;
	case ACT_LOG:
		return ACT_LOG_STR;
	default:
		return "Unknown action!";
	}
}

char* direction_to_str(int direction)
{
	switch (direction) {
	case DIRECTION_ALL:
		return DIRECTION_ALL_STR;
	case DIRECTION_IN:
		return DIRECTION_IN_STR;
	case DIRECTION_OUT:
		return DIRECTION_OUT_STR;
	default:
		return "Unknown direction!";
	}
}

char* proto_to_str(int proto)
{
	switch (proto) {
	case PROTO_ALL:
		return PROTO_ALL_STR;
	case PROTO_TCP:
		return PROTO_TCP_STR;
	case PROTO_UDP:
		return PROTO_UDP_STR;
	default:
		return "Unknown protocol!";
	}
}

