#include "merwall_admin.h"
#include "merwall_common.h"

#define SYSFS_PATH "/sys/class/merwall/merwall_file"

void out_help()
{
	/* XXX: Help for various commands. */
	printf("Help.\n");
}

void out_list()
{
	char buff[1024];
	FILE *f = fopen(SYSFS_PATH, "r");

	if (!f) {
		fprintf(stderr, "Can't open %s\n.", SYSFS_PATH);
		return;
	}

	while (fgets(buff, sizeof(buff) - 1, f) != NULL)
		fputs(buff, stdout);

	fclose(f);
}

void out_error()
{
	/* XXX: Take int argument for different error messages. */
	printf("Errors be here.\n");
}

/* Initialize a mer_rule structure. */
#define mer_rule_new(mrule)					\
	do {							\
		mrule = malloc(sizeof(*mrule));			\
		if (!mrule)					\
			return 1;				\
								\
		memset(mrule, '\0', sizeof(mrule));		\
	} while (0);

/*
 * @mrule   Rule structure.
 *
 * @return  -1: Error. 0: Output help. 1: Add rule. 2: Delete rule. 3: List
 * rules. 4: Flush rules.
 *
 */
int parse_args(int argc, char **argv, struct mer_rule *mrule)
{
	int opt, arg_index;

	/* Command-line options. */
	struct option mer_options[] = {
		{ "index", required_argument, NULL, 'x' },
		{ "delete", required_argument, NULL, 'd' },
		{ "action", required_argument, NULL, 'c' },
		{ "direction", required_argument, NULL, 'e' },
		{ "proto", required_argument, NULL, 'r' },
		{ "srcip", required_argument, NULL, 'i' },
		{ "dstip", required_argument, NULL, 'I' },
		{ "srcport", required_argument, NULL, 'p' },
		{ "dstport", required_argument, NULL, 'P' },
		{ "list", no_argument, NULL, 'l' },
		{ "flush", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	if (!argv || !mrule || argc < 2)
		return -1;

	/* Parse arguments */
	opt = getopt_long(argc, argv, "lh", mer_options, &arg_index);
	while (opt != -1) {
		int port, index;
		__u32 ip;

		switch (opt) {

		/* --index */
		case 'x':
			index = atoi(optarg);
			if (index < 0)
				return -1;
			mrule->index = index;
			break;

		/* --direction */
		case 'e':
			if (!strcasecmp(optarg, DIRECTION_ALL_STR))
				mrule->direction = DIRECTION_ALL;
			else if (!strcasecmp(optarg, DIRECTION_IN_STR))
				mrule->direction = DIRECTION_IN;
			else if (!strcasecmp(optarg, DIRECTION_OUT_STR))
				mrule->direction = DIRECTION_OUT;
			else
				return -1;
			break;

		/* --proto */
		case 'r':
			if (!strcasecmp(optarg, PROTO_ALL_STR))
				mrule->proto = PROTO_ALL;
			else if (!strcasecmp(optarg, PROTO_TCP_STR))
				mrule->proto = PROTO_TCP;
			else if (!strcasecmp(optarg, PROTO_UDP_STR))
				mrule->proto = PROTO_UDP;
			else
				return -1;
			break;

		/* --srcip */
		case 'i':
			if (inet_pton(AF_INET, optarg, &ip) <= 0)
				return -1;
			mrule->srcip = ip;
			break;

		/* --dstip */
		case 'I':
			if (inet_pton(AF_INET, optarg, &ip) <= 0)
				return -1;
			mrule->dstip = ip;
			break;

		/* --srcport */
		case 'p':
			port = atoi(optarg);
			if (port < 0 || port > PORT_MAX)
				return -1;
			mrule->srcport = port;
			break;

		/* --dstport */
		case 'P':
			port = atoi(optarg);
			if (port < 0 || port > PORT_MAX)
				return -1;
			mrule->dstport = port;
			break;

		/* --action */
		case 'c':
			if (!strcasecmp(optarg, ACT_DROP_STR))
				mrule->action = ACT_DROP;
			else if (!strcasecmp(optarg, ACT_PASS_STR))
				mrule->action = ACT_PASS;
			else if (!strcasecmp(optarg, ACT_LOG_STR))
				mrule->action = ACT_LOG;
			else
				return -1;
			break;

		/* --delete */
		case 'd':
			index = atoi(optarg);
			if (index < 0)
				return -1;
			mrule->index = index;
			return 2;

		/* --list */
		case 'l':
			return 3;

		/* --flush */
		case 'f':
			return 4;

		/* --help */
		case 'h':
			return 0;

		/* Error */
		case '?':
		default:
			return -1;
		}
		opt = getopt_long(argc, argv, "lh", mer_options, &arg_index);
	}

	/* Default: Add rule */
	return 1;
}

/*
 * @return -1 if error, 0 else.
 */
int handle_cmd(int cmd, struct mer_rule *mrule)
{
	FILE *sysfs_file;
	if (!mrule)
		return -1;

	sysfs_file = fopen(SYSFS_PATH, "w");

	if (!sysfs_file) {
		fprintf(stderr, "Can't open %s\n.", SYSFS_PATH);
		return -1;
	}

	switch (cmd) {
	case CMD_ADD:
		/* CMD_ADD INDEX ACT DIR PROTO SRCIP DSTIP SRCPORT DSTPORT*/
		fprintf(sysfs_file, "%d %d %d %d %d %u %u %d %d", CMD_ADD,
			mrule->index, mrule->action, mrule->direction,
			mrule->proto, mrule->srcip, mrule->dstip,
			mrule->srcport, mrule->dstport);
		break;
	case CMD_DEL:
		/* CMD_DEL INDEX */
		fprintf(sysfs_file, "%d %d", CMD_DEL, mrule->index);
		break;
	case CMD_FLUSH:
		/* CMD_FLUSH */
		fprintf(sysfs_file, "%d", CMD_FLUSH);
		break;
	default:
		fprintf(stderr, "Erroneous command value %d.\n", cmd);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct mer_rule *mrule;
	mer_rule_new(mrule);

	switch (parse_args(argc, argv, mrule)) {
	/* Error */
	case -1:
		out_error();
		break;
	/* Output help */
	case 0:
		out_help();
		break;
	/* Add rule */
	case 1:
		return handle_cmd(CMD_ADD, mrule);
	/* Delete rule */
	case 2:
		return handle_cmd(CMD_DEL, mrule);
	/* List rules */
	case 3:
		out_list();
		break;
	/* List rules */
	case 4:
		return handle_cmd(CMD_FLUSH, mrule);
	default:
		fprintf(stderr, "Unknown parse_args() return value.\n");
		return -1;
	}

	return 0;
}

