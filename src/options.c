#include "libft.h"
#include "ft_ping.h"
#include "display.h"
#include "flags.h"
#include "utils.h"

#include <arpa/inet.h>

int parse_options(int argc, char *argv[], t_options *options)
{
	int opt;

	while ((opt = getopt(argc, argv, ":vhc:fi:p:qs:S:t:w:W:")) != -1)
	if (opt == 'h')
		print_help();
	else if (opt == 'v')
		activate_flag(&global_flags, FLAG_V);
	else if (opt == 'c')
		(ft_atoi(optarg) > 0) ? options->count = ft_atoi(optarg) \
		: error_exit("bad number of packets to transmit");
	else if (opt == 'f')
		activate_flag(&global_flags, FLAG_F);
	else if (opt == 'i')
		(ft_atoi(optarg) > 0) ? options->interval = ft_atoi(optarg) \
		: error_exit("bad timing interval");
	else if (opt == 'p')
		(ft_isascii(*optarg) && ft_strlen(optarg) == 1) ? options->pattern = *optarg \
		: error_exit("pattern must be a valid ASCII character");
	else if (opt == 'q')
		activate_flag(&global_flags, FLAG_Q);
	else if (opt == 's')
		(ft_atoi(optarg) >= 0 && ft_atoi(optarg) + sizeof(struct ip) + sizeof(struct icmphdr) <= MAX_PACKET_SIZE) ? options->icmp_datasize = ft_atoi(optarg) \
		: error_exit("invalid icmp data size");
	else if (opt == 'S')
	{
		if (inet_pton(AF_INET, optarg, &(options->source_ip)) != 1)
			error_exit("invalid source ip");
	}
	else if (opt == 't')
		(ft_atoi(optarg) > 0 && ft_atoi(optarg) <= 255) ? options->ttl = ft_atoi(optarg) \
		: error_exit("ttl out of range");
	else if (opt == 'W')
		(ft_atoi(optarg) >= 0) ? options->timeout = ft_atoi(optarg) \
		: error_exit("bad timeout value");
	else if (opt == ':')
		error_exit("option needs a value");
	else if (opt == '?')
	{
		ft_dprintf(STDERR_FILENO, "ft_ping: invalid option -- '%c'\n", optopt);
		print_usage();
	}
	return (optind);
}
