#include "libft.h"
#include "ft_ping.h"
#include "utils.h"

#include <sys/time.h>
#include <signal.h>

void init_fullping_stats(t_fullping_stats *fullping_stats)
{
	gettimeofday(&(fullping_stats->tv_start_ping), NULL);
	fullping_stats->min_rtt = 0.0;
	fullping_stats->max_rtt = 0.0;
	fullping_stats->sum_duration = 0.0;
	fullping_stats->sum_duration_stddev = 0.0;
	fullping_stats->nb_packets_sent = 0;
	fullping_stats->nb_packets_received = 0;
	fullping_stats->nb_packets_error = 0;
}

void init_singleping_stats(t_singleping_stats *singleping_stats)
{
	singleping_stats->duration = 0.0;
	singleping_stats->nb_bytes_received = 0;
	singleping_stats->id_icmp = getpid() & 0xFFFF;
	singleping_stats->seq_icmp = 1;
}

void init_signals_handler()
{
	signal(SIGALRM, sig_handler);
	signal(SIGINT, sig_handler);
}

void init_options(t_options *options)
{
	ft_bzero(&(options->source_ip), sizeof(struct in_addr));
	options->pattern = 0;
	options->count = 0;
	options->interval = 1;
	options->icmp_datasize = 56;
	options->timeout = 1;
	options->ttl = 64;
}
