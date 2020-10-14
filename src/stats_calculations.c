#include "ft_ping.h"
#include "display.h"
#include <sys/time.h>
#include <math.h>

double calculate_msduration(struct timeval *start, struct timeval *end)
{
	double duration;

	duration = (end->tv_sec - start->tv_sec) * 1000.0;
	duration += (end->tv_usec - start->tv_usec) / 1000.0;
	return (duration);
}

void get_minmax_rtt(double duration, double *min_rtt, double *max_rtt)
{
	if (duration < *min_rtt)
		*min_rtt = duration;
	else if (duration > *max_rtt)
		*max_rtt = duration;
}

double get_average(double accumulation, int nb_elem)
{
	double average;

	average = accumulation / nb_elem;
	return (average);
}

double get_std_deviation(double average, double accumulation, int nb_elem)
{
	double variant;
	double std_deviation;

	variant = 0.0;
	std_deviation = 0.0;
	if ((nb_elem - average * average) != 0)
		variant = accumulation / nb_elem - average * average;
	std_deviation = sqrt(variant);
	return (std_deviation);
}

int calculate_percentloss(unsigned int nb_packets_sent, unsigned int nb_packets_received)
{
	int percent_loss;

	if (nb_packets_sent == 0)
		percent_loss = 0;
	else
		percent_loss = (1 - ((double)nb_packets_received/(double)nb_packets_sent)) * 100;
	return (percent_loss);
}

void handle_stats(char *packet, t_singleping_stats *singleping_stats, t_fullping_stats *fullping_stats)
{
	if (singleping_stats->nb_bytes_received >= 0)
	{
		singleping_stats->duration = calculate_msduration(&(singleping_stats->tv_start_rtt), &(singleping_stats->tv_end_rtt));
		fullping_stats->sum_duration += singleping_stats->duration;
		fullping_stats->sum_duration_stddev += singleping_stats->duration * singleping_stats->duration;
		if (fullping_stats->nb_packets_sent == 1)
		{
			fullping_stats->min_rtt = singleping_stats->duration;
			fullping_stats->max_rtt = singleping_stats->duration;
		}
		if (print_packet_stats(packet, singleping_stats->nb_bytes_received, singleping_stats->seq_icmp, singleping_stats->duration) == 0)
		{
			get_minmax_rtt(singleping_stats->duration, &(fullping_stats->min_rtt), &(fullping_stats->max_rtt));
			fullping_stats->nb_packets_received++;
		}
		else
			fullping_stats->nb_packets_error++;
	}
}
