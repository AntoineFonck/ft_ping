#include "libft.h"
#include "ft_ping.h"
#include "flags.h"
#include "stats_calculations.h"

#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/time.h>

void print_help()
{
	ft_printf("Usage: ./ft_ping [-vhfq] [-c count] [-i interval] "
	"[-p pattern] [-s icmp_data_size] [-S source_ip] [-t ttl] "
	"[-W timeout] DESTINATION\n"
	"Send ICMP ECHO_REQUEST packets to network hosts.\n"
	"\n"
	"   -v                verbose output\n"
	"   -h                give this help list\n"
	"   -f                ping flood (no cooldown between packets sent)\n"
	"   -q                quiet output (only show start and end summary)\n"
	"   -c=NUMBER         stop after sending NUMBER packets\n"
	"   -i=NUMBER         wait NUMBER seconds between sending each packet\n"
	"   -p=BYTE_PATTERN   put ASCII BYTE_PATTERN in the ICMP packet data\n"
	"   -s=NUMBER         set NUMBER as the size of ICMP data sent\n"
	"   -S=IPV4_ADDRESS   set IPV4_ADDRESS as the source address in the IP packet (IP spoofing)\n"
	"   -t=NUMBER         set NUMBER as TTL for outgoing packets\n"
	"   -W=NUMBER         set NUMBER as max time to wait for responses\n");
	exit(2);
}

void print_usage()
{
	ft_dprintf(STDERR_FILENO, "Usage: ./ft_ping [-vhfq] [-c count] [-i interval] "
	"[-p pattern] [-s icmp_data_size] [-S source_ip] [-t ttl] "
	"[-W timeout] DESTINATION\n");
	exit(2);
}

void print_time_exceeded(char *str_ip, struct icmp *icmp, int seq_icmp)
{
	if (icmp->icmp_code == 0)
		ft_printf("From %s icmp_seq=%d TTL Expired In Transit\n", str_ip, seq_icmp);
	else if (icmp->icmp_code == 1)
		ft_printf("From %s icmp_seq=%d Fragment Reassembly Time Exceeded\n", str_ip, seq_icmp);
	else
		ft_printf("From %s icmp_seq=%d Time Exceeded : \
		ICMP code not recognized\n", str_ip, seq_icmp);
}

void print_destination_unreachable(char *str_ip, struct icmp *icmp, int seq_icmp)
{
	const char *error_array[] = { \
	"Destination Network Unreachable", \
	"Destination Host Unreachable", \
	"Destination Protocol Unreachable", \
	"Destination Port Unreachable", \
	"Fragmentation Required, and DF flag set", \
	"Source Route Failed" \
	};
	if (icmp->icmp_code <= 5)
		ft_printf("From %s icmp_seq=%d %s\n", str_ip, seq_icmp, error_array[icmp->icmp_code]);
	else
		ft_printf("From %s icmp_seq=%d %s\n", str_ip, seq_icmp, "Destination Unreachable : \
		ICMP code not recognized");
}

void print_echo_reply(int icmp_size_received, char *str_ip, int seq_icmp, int ttl, double duration)
{
	ft_printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3lf ms\n", \
	icmp_size_received, str_ip, seq_icmp, ttl, duration);
}

int print_packet_stats(char *packet, int nb_bytes_rcvd, int seq_icmp, double duration)
{
	char str_ip[INET_ADDRSTRLEN];
	struct ip *ip;
	struct icmp *icmp;

	ip = (struct ip *)packet;
	icmp = (struct icmp *)(packet + sizeof(struct ip));
	inet_ntop(AF_INET, &(ip->ip_src), str_ip, INET_ADDRSTRLEN);
	if (is_flag_on(global_flags, FLAG_Q) && icmp->icmp_type == 0)
		return (0);
	else if (is_flag_on(global_flags, FLAG_Q) && icmp->icmp_type != 0)
		return (1);
	if (icmp->icmp_type == 0 && ntohs(icmp->icmp_hun.ih_idseq.icd_seq) == seq_icmp)
	{
		print_echo_reply(nb_bytes_rcvd - sizeof(struct ip), str_ip, seq_icmp, ip->ip_ttl, duration);
		return (0);
	}
	else if (icmp->icmp_type == 3)
		print_destination_unreachable(str_ip, icmp, seq_icmp);
	else if (icmp->icmp_type == 11)
		print_time_exceeded(str_ip, icmp, seq_icmp);
	else
		ft_printf("From %s icmp_seq=%d ICMP type %d not supported\n", str_ip, seq_icmp, icmp->icmp_type);
	if (is_flag_on(global_flags, FLAG_V) && icmp->icmp_type != 0)
	{
		ft_printf("Verbose error details for received packet with icmp_seq=%d: "
		"icmp_type=%d / icmp_code =%d\n", ntohs(icmp->icmp_hun.ih_idseq.icd_seq), icmp->icmp_type, icmp->icmp_code);
	}
	return(1);
}

int print_start_info(struct sockaddr_in *target_ip, char *hostname, t_options *options)
{
	char str_ip[INET_ADDRSTRLEN];	

	inet_ntop(AF_INET, &(target_ip->sin_addr), str_ip, INET_ADDRSTRLEN);
	ft_printf("PING %s (%s) %d(%d) bytes of data.\n", hostname, str_ip, options->icmp_datasize, \
	sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize);
	return (0);
}

void print_rtt_stats(double min_rtt, double max_rtt, double sum_duration, int nb_packets_received, double sum_duration_stddev)
{
	double average;
	double std_deviation;

	if (nb_packets_received == 0)
		return ;
	average = get_average(sum_duration, nb_packets_received);
	std_deviation = get_std_deviation(average, sum_duration_stddev, nb_packets_received);
	ft_printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min_rtt, \
	average, max_rtt, std_deviation);
}

void print_end_error(t_fullping_stats *fullping_stats, int percent_loss, double full_duration)
{
	ft_printf("%d packets transmitted, %d received, +%d errors, %d%% packet loss, time %.3fs\n", \
	fullping_stats->nb_packets_sent, fullping_stats->nb_packets_received, fullping_stats->nb_packets_error, \
	percent_loss, full_duration);
}

void print_end_normal(t_fullping_stats *fullping_stats, int percent_loss, double full_duration)
{
	ft_printf("%d packets transmitted, %d received, %d%% packet loss, time %.3fs\n", \
	fullping_stats->nb_packets_sent, fullping_stats->nb_packets_received, percent_loss, full_duration);
	print_rtt_stats(fullping_stats->min_rtt, fullping_stats->max_rtt, fullping_stats->sum_duration, \
	fullping_stats->nb_packets_received, fullping_stats->sum_duration_stddev);
}

int	print_end_statistics(t_fullping_stats *fullping_stats, char *hostname)
{
	int percent_loss;
	double full_duration;

	gettimeofday(&(fullping_stats->tv_end_ping), NULL);
	full_duration = calculate_msduration(&(fullping_stats->tv_start_ping), &(fullping_stats->tv_end_ping)) / 1000;
	percent_loss = calculate_percentloss(fullping_stats->nb_packets_sent, fullping_stats->nb_packets_received);
	ft_printf("\n--- %s ping statistics ---\n", hostname);
	if (fullping_stats->nb_packets_error != 0)
		print_end_error(fullping_stats, percent_loss, full_duration);
	else
		print_end_normal(fullping_stats, percent_loss, full_duration);
	return (0);
}
