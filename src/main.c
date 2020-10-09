#include "libft.h"
#include "ft_ping.h"

//socket libraries
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h> 
//inet_ntop and inet_pton
#include <arpa/inet.h>
//signal
#include <signal.h>
//printf
//#include <stdio.h>
//time
#include <sys/time.h>
//sqrt
#include <math.h>

enum e_flags
{
	FLAG_V = 1 << 0,
	FLAG_F = 1 << 1,
	FLAG_Q = 1 << 2,
	FLAG_SIGALRM = 1 << 3,
	FLAG_SIGINT = 1 << 4
};

void activate_flag(char *flags, char flag)
{
	*flags |= flag;
}

void deactivate_flag(char *flags, char flag)
{
	*flags &= ~(flag);
}

int	is_flag_on(char flags, char flag)
{
	if (flags & flag)
		return (1);
	return (0);
}

char global_flags = 0;

int create_socket()
{
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd == -1)
	{
		ft_dprintf(STDERR_FILENO, "socket failed : %{r}s\n", strerror(errno));
		exit(2);
	}
	return(fd);
}

int setup_socket(int fd, t_options *options)
{
	int hdrincl;
	struct timeval tv_timeout;

	hdrincl = 1;
	tv_timeout.tv_sec = options->timeout;
	tv_timeout.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "setsockopt failed : %{r}s\n", strerror(errno));
		exit(2);
	}
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "setsockopt failed : %{r}s\n", strerror(errno));
		exit(2);
	}
	return (0);
}

uint16_t inet_checksum(void *addr, int count)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     * Taken from https://tools.ietf.org/html/rfc1071
     */

    register uint32_t sum = 0;
    uint16_t * ptr = addr;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * ptr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (uint8_t *) ptr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int send_echo_request(int sockfd, struct sockaddr_in *ip, char *packet, t_options *options)
{
	if (sendto(sockfd, packet, sizeof(struct ip) + 8 + options->icmp_datasize, 0, (struct sockaddr *)ip, sizeof(*ip)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "sendto error %{r}s\n", strerror(errno));
		exit(1);
	}
	return(0);
}

int	receive_echo_reply(int sockfd, char *packet, t_options *options)
{
	int nb_bytes_rcvd;

	struct iovec iovec[1];
	struct msghdr msghdr;

	ft_bzero(packet, sizeof(struct ip) + 8 + options->icmp_datasize);
	iovec[0].iov_base = packet;
	iovec[0].iov_len = sizeof(struct ip) + 8 + options->icmp_datasize;

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_iov = iovec;
	msghdr.msg_iovlen = 1;

	if ((nb_bytes_rcvd = recvmsg(sockfd, &msghdr, MSG_WAITALL)) == -1)
	{
		//ft_dprintf(STDERR_FILENO, "recvmsg error %{r}s\n", strerror(errno));
		if (is_flag_on(global_flags, FLAG_V))
			ft_dprintf(STDERR_FILENO, "Timeout for receiving echo reply\n");
	}
	else if (inet_checksum(packet, nb_bytes_rcvd) != 0)
		ft_dprintf(STDERR_FILENO, "error checksum in received packet\n");
	return(nb_bytes_rcvd);
}

void fill_icmpdatapattern(char *packet, char pattern, int nb_bytes_tofill)
{
	char *icmpdata_ptr;

	if (pattern == 0)
		return ;
	icmpdata_ptr = packet + sizeof(struct ip) + 8;
	while (nb_bytes_tofill > 0)
	{
		*icmpdata_ptr = pattern;
		icmpdata_ptr++;
		nb_bytes_tofill--;
	}
}

int	prepare_echo_request_packet(char *packet, struct sockaddr_in *target_ip, int id_icmp, int seq_icmp, t_options *options)
{
	struct ip ip;
	struct icmp icmp;

	ft_bzero(packet, sizeof(struct ip) + 8 + options->icmp_datasize);
	ft_bzero(&ip, sizeof(ip));
	ft_bzero(&icmp, sizeof(icmp));
	ip.ip_hl = 0x5; //5 x 32 bits = 20 bytes (ip basic header size)
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = htons(sizeof(struct ip) + 8 + options->icmp_datasize); //20 bytes ip header + 8 bytes icmp header + 56 bytes icmp data
	ip.ip_id = 0x0;
	ip.ip_off = 0x0 | ntohs(IP_DF);
	ip.ip_ttl = options->ttl;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0x0;
	ip.ip_src.s_addr = options->source_ip.s_addr;
	ip.ip_dst.s_addr = target_ip->sin_addr.s_addr;
	ip.ip_sum = inet_checksum(&ip, sizeof(ip));
	ft_memcpy(packet, &ip, sizeof(ip));

	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_hun.ih_idseq.icd_id = htons(id_icmp);
	icmp.icmp_hun.ih_idseq.icd_seq = htons(seq_icmp);
	icmp.icmp_cksum = inet_checksum(&icmp, sizeof(icmp));
	ft_memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));
	fill_icmpdatapattern(packet, options->pattern, options->icmp_datasize);
	return(0);
}

void sig_handler(int signum)
{
	if (signum == SIGALRM)
		activate_flag(&global_flags, FLAG_SIGALRM);
	else if (signum == SIGINT)
		activate_flag(&global_flags, FLAG_SIGINT);
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

double calculate_msduration(struct timeval *start, struct timeval *end)
{
	double duration;

	duration = (end->tv_sec - start->tv_sec) * 1000.0;
	duration += (end->tv_usec - start->tv_usec) / 1000.0;
	return (duration);
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
	sizeof(struct ip) + 8 + options->icmp_datasize);
	return (0);
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

void print_rtt_stats(double min_rtt, double max_rtt, double sum_duration, int nb_packets_received, double sum_duration_stddev)
{
	double average;
	double std_deviation;

	average = get_average(sum_duration, nb_packets_received);
	std_deviation = get_std_deviation(average, sum_duration_stddev, nb_packets_received);
	ft_printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min_rtt, \
	average, max_rtt, std_deviation);
}

int	print_end_statistics(int nb_packets_sent, int nb_packets_received, int nb_packets_error, struct timeval *tv_start_ping, double min_rtt, double max_rtt, double sum_duration, double sum_duration_stddev)
{
	int percent_loss;
	double full_duration;
	struct timeval tv_end_ping;

	gettimeofday(&tv_end_ping, NULL);
	full_duration = calculate_msduration(tv_start_ping, &tv_end_ping) / 1000;
	if (nb_packets_sent == 0)
		percent_loss = 0;
	else
		percent_loss = (1 - ((double)nb_packets_received/(double)nb_packets_sent)) * 100;
	ft_printf("\n--- ping statistics ---\n");
	if (nb_packets_error != 0)
		ft_printf("%d packets transmitted, %d received, +%d errors, %d%% packet loss, time %.3fs\n", \
		nb_packets_sent, nb_packets_received, nb_packets_error, percent_loss, full_duration);
	else
	{
		ft_printf("%d packets transmitted, %d received, %d%% packet loss, time %.3fs\n", \
		nb_packets_sent, nb_packets_received, percent_loss, full_duration);
		print_rtt_stats(min_rtt, max_rtt, sum_duration, nb_packets_received, sum_duration_stddev);
	}
	return (0);
}

int check_stop_ping(t_options *options, unsigned int nb_packets_sent)
{
	if (options->count == 0)
		return (0);
	else if (nb_packets_sent == options->count)
		return (1);
	return (0);
}

void get_minmax_rtt(double duration, double *min_rtt, double *max_rtt)
{
	if (duration < *min_rtt)
		*min_rtt = duration;
	else if (duration > *max_rtt)
		*max_rtt = duration;
}

int ping_loop(struct sockaddr_in *target_ip, char *packet, t_options *options)
{
	int sockfd;

	int id_icmp;
	int seq_icmp;

	struct timeval tv_start_ping; 
	struct timeval tv_start_rtt;
	struct timeval tv_end_rtt;
	double			duration;
	double			sum_duration;
	double			sum_duration_stddev;
	double			min_rtt;
	double			max_rtt;
	gettimeofday(&tv_start_ping, NULL);
	min_rtt = 0.0;
	max_rtt = 0.0;
	duration = 0.0;
	sum_duration = 0.0;
	sum_duration_stddev = 0.0;

	int nb_bytes_received;
	nb_bytes_received = 0;

	unsigned int nb_packets_sent;
	unsigned int nb_packets_received;
	unsigned int nb_packets_error;
	nb_packets_sent = 0;
	nb_packets_received = 0;
	nb_packets_error = 0;

	id_icmp = getpid() & 0xFFFF;
	seq_icmp = 1;

	signal(SIGALRM, sig_handler);
	signal(SIGINT, sig_handler);

	sockfd = create_socket();
	setup_socket(sockfd, options);
	while (is_flag_on(global_flags, FLAG_SIGINT) == 0 && check_stop_ping(options, nb_packets_sent) == 0)
	{
		prepare_echo_request_packet(packet, target_ip, id_icmp, seq_icmp, options);
		gettimeofday(&tv_start_rtt, NULL);
		send_echo_request(sockfd, target_ip, packet, options);
		nb_packets_sent++;
		if (is_flag_on(global_flags, FLAG_F) == 0)
			alarm(options->interval);
		nb_bytes_received = receive_echo_reply(sockfd, packet, options);
		gettimeofday(&tv_end_rtt, NULL);
		if (nb_bytes_received >= 0)
		{
			duration = calculate_msduration(&tv_start_rtt, &tv_end_rtt);
			sum_duration += duration;
			sum_duration_stddev += duration * duration;
			if (nb_packets_sent == 1)
			{
				min_rtt = duration;
				max_rtt = duration;
			}
			if (print_packet_stats(packet, nb_bytes_received, seq_icmp, duration) == 0)
			{
				get_minmax_rtt(duration, &min_rtt, &max_rtt);
				nb_packets_received++;
			}
			else
				nb_packets_error++;
		}
		if (is_flag_on(global_flags, FLAG_F) == 0)
		{
			while (is_flag_on(global_flags, FLAG_SIGALRM | FLAG_SIGINT) == 0)
				;
		}
		deactivate_flag(&global_flags, FLAG_SIGALRM);
		seq_icmp++;
	}
	print_end_statistics(nb_packets_sent, nb_packets_received, nb_packets_error, &tv_start_ping, min_rtt, max_rtt, sum_duration, sum_duration_stddev);
	return (0);

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

void error_exit(char *errorstr)
{
	ft_dprintf(STDERR_FILENO, "ft_ping: %{r}s\n", errorstr);
	exit(2);
}

void print_usage()
{
	ft_dprintf(STDERR_FILENO, "Usage: ./ft_ping [-vhfq] [-c count] [-i interval] "
	"[-p pattern] [-s icmp_data_size] [-S source_ip] [-t ttl] "
	"[-W timeout] DESTINATION\n");
	exit(2);
}

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
		(ft_atoi(optarg) >= 0 && ft_atoi(optarg) <= 1000) ? options->icmp_datasize = ft_atoi(optarg) \
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

int main(int argc, char *argv[])
{
	int target_argindex;
	struct sockaddr_in target_ip;
	t_options options;	
	//char packet[PACKET_SIZE]; //with ip
	char packet[1028];

	target_ip.sin_family = AF_INET;
	if (getuid() != 0)
		error_exit("This utility requires root privileges to use raw sockets");
	if (argc <= 1)
		print_usage();
	init_options(&options);
	target_argindex = parse_options(argc, argv, &options);

	if (!(argv[target_argindex]))
		error_exit("No destination !");
	hostname_to_ip(argv[target_argindex], &(target_ip.sin_addr));
	print_start_info(&target_ip, argv[target_argindex], &options);
	ping_loop(&target_ip, packet, &options);
	return(0);
}
