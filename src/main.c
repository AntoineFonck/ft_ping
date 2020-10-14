#include "libft.h"
#include "ft_ping.h"
#include "flags.h"
#include "ping_rawsocket.h"
#include "display.h"
#include "stats_calculations.h"
#include "init.h"
#include "utils.h"
#include "prepare_echorequest.h"

#include <errno.h>
#include <sys/time.h>

char global_flags = 0;

int send_echo_request(int sockfd, struct sockaddr_in *ip, char *packet, t_options *options)
{
	if (sendto(sockfd, packet, sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize, 0, (struct sockaddr *)ip, sizeof(*ip)) == -1)
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

	ft_bzero(packet, sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize);
	iovec[0].iov_base = packet;
	iovec[0].iov_len = sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize;

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_iov = iovec;
	msghdr.msg_iovlen = 1;

	if ((nb_bytes_rcvd = recvmsg(sockfd, &msghdr, MSG_WAITALL)) == -1)
	{
		if (is_flag_on(global_flags, FLAG_V))
			ft_dprintf(STDERR_FILENO, "Timeout for receiving echo reply\n");
	}
	else if (inet_checksum(packet, nb_bytes_rcvd) != 0)
		ft_dprintf(STDERR_FILENO, "error checksum in received packet\n");
	return(nb_bytes_rcvd);
}

void send_ping(int sockfd, char *packet, struct sockaddr_in *target_ip, t_singleping_stats *singleping_stats, t_options *options, t_fullping_stats *fullping_stats)
{
	prepare_echo_request_packet(packet, target_ip, singleping_stats, options);
	gettimeofday(&(singleping_stats->tv_start_rtt), NULL); // start of timer for RTT calculations
	send_echo_request(sockfd, target_ip, packet, options);
	fullping_stats->nb_packets_sent++;
}

void receive_pong(int sockfd, char *packet, t_singleping_stats *singleping_stats, t_options *options)
{
	if (is_flag_on(global_flags, FLAG_F) == 0)	// if flood flag is off
		alarm(options->interval);				// launch alarm to wait for the reply
	singleping_stats->nb_bytes_received = receive_echo_reply(sockfd, packet, options);
	gettimeofday(&(singleping_stats->tv_end_rtt), NULL); // end of timer for RTT calculations
}

int ping_loop(struct sockaddr_in *target_ip, t_fullping_stats *fullping_stats, t_options *options)
{
	int sockfd;
	char packet[MAX_PACKET_SIZE];
	t_singleping_stats singleping_stats;

	init_fullping_stats(fullping_stats);
	init_singleping_stats(&singleping_stats);
	init_signals_handler();

	sockfd = create_socket();
	setup_socket(sockfd, options);
	while (ping_continue(options, fullping_stats) == 1)
	{
		send_ping(sockfd, packet, target_ip, &singleping_stats, options, fullping_stats);
		receive_pong(sockfd, packet, &singleping_stats, options);
		handle_stats(packet, &singleping_stats, fullping_stats);
		wait_interval();
		singleping_stats.seq_icmp++;
	}
	return (0);
}

int main(int argc, char *argv[])
{
	int target_argindex;
	struct sockaddr_in	target_ip;
	t_fullping_stats	fullping_stats;
	t_options options;	

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
	ping_loop(&target_ip, &fullping_stats, &options);
	print_end_statistics(&fullping_stats, argv[target_argindex]);
	return(0);
}
