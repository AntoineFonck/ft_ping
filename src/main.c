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

#define PACKET_SIZE 84

int interval_time_reached = 0;
int	sigint_received = 0;

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

int setup_socket(int fd)
{
	int hdrincl;
	struct timeval tv_timeout;

	hdrincl = 1;
	tv_timeout.tv_sec = 1;
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

int send_echo_request(int sockfd, struct sockaddr_in *ip, char *packet)
{
	if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)ip, sizeof(*ip)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "sendto error %{r}s\n", strerror(errno));
		exit(1);
	}
	return(0);
}

int	receive_echo_reply(int sockfd, struct sockaddr_in *target_ip, char *packet)
{
	int nb_bytes_rcvd;

	struct iovec iovec[1];
	struct msghdr msghdr;

	ft_bzero(packet, PACKET_SIZE);
	iovec[0].iov_base = packet;
	iovec[0].iov_len = PACKET_SIZE;

	(void)target_ip;
	//msghdr.msg_name = target_ip;
	//msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_name = NULL;
	msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_iov = iovec;
	msghdr.msg_iovlen = 1;

	if ((nb_bytes_rcvd = recvmsg(sockfd, &msghdr, MSG_WAITALL)) == -1)
	{
		//;
		ft_dprintf(STDERR_FILENO, "recvmsg error %{r}s\n", strerror(errno));
	}
	else if (inet_checksum(packet, nb_bytes_rcvd) != 0)
		ft_dprintf(STDERR_FILENO, "error checksum\n");
	return(nb_bytes_rcvd);
}

int	prepare_echo_request_packet(char *packet, struct sockaddr_in *target_ip, int id_icmp, int seq_icmp)
{
	struct ip ip;
	struct icmp icmp;

	ft_bzero(packet, PACKET_SIZE);
	ft_bzero(&ip, sizeof(ip));
	ft_bzero(&icmp, sizeof(icmp));
	ip.ip_hl = 0x5; //5 x 32 bits = 20 bytes (ip basic header size)
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = htons(PACKET_SIZE); //20 bytes ip header + 8 bytes icmp header + 56 bytes icmp data
	ip.ip_id = 0x0;
	//ip.ip_off = 0x0;
	ip.ip_off = 0x0 | ntohs(IP_DF);
	ip.ip_ttl = 64;
	//ip.ip_ttl = 1;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0x0;
	/*if (inet_pton(AF_INET, "192.168.0.21", &ip.ip_src.s_addr) == 0)
	{
		ft_dprintf(STDERR_FILENO, "inet_pton error = %{r}s\n", "source address malformed");
		exit(2);
	}*/
	ip.ip_src.s_addr = 0;
	ip.ip_dst.s_addr = target_ip->sin_addr.s_addr;
	//ft_printf("ip packet dst address = %4x\n", ip.ip_dst.s_addr);
	ip.ip_sum = inet_checksum(&ip, sizeof(ip));
	ft_memcpy(packet, &ip, sizeof(ip));
	//ft_printf("struct ip size = %{g}d bytes\n", sizeof(ip));

	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_hun.ih_idseq.icd_id = htons(id_icmp);
	icmp.icmp_hun.ih_idseq.icd_seq = htons(seq_icmp);
	icmp.icmp_cksum = inet_checksum(&icmp, sizeof(icmp));
	ft_memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));
	//ft_printf("struct icmp size = %{g}d bytes\n", sizeof(icmp));
	return(0);
}

void sig_handler(int signum)
{
	if (signum == SIGALRM)
	{
		interval_time_reached = 1;
	}
	else if (signum == SIGINT)
	{
		sigint_received = 1;
	}
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

int print_packet_stats(char *packet, int nb_bytes_rcvd, int seq_icmp, struct timeval tv_start, struct timeval tv_end)
{
	double duration;
	char str_ip[INET_ADDRSTRLEN];
	struct ip *ip;
	struct icmp *icmp;

	duration = (((double)tv_end.tv_sec * 1000000.0 + tv_end.tv_usec) - \
	((double)tv_start.tv_sec * 1000000.0 + tv_start.tv_usec)) / 1000;
	ip = (struct ip *)packet;
	icmp = (struct icmp *)(packet + sizeof(struct ip));
	inet_ntop(AF_INET, &(ip->ip_src), str_ip, INET_ADDRSTRLEN);
	//ft_printf("packet seq %d | calculated seq %d\n", ntohs(icmp->icmp_hun.ih_idseq.icd_seq), seq_icmp);
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
	return(1);
}

int print_start_info(struct sockaddr_in *target_ip, char *hostname)
{
	char str_ip[INET_ADDRSTRLEN];	

	inet_ntop(AF_INET, &(target_ip->sin_addr), str_ip, INET_ADDRSTRLEN);
	ft_printf("PING %s (%s) %d(%d) bytes of data.\n", hostname, str_ip, PACKET_SIZE \
	- (sizeof(struct ip) + sizeof(struct icmphdr)), PACKET_SIZE);
	return (0);
}

int	print_end_statistics(int nb_packets_sent, int nb_packets_received, int nb_packets_error)
{
	int percent_loss;

	if (nb_packets_sent == 0)
		percent_loss = 0;
	else
		percent_loss = (1 - ((double)nb_packets_received/(double)nb_packets_sent)) * 100;
	ft_printf("\n--- ping statistics ---\n");
	if (nb_packets_error != 0)
		ft_printf("%d packets transmitted, %d received, +%d errors, %d%% packet loss, time dms\n", \
		nb_packets_sent, nb_packets_received, nb_packets_error, percent_loss);
	else
		ft_printf("%d packets transmitted, %d received, %d%% packet loss, time dms\n", \
		nb_packets_sent, nb_packets_received, percent_loss);
	return (0);
}

int ping_loop(struct sockaddr_in *target_ip, char *packet)
{
	int sockfd;

	int id_icmp;
	int seq_icmp;

	struct timeval tv_start;
	struct timeval tv_end;

	int nb_bytes_received;
	nb_bytes_received = 0;

	int nb_packets_sent;
	int nb_packets_received;
	int nb_packets_error;
	nb_packets_sent = 0;
	nb_packets_received = 0;
	nb_packets_error = 0;

	id_icmp = getpid() & 0xFFFF;
	seq_icmp = 1;

	signal(SIGALRM, sig_handler);
	signal(SIGINT, sig_handler);

	sockfd = create_socket();
	setup_socket(sockfd);
	while (sigint_received == 0)
	{
		prepare_echo_request_packet(packet, target_ip, id_icmp, seq_icmp);
		gettimeofday(&tv_start, NULL);
		send_echo_request(sockfd, target_ip, packet);
		nb_packets_sent++;
		alarm(1);
		nb_bytes_received = receive_echo_reply(sockfd, target_ip, packet);
		gettimeofday(&tv_end, NULL);
		if (nb_bytes_received >= 0)
		{
			if (print_packet_stats(packet, nb_bytes_received, seq_icmp, tv_start, tv_end) == 0)
				nb_packets_received++;
			else
				nb_packets_error++;
		}
		while (interval_time_reached == 0 && sigint_received == 0)
			;
		interval_time_reached = 0;
		seq_icmp++;
	}
	print_end_statistics(nb_packets_sent, nb_packets_received, nb_packets_error);
	return (0);

}

int main(int argc, char *argv[])
{
	struct sockaddr_in target_ip;
	char str_ip[16];
	target_ip.sin_family = AF_INET;

	char packet[PACKET_SIZE]; //with ip

	if (argc != 2 || ft_strstr(argv[1], "-h") != NULL)
	{
		ft_dprintf(STDERR_FILENO, "Usage: ft_ping %{g}s\n", "destination");
		return(0);
	}

	hostname_to_ip(argv[1], &(target_ip.sin_addr));
	//ft_dprintf(STDERR_FILENO, "ip of %s is %4x\n", argv[1], target_ip.sin_addr.s_addr);
	inet_ntop(AF_INET, &target_ip.sin_addr, str_ip, INET_ADDRSTRLEN);
	//ft_dprintf(STDERR_FILENO, "ip of %s is %s\n", argv[1], str_ip);
	print_start_info(&target_ip, argv[1]);
	ping_loop(&target_ip, packet);
	return(0);
}
