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

	hdrincl = 1;
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
	if (sendto(sockfd, packet, 84, 0, (struct sockaddr *)ip, sizeof(*ip)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "sendto error %{r}s\n", strerror(errno));
		exit(1);
	}
	return(0);
}

int	receive_echo_reply(int sockfd, struct sockaddr_in *target_ip, char *packet)
{
	//socklen_t addr_len;

	int nb_bytes_rcvd;

	struct iovec iovec[1];
	struct msghdr msghdr;

	ft_bzero(packet, 84);
	iovec[0].iov_base = packet;
	iovec[0].iov_len = 84;

	msghdr.msg_name = target_ip;
	msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_iov = iovec;
	msghdr.msg_iovlen = 1;

	if ((nb_bytes_rcvd = recvmsg(sockfd, &msghdr, 0)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "recvmsg error %{r}s\n", strerror(errno));
	}
/*
	struct ip *ip_test;
	ip_test = (struct ip *)packet;
	ft_printf("test ip receive %d\n", ip_test);
	struct icmp *icmp_test;
	icmp_test = (struct icmp *)packet + sizeof(struct ip);
	ft_printf("test icmp receive %d\n", icmp_test->icmp_hun.ih_idseq.icd_id);
*/
	ft_printf("nb bytes received = %d\n", nb_bytes_rcvd);
	if (inet_checksum(packet, nb_bytes_rcvd) != 0)
		ft_dprintf(STDERR_FILENO, "error checksum\n");
	return(0);
}

int	prepare_echo_request_packet(char *packet, struct sockaddr_in *target_ip, int id_icmp, int seq_icmp)
{
	struct ip ip;
	struct icmp icmp;

	ft_bzero(packet, 84);
	ip.ip_hl = 0x5;
	ip.ip_v = 0x4;
	ip.ip_tos = 0x0;
	ip.ip_len = htons(60);
	ip.ip_id = 0x0;
	ip.ip_off = 0x0;
	ip.ip_ttl = 64;
	ip.ip_p = IPPROTO_ICMP;
	ip.ip_sum = 0x0;
	/*if (inet_pton(AF_INET, "192.168.0.26", &ip.ip_src.s_addr) == 0)
	{
		ft_dprintf(STDERR_FILENO, "inet_pton error = %{r}s\n", "source address malformed");
		exit(2);
	}*/
	ip.ip_src.s_addr = 0;
	ip.ip_dst.s_addr = target_ip->sin_addr.s_addr;
	ft_printf("ip packet dst address = %4x\n", ip.ip_dst.s_addr);
	ip.ip_sum = inet_checksum(&ip, sizeof(ip));
	ft_memcpy(packet, &ip, sizeof(ip));
	ft_printf("struct ip size = %{g}d bytes\n", sizeof(ip));

	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_hun.ih_idseq.icd_id = id_icmp;
	icmp.icmp_hun.ih_idseq.icd_seq = seq_icmp;
	icmp.icmp_cksum = inet_checksum(&icmp, sizeof(icmp));
	ft_memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));
	ft_printf("struct icmp size = %{g}d bytes\n", sizeof(icmp));
	return(0);
}

void sig_handler(int signum)
{
	if (signum == SIGALRM)
	{
		ft_printf("Packet timeout\n");
		//exit(2);
	}
}

int ping_loop(struct sockaddr_in *target_ip, char *packet)
{
	int sockfd;

	int id_icmp;
	int seq_icmp;

	//struct timeval time;

	id_icmp = getpid() & 0xFFFF;
	seq_icmp = 0;

	signal(SIGALRM, sig_handler);

	sockfd = create_socket();
	setup_socket(sockfd);
	while (1)
	{
		prepare_echo_request_packet(packet, target_ip, id_icmp, seq_icmp);
		alarm(1);
		send_echo_request(sockfd, target_ip, packet);
		receive_echo_reply(sockfd, target_ip, packet);
		alarm(0);
		seq_icmp++;
	}
	return (0);

}

int main(int argc, char *argv[])
{
	struct sockaddr_in target_ip;
	char str_ip[16];
	target_ip.sin_family = AF_INET;

	char packet[84]; //with ip

	if (argc != 2 || ft_strstr(argv[1], "-h") != NULL)
	{
		ft_dprintf(STDERR_FILENO, "Usage: ft_ping %{g}s\n", "destination");
		return(0);
	}

	hostname_to_ip(argv[1], &(target_ip.sin_addr));
	ft_dprintf(STDERR_FILENO, "ip of %s is %4x\n", argv[1], target_ip.sin_addr.s_addr);
	inet_ntop(AF_INET, &target_ip.sin_addr, str_ip, INET_ADDRSTRLEN);
	ft_dprintf(STDERR_FILENO, "ip of %s is %s\n", argv[1], str_ip);
	ping_loop(&target_ip, packet);
	return(0);
}
