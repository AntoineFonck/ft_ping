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

uint16_t ip_checksum(void *addr, int count)
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

int prepare_echo_request(int fd, struct sockaddr_in *ip)
{
	const size_t req_size = 8;
	struct icmphdr req;

	req.type = 8;
	req.code = 0;
	req.checksum = 0;
	req.un.echo.id = htons(rand());
	req.un.echo.sequence = htons(1);
	req.checksum = ip_checksum(&req,req_size);
	if (sendto(fd, &req, req_size, 0, (struct sockaddr *)ip, sizeof(*ip)) == -1)
	{
		ft_dprintf(STDERR_FILENO, "sendto error %{r}s\n", strerror(errno));
		exit(1);
	}
	return(0);
}

int send_ping(struct sockaddr_in *target_ip)
{
	int fd;

	fd = create_socket();
	//setup_socket(fd);
	prepare_echo_request(fd, target_ip);
	return (0);

}

int main(int argc, char *argv[])
{
	struct sockaddr_in target_ip;
	char str_ip[16];
	target_ip.sin_family = AF_INET;
	if (argc != 2 || ft_strstr(argv[1], "-h") != NULL)
	{
		ft_dprintf(STDERR_FILENO, "Usage: ft_ping %{g}s\n", "destination");
		return(0);
	}
	hostname_to_ip(argv[1], &(target_ip.sin_addr));
	ft_dprintf(STDERR_FILENO, "ip of %s is %4x\n", argv[1], target_ip.sin_addr.s_addr);
	inet_ntop(AF_INET, &target_ip.sin_addr, str_ip, INET_ADDRSTRLEN);
	ft_dprintf(STDERR_FILENO, "ip of %s is %s\n", argv[1], str_ip);
	send_ping(&target_ip);
	return(0);
}
