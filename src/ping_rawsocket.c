#include "libft.h"
#include "ft_ping.h"

#include <errno.h>

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