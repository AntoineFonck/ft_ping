#include "libft.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int hostname_to_ip(char *hostname, struct in_addr *ip)
{
	int			status;
	struct addrinfo		hints;
	struct addrinfo		*servinfo;
	struct sockaddr_in	*ipv4;

	ft_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(hostname, "http", &hints, &servinfo)) != 0)
	{
		ft_dprintf(STDERR_FILENO, "ft_ping: %s: %{r}s\n", hostname, gai_strerror(status));
		exit(2);
	}
	ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
	ip->s_addr = ipv4->sin_addr.s_addr;
	freeaddrinfo(servinfo);
	return (0);
}
