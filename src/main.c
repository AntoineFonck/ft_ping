#include "libft.h"
#include "ft_ping.h"

int main(int argc, char *argv[])
{
	char ip[16];
	if (argc != 2 || ft_strstr(argv[1], "-h") != NULL)
	{
		ft_dprintf(STDERR_FILENO, "Usage: ft_ping %{g}s\n", "destination");
		return(0);
	}
	hostname_to_ip(argv[1], ip);
	ft_dprintf(STDERR_FILENO, "ip of %s is %s\n", argv[1], ip);
	return(0);
}
