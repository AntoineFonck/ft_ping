#include "libft.h"
#include "ft_ping.h"
#include "flags.h"

#include <signal.h>
#include <netinet/ip_icmp.h>

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

void sig_handler(int signum)
{
	if (signum == SIGALRM)
		activate_flag(&global_flags, FLAG_SIGALRM);
	else if (signum == SIGINT)
		activate_flag(&global_flags, FLAG_SIGINT);
}

int check_stop_ping(t_options *options, unsigned int nb_packets_sent)
{
	if (options->count == 0)
		return (0);
	else if (nb_packets_sent == options->count)
		return (1);
	return (0);
}

void wait_interval()
{
	if (is_flag_on(global_flags, FLAG_F) == 0)
	{
		while (is_flag_on(global_flags, FLAG_SIGALRM | FLAG_SIGINT) == 0)
			;
	}
	deactivate_flag(&global_flags, FLAG_SIGALRM);
}

int ping_continue(t_options *options, t_fullping_stats *fullping_stats)
{
	if (is_flag_on(global_flags, FLAG_SIGINT) == 1 \
	|| check_stop_ping(options, fullping_stats->nb_packets_sent) == 1)
		return (0);
	else
		return (1);
}

void error_exit(char *errorstr)
{
	ft_dprintf(STDERR_FILENO, "ft_ping: %{r}s\n", errorstr);
	exit(2);
}

int is_icmp_type(char *packet, int icmp_type)
{
	struct icmp *icmp;

	icmp = (struct icmp *)(packet + sizeof(struct ip));
	if (icmp->icmp_type == icmp_type) 
		return (1);
	else
		return (0);
}
