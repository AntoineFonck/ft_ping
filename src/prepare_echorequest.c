#include "libft.h"
#include "ft_ping.h"
#include "utils.h"

#include <netinet/ip_icmp.h> 

void fill_icmpdatapattern(char *packet, char pattern, int nb_bytes_tofill)
{
	char *icmpdata_ptr;

	if (pattern == 0)
		return ;
	icmpdata_ptr = packet + sizeof(struct ip) + sizeof(struct icmphdr);
	while (nb_bytes_tofill > 0)
	{
		*icmpdata_ptr = pattern;
		icmpdata_ptr++;
		nb_bytes_tofill--;
	}
}

void fill_ip_header(struct ip *ip, struct sockaddr_in *target_ip, t_options *options)
{	
	ip->ip_hl = 0x5; //5 x 32 bits = 20 bytes (ip basic header size)
	ip->ip_v = 0x4;
	ip->ip_tos = 0x0;
	ip->ip_len = htons(sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize); //20 bytes ip header + 8 bytes icmp header + icmp data bytes (default=56)
	ip->ip_id = 0x0;
	ip->ip_off = 0x0 | ntohs(IP_DF);
	ip->ip_ttl = options->ttl;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_sum = 0x0;
	ip->ip_src.s_addr = options->source_ip.s_addr;
	ip->ip_dst.s_addr = target_ip->sin_addr.s_addr;
	ip->ip_sum = inet_checksum(ip, sizeof(ip));
}

void fill_icmp_header(struct icmp *icmp, t_singleping_stats *singleping_stats)
{
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_hun.ih_idseq.icd_id = htons(singleping_stats->id_icmp);
	icmp->icmp_hun.ih_idseq.icd_seq = htons(singleping_stats->seq_icmp);
	icmp->icmp_cksum = inet_checksum(icmp, sizeof(icmp));
}

int	prepare_echo_request_packet(char *packet, struct sockaddr_in *target_ip, t_singleping_stats *singleping_stats,/*int id_icmp, int seq_icmp,*/ t_options *options)
{
	struct ip ip;
	struct icmp icmp;

	ft_bzero(packet, sizeof(struct ip) + sizeof(struct icmphdr) + options->icmp_datasize);
	ft_bzero(&ip, sizeof(ip));
	ft_bzero(&icmp, sizeof(icmp));
	fill_ip_header(&ip, target_ip, options);
	ft_memcpy(packet, &ip, sizeof(ip));

	fill_icmp_header(&icmp, singleping_stats);
	ft_memcpy(packet + sizeof(ip), &icmp, sizeof(icmp));
	fill_icmpdatapattern(packet, options->pattern, options->icmp_datasize);
	return(0);
}
