#ifndef PREPARE_ECHOREQUEST_H
# define PREPARE_ECHOREQUEST_H

void    fill_icmpdatapattern(char *packet, char pattern, int nb_bytes_tofill);
void    fill_ip_header(struct ip *ip, struct sockaddr_in *target_ip, t_options *options);
void    fill_icmp_header(struct icmp *icmp, t_singleping_stats *singleping_stats);
int     prepare_echo_request_packet(char *packet, struct sockaddr_in *target_ip, t_singleping_stats *singleping_stats, t_options *options);

#endif