#ifndef DISPLAY_H
# define DISPLAY_H

#include <netinet/ip_icmp.h>

void    print_help();
void    print_usage();

int     print_start_info(struct sockaddr_in *target_ip, char *hostname, t_options *options);

void    print_time_exceeded(char *str_ip, struct icmp *icmp, int seq_icmp);
void    print_destination_unreachable(char *str_ip, struct icmp *icmp, int seq_icmp);

int     print_packet_stats(char *packet, int nb_bytes_rcvd, int seq_icmp, double duration);
void    print_echo_reply(int icmp_size_received, char *str_ip, int seq_icmp, int ttl, double duration);
void    print_rtt_stats(double min_rtt, double max_rtt, double sum_duration, int nb_packets_received, double sum_duration_stddev);

void    print_end_error(t_fullping_stats *fullping_stats, int percent_loss, double full_duration);
void    print_end_normal(t_fullping_stats *fullping_stats, int percent_loss, double full_duration);
int     print_end_statistics(t_fullping_stats *fullping_stats, char *hostname);
#endif