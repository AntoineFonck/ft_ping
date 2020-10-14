#ifndef UTILS_H
# define UTILS_H

uint16_t    inet_checksum(void *addr, int count);

void        sig_handler(int signum);

void        wait_interval();

int         check_stop_ping(t_options *options, unsigned int nb_packets_sent);
int         ping_continue(t_options *options, t_fullping_stats *fullping_stats);

void        error_exit(char *errorstr);

int         is_icmp_type(char *packet, int icmp_type);

#endif