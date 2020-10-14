#ifndef FT_PING_H
# define FT_PING_H

# include <netdb.h>

int hostname_to_ip(char *hostname, struct in_addr *ip);

typedef struct          s_options
{
    struct in_addr      source_ip;
    unsigned int        count;
    unsigned int        interval;
    unsigned int        icmp_datasize;
    unsigned int        timeout;
    uint8_t             ttl;
    char                pattern;
}                       t_options;

typedef struct          s_fullping_stats
{
	struct timeval      tv_start_ping; 
	struct timeval      tv_end_ping; 
	double  			sum_duration;
	double  			sum_duration_stddev;
	double  			min_rtt;
	double  			max_rtt;
	unsigned int        nb_packets_sent;
	unsigned int        nb_packets_received;
	unsigned int        nb_packets_error;
}                       t_fullping_stats;

typedef struct          s_singleping_stats
{
	struct timeval      tv_start_rtt;
	struct timeval      tv_end_rtt;
	double  			duration;
	int                 nb_bytes_received;
	int                 id_icmp;
	int                 seq_icmp;
}                       t_singleping_stats;

#endif
