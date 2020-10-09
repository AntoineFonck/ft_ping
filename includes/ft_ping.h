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

#endif
