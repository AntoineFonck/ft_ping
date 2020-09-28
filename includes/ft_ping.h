#ifndef FT_PING_H
# define FT_PING_H

# include <netdb.h>

int hostname_to_ip(char *hostname, struct in_addr *ip);

#endif
