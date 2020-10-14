#ifndef PING_RAWSOCKET_H
# define PING_RAWSOCKET_H

int create_socket();

int setup_socket(int fd, t_options *options);

#endif