#ifndef STATS_CALCULATIONS_H
# define STATS_CALCULATIONS_H

double  calculate_msduration(struct timeval *start, struct timeval *end);
double  get_average(double accumulation, int nb_elem);
double  get_std_deviation(double average, double accumulation, int nb_elem);
int     calculate_percentloss(unsigned int nb_packets_sent, unsigned int nb_packets_received);

void    handle_stats(char *packet, t_singleping_stats *singleping_stats, t_fullping_stats *fullping_stats);

#endif