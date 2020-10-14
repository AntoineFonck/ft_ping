#ifndef FLAGS_H
# define FLAGS_H

enum e_flags
{
	FLAG_V = 1 << 0,
	FLAG_F = 1 << 1,
	FLAG_Q = 1 << 2,
	FLAG_SIGALRM = 1 << 3,
	FLAG_SIGINT = 1 << 4
};

extern char global_flags;

void	activate_flag(char *flags, char flag);

void	deactivate_flag(char *flags, char flag);

int		is_flag_on(char flags, char flag);

#endif