void activate_flag(char *flags, char flag)
{
	*flags |= flag;
}

void deactivate_flag(char *flags, char flag)
{
	*flags &= ~(flag);
}

int	is_flag_on(char flags, char flag)
{
	if (flags & flag)
		return (1);
	return (0);
}
