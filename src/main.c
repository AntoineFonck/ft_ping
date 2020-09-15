#include "libft.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		(void)argv;
		ft_printf("nope, %{r}s\n", "bad");
		return(1);
	}
	return(0);
}
