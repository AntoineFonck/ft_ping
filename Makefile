NAME = ft_ping
DEBUG_NAME = ft_ping_debug

CC = gcc

CFLAGS = -Wall -Werror -Wextra 
DEBUGFLAGS = -Wall -Werror -Wextra -g

LDFLAGS = -L$(LIBFT_DIRECTORY)
LDLIBS = -lft -lm

INCLUDES = -I$(HEADERS_DIRECTORY) -I$(LIBFT_HEADER)
HARD_DBG ?= 1

CURRENT_DIR = $(shell pwd)

LIBFT = $(LIBFT_DIRECTORY)libft.a
LIBFT_DIRECTORY = ./libft/
LIBFT_HEADER = $(LIBFT_DIRECTORY)

HEADERS_LIST = ft_ping.h \

HEADERS_DIRECTORY = ./includes/
HEADERS = $(addprefix $(HEADERS_DIRECTORY), $(HEADERS_LIST))

SOURCES_DIRECTORY = ./src/
SOURCES_LIST = main.c \
	       resolve_hostname.c

SOURCES = $(addprefix $(SOURCES_DIRECTORY), $(SOURCES_LIST))

OBJECTS_DIRECTORY = objects/
OBJECTS_DIRECTORY_DEBUG = objects_debug/

OBJECTS_LIST = $(patsubst %.c, %.o, $(SOURCES_LIST))
OBJECTS = $(addprefix $(OBJECTS_DIRECTORY), $(OBJECTS_LIST))
OBJECTS_DEBUG = $(addprefix $(OBJECTS_DIRECTORY_DEBUG), $(OBJECTS_LIST))

# COLORS

GREEN = \033[0;32m
RED = \033[0;31m
RESET = \033[0m

.PHONY: all clean fclean re debug

all: $(NAME)

$(NAME): $(LIBFT) $(OBJECTS_DIRECTORY) $(OBJECTS)
	@$(CC) $(INCLUDES) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(NAME)
	@echo "\n$(NAME): $(GREEN)object files were created$(RESET)"
	@echo "$(NAME): $(GREEN)$(NAME) was created$(RESET)"

$(OBJECTS_DIRECTORY):
	@mkdir -p $(OBJECTS_DIRECTORY)
	@echo "$(NAME): $(GREEN)$(OBJECTS_DIRECTORY) was created$(RESET)"

$(OBJECTS_DIRECTORY_DEBUG):
	@mkdir -p $(OBJECTS_DIRECTORY_DEBUG)
	@echo "$(DEBUG_NAME): $(GREEN)$(OBJECTS_DIRECTORY_DEBUG) was created$(RESET)"

$(OBJECTS_DIRECTORY)%.o : $(SOURCES_DIRECTORY)%.c $(HEADERS)
	@$(CC) $(CFLAGS) -c $(INCLUDES) $< -o $@
	@echo "$(GREEN).$(RESET)\c"

$(OBJECTS_DIRECTORY_DEBUG)%.o : $(SOURCES_DIRECTORY)%.c $(HEADERS)
ifeq ($(HARD_DBG), 1)
	@$(eval DEBUGFLAGS += -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined)
	@$(eval LDFLAGS += -fsanitize=address -fno-omit-frame-pointer -fsanitize=undefined)
endif

	@$(CC) $(DEBUGFLAGS) -c $(INCLUDES) $< -o $@
	@echo "$(GREEN).$(RESET)\c"

$(LIBFT):
	@echo "$(NAME): $(GREEN)Creating $(LIBFT)...$(RESET)"
	@$(MAKE) -sC $(LIBFT_DIRECTORY)

clean:
	@$(MAKE) -sC $(LIBFT_DIRECTORY) clean
	@rm -rf $(OBJECTS_DIRECTORY)
	@echo "$(NAME): $(RED)$(LIBFT_DIRECTORY) was cleaned$(RESET)"
	@echo "$(NAME): $(RED)$(OBJECTS_DIRECTORY) was deleted$(RESET)"
	@echo "$(NAME): $(RED)object files were deleted$(RESET)"

fclean: clean
	@$(MAKE) -sC $(LIBFT_DIRECTORY) fclean
	@echo "$(NAME): $(RED)$(LIBFT) was deleted$(RESET)"
	@rm -f $(NAME)
	@echo "$(NAME): $(RED)$(NAME) was deleted$(RESET)"

re:
	@$(MAKE) fclean
	@$(MAKE) all

debug: $(DEBUG_NAME)

$(DEBUG_NAME): $(LIBFT) $(OBJECTS_DIRECTORY_DEBUG) $(OBJECTS_DEBUG)
	@$(CC) $(INCLUDES) $(OBJECTS_DEBUG) $(LDFLAGS) $(LDLIBS) -o $(DEBUG_NAME)
	@echo "\n$(DEBUG_NAME): $(GREEN)object debug files were created$(RESET)"
	@echo "$(DEBUG_NAME): $(GREEN)$(DEBUG_NAME) was created$(RESET)"

debugclean:
	@rm -rf $(OBJECTS_DIRECTORY_DEBUG)
	@echo "$(DEBUG_NAME): $(RED)$(OBJECTS_DIRECTORY_DEBUG) was deleted$(RESET)"
	@echo "$(DEBUG_NAME): $(RED)debug objects files were deleted$(RESET)"

debugfclean: debugclean
	@rm -f $(DEBUG_NAME)
	@echo "$(DEBUG_NAME): $(RED)$(DEBUG_NAME) was deleted$(RESET)"

debugre:
	@$(MAKE) debugfclean
	@$(MAKE) debug

