ifneq ($(OS),Windows_NT)
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		CCFLAGS += -D LINUX_BACKTRACES
	endif
endif

all:
	EXTRA_CFLAGS="-m64 -fPIC -w $(CCFLAGS)" make -f Makefile-gcc

clean:
	make -f Makefile-gcc clean
