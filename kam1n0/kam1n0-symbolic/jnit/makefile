all:

ifeq ($(OS),Windows_NT)
all: all-win
else
all: all-linux
endif

all-win: 
	make -f makefile-windows rebuild

all-linux: 
	make -f makefile-linux rebuild