CC= gcc
CFLAGS= -nostdlib -nostartfiles -fPIC
ASM= nasm
ASMFLAGS= -f elf64

all: hostile pivirus

hostile: hostile.s 
	$(ASM) $(ASMFLAGS) -o hostile.o hostile.s

pivirus: pivirus.c
	$(CC) pivirus.c hostile.o $(CFLAGS) -o pivirus

clean:
	rm *.o
