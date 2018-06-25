%define ZERO_ARGS           0x0
%define WRITE_SYSCALL_NUM   0x1
%define STDOUT_FILENO       0x1
%define BUF_LEN             0x1
%define LOOP_COUNTER        0x8000
%define RANDOM_NUM          0x100

%macro do_write_syscall ZERO_ARGS 
    mov rdi, STDOUT_FILENO
    mov rdx, BUF_LEN
    mov rax, WRITE_SYSCALL_NUM
    syscall   
%endmacro

%macro func_ret ZERO_ARGS
    xor rax, rax
    ret
%endmacro

%macro save_regs ZERO_ARGS
    push rbx
    push rdx
    push rcx
    push rdi
    push rsi
    push r8
    push r9
    push r10
%endmacro

%macro restore_regs ZERO_ARGS
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rcx
    pop rdx
    pop rbx
%endmacro

%macro clear_regs ZERO_ARGS
    xor rax,rax
    xor rbx,rbx
    xor rcx,rcx
    xor rdx,rdx
    xor rdi,rdi
    xor rsi,rsi
    xor r8,r8
    xor r9,r9
    xor r10,r10
%endmacro
    
    
section .text

global pi_hostile_fclose, pi_get_hostile_len


pi_hostile_fclose:


    save_regs
    clear_regs
    
    push RANDOM_NUM

    lea rsi, [ rsp ]    
 
    mov rcx, LOOP_COUNTER

loop_start:
    
    inc byte [ rsi ] 
    
    push rcx
    
    do_write_syscall
    
    pop rcx
    
    loop loop_start

loop_end:

    pop rax
    restore_regs
    func_ret


pi_hostile_fclose_end:


pi_get_hostile_len:
    
    mov  rax, pi_hostile_fclose_end - pi_hostile_fclose
    ret
