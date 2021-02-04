#ifndef PIEHOOK_UTILS
#define PIEHOOK_UTILS
#include "piehook_include.h"

extern unsigned int __piehook__force_order;

void 
printhex(void *addr, unsigned long long length){
    unsigned long long i = 0;
    for(i = 0; i < length; i ++){
        if((i) % 4 == 0){
            printk(KERN_CONT"\t");
        }
        if((i) % 16 == 0){
            printk(KERN_CONT"\n");
        }
        printk(KERN_CONT"%02x ", ((unsigned char *)addr)[i]);
    }
}

inline void mywrite_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__piehook__force_order));
}

void
disable_write_protection(void){
    unsigned long cr0;
    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();
    return;
}

unsigned long
search_call(unsigned long search_start, unsigned long call_target, unsigned long limit){
    unsigned long long i, cursor;
    int call_offset;
    for(i = 0; i < limit; i ++){
        cursor = search_start + i;
        // call or jmp
        if(*(unsigned char *)cursor == 0xe8 || *(unsigned char *)cursor == 0xe9){
            call_offset = *(int *)(cursor + 1);
            if(call_offset == (call_target - cursor - 5)){
                return cursor;
            }
        }
    }
    return 0;
}

void
enable_write_protection(void){
    unsigned long cr0;
    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();
    
}

unsigned int call_opnum(unsigned long calladdr, unsigned long targetaddr){
    int result = targetaddr - (calladdr + 5);
    return (unsigned int)result;
}

int edit_call(unsigned long calladdr, unsigned long targetaddr){
    if (*(unsigned char *)calladdr != 0xe8 && *(unsigned char *)calladdr != 0xe9){
        printk("[piehook] \"edit_call\" calladdr not a call instruction.\n");
        return -1;
    }
    *(unsigned int *)(calladdr + 1) = call_opnum(calladdr, targetaddr);
    return 0;
}

#endif