#ifndef HOOK_H
#define HOOK_H

#define HOOK_VERSION	0.1

#define HOOK_DEBUG

#ifdef HOOK_DEBUG
#define DbgPrint(format, args...) \
        printk("hook: function:%s-L%d: "format, __FUNCTION__, __LINE__, ##args);
#else
#define DbgPrint(format, args...)  do {} while(0);
#endif

#define SYS_REPLACE(x) 	orig_##x = sys_call_table[__NR_##x];	\
    			sys_call_table[__NR_##x] = new_##x

#define SYS_RESTORE(x)	sys_call_table[__NR_##x] = orig_##x

#define CLEAR_CR0	asm ("pushl %eax\n\t" 			\
				"movl %cr0, %eax\n\t"		\
				"andl $0xfffeffff, %eax\n\t" 	\
				"movl %eax, %cr0\n\t"		\
				"popl %eax");

#define SET_CR0		asm ("pushl %eax\n\t" 			\
				"movl %cr0, %eax\n\t" 		\
				"orl $0x00010000, %eax\n\t" 	\
				"movl %eax, %cr0\n\t"		\
				"popl %eax");
					

struct descriptor_idt
{
        unsigned short offset_low;	
        unsigned short ignore1;
        unsigned short ignore2;
        unsigned short offset_high;
};

static struct {
        unsigned short limit;
        unsigned long base;
}__attribute__ ((packed)) idt48;

void **sys_call_table;

asmlinkage ssize_t new_read(unsigned int fd, char __user * buf, size_t count);
asmlinkage ssize_t (*orig_read)(unsigned int fd, char __user * buf, size_t count);

#endif













