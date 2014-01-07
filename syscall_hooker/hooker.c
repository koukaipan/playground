#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>

unsigned long *sys_call_table;

static unsigned long orig_syscall;
static int cnt = 0;

asmlinkage void my_func(void)
{
	cnt++;
	return;
}

asmlinkage void stub(void);
asm(	
	".text				\n"
	".type	stub, @function		\n"
	"stub:				\n"
	"	call my_func		\n"
	"	jmp *orig_syscall	\n"
);

/** 
 * NOTE:
 *  * the prototype of lookup_address() is changed in 2.6.25
 *  * lookup_address() is not exported until 2.6.27
 */
static void make_page_rw(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	*pte = pte_mkwrite(*pte);
	flush_cache_all();
}

static void make_page_ro(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	*pte = pte_wrprotect(*pte);
	flush_cache_all();
}

#define SYSCALL_NUM	__NR_write
static int hooker_init(void)
{
	pr_info("%s\n", __func__);

	/* obtain sys_call_table addr. */
	/* FIXME: how to obtain this addr. dynamically */
	sys_call_table = (unsigned long*)0xffffffff81801320;
	orig_syscall = sys_call_table[SYSCALL_NUM];
	pr_info("orig_syscall = 0x%8lx\n", orig_syscall);

	/* modify the target entry */
	make_page_rw((unsigned long)sys_call_table);
	sys_call_table[SYSCALL_NUM] = (unsigned long)stub;
	make_page_ro((unsigned long)sys_call_table);

	return 0;
}


static void hooker_exit(void)
{
	pr_info("%s: # of occurrence in syscall(%d) = %d\n", __func__, SYSCALL_NUM, cnt);

	/* restore entry */
	make_page_rw((unsigned long)sys_call_table);
	sys_call_table[SYSCALL_NUM] = orig_syscall;
	make_page_ro((unsigned long)sys_call_table);
}

MODULE_LICENSE("GPL");
module_init(hooker_init);
module_exit(hooker_exit);
