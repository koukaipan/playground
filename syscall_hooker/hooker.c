#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>

#define SYSCALL_NUM	__NR_open

static unsigned long *sys_call_table;
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

static int readline(struct file *f, char *buf)
{
	int nr_bytes = 0;
	static loff_t pos = 0;

	memset(buf, 0, 100);
	while (nr_bytes < 100 && vfs_read(f, &buf[nr_bytes], 1, &pos) == 1) {
		if (buf[nr_bytes] == '\n') {
			buf[nr_bytes] = 0;
			nr_bytes++;
			break;
		}
		nr_bytes++;
	}

	return nr_bytes;
}

/**
 *  find out sys_call_table symbol from /proc/kallsyms
 */
#define PROC_KALLSYMS "/proc/kallsyms"
int find_sys_call_table(void)
{
	struct file *f;
	char buf[100];
	mm_segment_t old_fs;
	int ret, i;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	f = filp_open(PROC_KALLSYMS, O_RDONLY, 0);
	if (IS_ERR(f) || f == NULL) {
		pr_err("[SYSCALL_HOOKER] cannot open %s\n", PROC_KALLSYMS);
		ret = -ESRCH;
		goto err_fopen;
	}

	while(readline(f, buf) > 0)
		if(strstr(buf, "sys_call_table"))
			break;

	if (strlen(buf) == 0) {
		pr_err("[SYSCALL_HOOKER] cannot find sys_call_table addr. from %s\n", PROC_KALLSYMS);
		ret = -ESRCH;
		goto err;
	}

	for(i=0; i<100 && buf[i]; i++)
		if (buf[i] == ' ') {
			buf[i] = 0;
			break;
		}

	ret = kstrtoul(buf, 16, (unsigned long*)&sys_call_table);
	if (ret == 0)
		pr_info("[SYSCALL_HOOKER] found sys_call_table at %p\n", sys_call_table);
	else
		pr_err("[SYSCALL_HOOKER] error occured in parsing address of %s\n", buf);

err:
	filp_close(f, 0);
err_fopen:
	set_fs(old_fs);
	return ret;
}

static int hooker_init(void)
{
	int ret;
	pr_info("%s\n", __func__);

	/* obtain sys_call_table addr. */
	if ((ret = find_sys_call_table()) != 0)
		return ret;

	orig_syscall = sys_call_table[SYSCALL_NUM];
	pr_info("[SYSCALL_HOOKER] orig_syscall = 0x%lx\n", orig_syscall);

	/* modify the target entry */
	make_page_rw((unsigned long)sys_call_table);
	sys_call_table[SYSCALL_NUM] = (unsigned long)stub;
	make_page_ro((unsigned long)sys_call_table);

	return 0;
}

static void hooker_exit(void)
{
	pr_info("[SYSCALL_HOOKER] exit: # of occurrence in syscall(%d) = %d\n", SYSCALL_NUM, cnt);

	/* restore entry */
	make_page_rw((unsigned long)sys_call_table);
	sys_call_table[SYSCALL_NUM] = orig_syscall;
	make_page_ro((unsigned long)sys_call_table);
}

MODULE_LICENSE("GPL");
module_init(hooker_init);
module_exit(hooker_exit);
