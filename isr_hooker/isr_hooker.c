#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/desc.h>
#include <asm/traps.h>

/* refer: arch/x86/include/asm/traps.h */
#define TRAP_NR X86_TRAP_DE

static struct desc_ptr old_idtr, new_idtr;
static unsigned long orig_isr;

asmlinkage void stub(void);
asm(	
	".text				\n"
	".type	stub, @function		\n"
	"stub:				\n"
	"	jmp *orig_isr		\n"
);

static int isr_hooker_init(void)
{
	gate_desc *old_idt, *new_idt;
	unsigned long new_idt_page;

	pr_info("%s\n", __func__);

	/* obtain IDT descriptor */
	store_idt(&old_idtr);
	old_idt = (gate_desc *)old_idtr.address;

	/* prepare new IDT */
	new_idt_page = __get_free_page(GFP_KERNEL);
	if(!new_idt_page)
		return -ENOMEM;

	new_idtr.address = new_idt_page;
	new_idtr.size = old_idtr.size;
	new_idt = (gate_desc *)new_idtr.address;

	memcpy(new_idt, old_idt, old_idtr.size);

	/* modify the target entry */
	orig_isr = gate_offset(new_idt[TRAP_NR]);
	pr_info("orig_isr@%p\n", (void*)orig_isr);
	pack_gate(&new_idt[TRAP_NR], GATE_INTERRUPT, (unsigned long)stub, 0, 0, __KERNEL_CS);

	/* setup new entry */
	load_idt((void *)&new_idtr);
	smp_call_function((smp_call_func_t)load_idt, &new_idtr, 1);

	return 0;
}


static void isr_hooker_exit(void)
{
	pr_info("%s\n", __func__);

	/* restore entry */
	load_idt((void *)&old_idtr);
	smp_call_function((smp_call_func_t)load_idt, &old_idtr, 1);
	free_page(new_idtr.address);
}

MODULE_LICENSE("GPL");
module_init(isr_hooker_init);
module_exit(isr_hooker_exit);
