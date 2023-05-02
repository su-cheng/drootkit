/*
 * @Author: su-cheng
 * @Description: 
 *    This is the kernel module used to recover system calls.
 *    This module requires four parameters:
 *        1. sys_call_table_addr: Address corresponding to the symbol 'sys_call_table'.
 *        2. syscall_nr: The id of the tampered system call.
 *        3. syscall_addr: The correct address of the tampered system call.
 *        4. init_mm_addr: Address corresponding to the symbol 'init_mm'.
 * @TODO：
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

static void **syscall_table;

typedef long (*syscall_fn_t)(const struct pt_regs *regs);

static struct mm_struct *g_init_mm;
static unsigned long address;
static unsigned long size;

static unsigned long sys_call_table_addr = 0;
module_param(sys_call_table_addr, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static int syscall_nr = -1;
module_param(syscall_nr, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static unsigned long syscall_addr = 0;
module_param(syscall_addr, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static unsigned long init_mm_addr = 0;
module_param(init_mm_addr, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

static int change_pte_memory(pmd_t *pmdp, struct mm_struct *mm,
		unsigned long start,
		unsigned long end, bool writable)
{
	pte_t *ptep;
	pte_t pte;
	pte_t pte_entry;
	pmd_t pmd = READ_ONCE(*pmdp);
	spinlock_t *lock;

	if (pmd_none(pmd))
		return -EINVAL;

	lock = pte_lockptr(mm, pmdp);
	ptep = pte_offset_kernel(pmdp, start);
	do {
		pte = READ_ONCE(*ptep);
		pr_info(", pte=%016llx\n", pte_val(pte));
		if (pte_none(pte)) {
			printk("invalid pte\n");
			pte_unmap_unlock(ptep, lock);
			return -EFAULT;
		}

		pte_entry = pte_mkyoung(pte);
		if (writable) {
			if (pte_write(pte))
				goto out;
			pte_entry = pte_mkwrite(pte_entry);
		} else {
			if (!pte_write(pte))
				goto out;
			pte_entry = pte_wrprotect(pte_entry);
		}
		pr_info("after change pte=%016llx\n", pte_val(pte_entry));
		set_pte(ptep, pte_entry);

		/* update new mapping of this page */
		flush_dcache_page(pte_page(pte));
		flush_tlb_kernel_range(start, start + PAGE_SIZE);
	} while (ptep++, start += PAGE_SIZE, start != end);

out:
	pte_unmap_unlock(ptep, lock);
	return 0;
}

static int change_pmd_memory(pud_t *pudp, struct mm_struct *mm,
		unsigned long start,
		unsigned long end, bool writable)
{
	unsigned long next;
	int ret = 0;
	pmd_t *pmdp;
	pmd_t pmd, pmd_entry;
	pud_t pud = READ_ONCE(*pudp);

	if (pud_none(pud))
		return -EINVAL;

	pmdp = pmd_offset(pudp, start);
	pmd = READ_ONCE(*pmdp);
	pr_info(", pmd=%016llx\n", pmd_val(pmd));
	if (pmd_none(pmd)) {
		pr_err("invalid pmd\n");
		return -EFAULT;
	}
	else if (pmd_sect(pmd)) {
		pmd_entry = pmd_mkyoung(pmd);
		flush_tlb_kernel_range(start, end);
		if (writable) {
			if (pmd_write(pmd))
				goto out;
			pmd_entry = pmd_mkwrite(pmd_entry);
		} else {
			if (!pmd_write(pmd))
				goto out;
			pmd_entry = pmd_wrprotect(pmd_entry);
		}
		pr_info("after change pmd=%016llx\n", pmd_val(pmd_entry));
		set_pmd(pmdp, pmd_entry);
		flush_tlb_kernel_range(start, end);
		return 0;
	}

	do {
		next = pmd_addr_end(start, end);
		if (next < end)
			next = end;
		ret = change_pte_memory(pmdp, mm, start, next, writable);
		if (ret)
			break;
	} while (pmdp++, start = next, start != end);

	return ret;
out:
	return 0;
}

static int change_pud_memory(pgd_t *pgdp, struct mm_struct *mm,
		unsigned long start,
		unsigned long end, bool writable)
{
	unsigned long next;
	int ret;
	pud_t *pudp;
	pud_t pud;
	pgd_t pgd = READ_ONCE(*pgdp);

	if (pgd_none(pgd))
		return -EINVAL;

	pudp = pud_offset((p4d_t *)pgdp, start);
	pud = READ_ONCE(*pudp);
	pr_info(", pud=%016llx\n", pud_val(pud));
	if (pud_none(pud))
		return -EFAULT;

	do {
		next = pud_addr_end(start, end);
		ret = change_pmd_memory(pudp, mm, start, next, writable);
		if (ret)
			break;
	} while (pudp++, start = next, start != end);

	return 0;
}

static int change_memory_writable(unsigned long addr, struct mm_struct *mm,
		unsigned long size,
		bool writable)
{
	unsigned long start, end, next;
	int ret;
	pgd_t *pgdp;
	pgd_t pgd;

	/* pgd */
	pgdp = pgd_offset(g_init_mm, addr);
	pgd = READ_ONCE(*pgdp);
	pr_info("[%016lx] pgd=%016llx\n", addr, pgd_val(pgd));
	if (pgd_none(pgd) || pgd_bad(pgd))
		return -EFAULT;

	end = addr + size;
	start = addr & PAGE_MASK;
	end = (end + PAGE_SIZE) & PAGE_MASK;

	pr_info("align: start=0x%lx, end=0x%lx, size=%ld\n", start, end, size);

	do {
		next = pgd_addr_end(start, end);
		ret = change_pud_memory(pgdp, mm, start, next, writable);
		if (ret)
			break;
	} while(pgdp++, start = next, start !=end);

	return ret;
}

static int __init syscall_init(void)
{	
	if (sys_call_table_addr == 0) {
		printk(KERN_INFO "Please input param: sys_call_table_addr...\n");
		return 0;
	}

	if (syscall_nr == -1) {
		printk(KERN_INFO "Please input param: syscall_nr...");
		return 0;
	}
	
	if (syscall_addr == 0) {
		printk(KERN_INFO "Please input param: syscall_addr...\n");
		return 0;
	}

	if (init_mm_addr == 0) {
		printk(KERN_INFO "Please input param: init_mm_addr...\n");
		return 0;
	}

	int ret;

	syscall_table = (void **)sys_call_table_addr;
	if (!syscall_table) {
		pr_err("Cannot find the sys_call_table\n"); 
		return -EFAULT;
	}

	address = (unsigned long)syscall_table;
	size = sizeof(syscall_fn_t) * __NR_syscalls;

	pr_info("Found the sys_call_table at 0x%16lx ~ 0x%16lx\n", address, address+size);

	g_init_mm = (struct mm_struct *)init_mm_addr;
	if (!g_init_mm) {
		pr_err("Cannot find init_mm\n");
		return -EFAULT;
	}

	printk(KERN_INFO "restore back the syscall\n");

	ret = change_memory_writable(address, g_init_mm, size, 1);
	if (ret) {
		pr_err("cannot change page writable\n");
		return ret;
	}

	pr_info("before change: sys_call_table[%d] at %16lx.\n",
			syscall_nr, (unsigned long)syscall_table[syscall_nr]);

	syscall_table[syscall_nr] = (syscall_fn_t)syscall_addr;

	pr_info("after change: sys_call_table[%d] at %16lx.\n",
		syscall_nr, (unsigned long)syscall_table[syscall_nr]);
			
	ret = change_memory_writable(address, g_init_mm, size, 0);
	if (ret) {
		printk("cannot change page writable\n");
	}

	return ret;
}

static void __exit syscall_release(void)
{
	printk(KERN_INFO "Successfully recovered system call!\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Recovery syscall dynamically");
module_init(syscall_init);
module_exit(syscall_release);
