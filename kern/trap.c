#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	return "(unknown trap)";
}


void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	
	extern void h0(void);
	extern void h1(void);
	extern void h2(void);
	extern void h3(void);
	extern void h4(void);
	extern void h5(void);
	extern void h6(void);
	extern void h7(void);
	extern void h8(void);
	extern void h9(void);
	extern void h10(void);
	extern void h11(void);
	extern void h12(void);
	extern void h13(void);
	extern void h14(void);
	extern void h15(void);
	extern void h16(void);
	extern void h17(void);
	extern void h18(void);
	extern void h19(void);
	extern void h20(void);
	extern void h21(void);
	extern void h22(void);
	extern void h23(void);
	extern void h24(void);
	extern void h25(void);
	extern void h26(void);
	extern void h27(void);
	extern void h28(void);
	extern void h29(void);
	extern void h30(void);
	extern void h31(void);
	extern void h32(void);
	extern void h33(void);
	extern void h34(void);
	extern void h35(void);
	extern void h36(void);
	extern void h37(void);
	extern void h38(void);
	extern void h39(void);
	extern void h40(void);
	extern void h41(void);
	extern void h42(void);
	extern void h43(void);
	extern void h44(void);
	extern void h45(void);
	extern void h46(void);
	extern void h47(void);
	extern void h48(void);
	SETGATE(idt[0], 1, GD_KT, h0, 0);
	SETGATE(idt[1], 1, GD_KT, h1, 0);
	SETGATE(idt[2], 1, GD_KT, h2, 0);
	SETGATE(idt[3], 1, GD_KT, h3, 3);
	SETGATE(idt[4], 1, GD_KT, h4, 0);
	SETGATE(idt[5], 1, GD_KT, h5, 0);
	SETGATE(idt[6], 1, GD_KT, h6, 0);
	SETGATE(idt[7], 1, GD_KT, h7, 0);
	SETGATE(idt[8], 1, GD_KT, h8, 0);
	SETGATE(idt[9], 1, GD_KT, h9, 0);
	SETGATE(idt[10], 1, GD_KT, h10, 0);
	SETGATE(idt[11], 1, GD_KT, h11, 0);
	SETGATE(idt[12], 1, GD_KT, h12, 0);
	SETGATE(idt[13], 1, GD_KT, h13, 0);
	SETGATE(idt[14], 1, GD_KT, h14, 0);
	SETGATE(idt[15], 1, GD_KT, h15, 0);
	SETGATE(idt[16], 1, GD_KT, h16, 0);
	SETGATE(idt[17], 1, GD_KT, h17, 0);
	SETGATE(idt[18], 1, GD_KT, h18, 0);
	SETGATE(idt[19], 1, GD_KT, h19, 0);
	SETGATE(idt[20], 1, GD_KT, h20, 0);
	SETGATE(idt[21], 1, GD_KT, h21, 0);
	SETGATE(idt[22], 1, GD_KT, h22, 0);
	SETGATE(idt[23], 1, GD_KT, h23, 0);
	SETGATE(idt[24], 1, GD_KT, h24, 0);
	SETGATE(idt[25], 1, GD_KT, h25, 0);
	SETGATE(idt[26], 1, GD_KT, h26, 0);
	SETGATE(idt[27], 1, GD_KT, h27, 0);
	SETGATE(idt[28], 1, GD_KT, h28, 0);
	SETGATE(idt[29], 1, GD_KT, h29, 0);
	SETGATE(idt[30], 1, GD_KT, h30, 0);
	SETGATE(idt[31], 1, GD_KT, h31, 0);
	SETGATE(idt[32], 0, GD_KT, h32, 0);
	SETGATE(idt[33], 0, GD_KT, h33, 0);
	SETGATE(idt[34], 0, GD_KT, h34, 0);
	SETGATE(idt[35], 0, GD_KT, h35, 0);
	SETGATE(idt[36], 0, GD_KT, h36, 0);
	SETGATE(idt[37], 0, GD_KT, h37, 0);
	SETGATE(idt[38], 0, GD_KT, h38, 0);
	SETGATE(idt[39], 0, GD_KT, h39, 0);
	SETGATE(idt[40], 0, GD_KT, h40, 0);
	SETGATE(idt[41], 0, GD_KT, h41, 0);
	SETGATE(idt[42], 0, GD_KT, h42, 0);
	SETGATE(idt[43], 0, GD_KT, h43, 0);
	SETGATE(idt[44], 0, GD_KT, h44, 0);
	SETGATE(idt[45], 0, GD_KT, h45, 0);
	SETGATE(idt[46], 0, GD_KT, h46, 0);
	SETGATE(idt[47], 0, GD_KT, h47, 0);
	SETGATE(idt[48], 0, GD_KT, h48, 3);

	// Per-CPU setup 
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;
	ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.

	switch (tf->tf_trapno) {
	case T_PGFLT:
		page_fault_handler(tf);
		return;
	case T_BRKPT:
		monitor(tf);
		return;
	case T_SYSCALL:
		tf->tf_regs.reg_eax = syscall(tf->tf_regs.reg_eax, 
				              tf->tf_regs.reg_edx,
				              tf->tf_regs.reg_ecx,
				              tf->tf_regs.reg_ebx,
				              tf->tf_regs.reg_edi,
				              tf->tf_regs.reg_esi);
		return;
	default:
		break;
	}

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		assert(curenv);

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 3) != 3) {
		panic("Kernel mode page faults");
	}

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

