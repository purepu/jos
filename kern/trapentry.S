/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

 TRAPHANDLER_NOEC(h0, 0);
 TRAPHANDLER_NOEC(h1, 1);
 TRAPHANDLER_NOEC(h2, 2);
 TRAPHANDLER_NOEC(h3, 3);
 TRAPHANDLER_NOEC(h4, 4);
 TRAPHANDLER_NOEC(h5, 5);
 TRAPHANDLER_NOEC(h6, 6);
 TRAPHANDLER_NOEC(h7, 7);
 TRAPHANDLER(h8, 8);
 TRAPHANDLER_NOEC(h9, 9);
 TRAPHANDLER(h10, 10);
 TRAPHANDLER(h11, 11);
 TRAPHANDLER(h12, 12);
 TRAPHANDLER(h13, 13);
 TRAPHANDLER(h14, 14);
 TRAPHANDLER_NOEC(h15, 15);
 TRAPHANDLER_NOEC(h16, 16);
 TRAPHANDLER_NOEC(h17, 17);
 TRAPHANDLER_NOEC(h18, 18);
 TRAPHANDLER_NOEC(h19, 19);
 TRAPHANDLER_NOEC(h20, 20);
 TRAPHANDLER_NOEC(h21, 21);
 TRAPHANDLER_NOEC(h22, 22);
 TRAPHANDLER_NOEC(h23, 23);
 TRAPHANDLER_NOEC(h24, 24);
 TRAPHANDLER_NOEC(h25, 25);
 TRAPHANDLER_NOEC(h26, 26);
 TRAPHANDLER_NOEC(h27, 27);
 TRAPHANDLER_NOEC(h28, 28);
 TRAPHANDLER_NOEC(h29, 29);
 TRAPHANDLER_NOEC(h30, 30);
 TRAPHANDLER_NOEC(h31, 31);
 TRAPHANDLER_NOEC(h32, 32);
 TRAPHANDLER_NOEC(h33, 33);
 TRAPHANDLER_NOEC(h34, 34);
 TRAPHANDLER_NOEC(h35, 35);
 TRAPHANDLER_NOEC(h36, 36);
 TRAPHANDLER_NOEC(h37, 37);
 TRAPHANDLER_NOEC(h38, 38);
 TRAPHANDLER_NOEC(h39, 39);
 TRAPHANDLER_NOEC(h40, 40);
 TRAPHANDLER_NOEC(h41, 41);
 TRAPHANDLER_NOEC(h42, 42);
 TRAPHANDLER_NOEC(h43, 43);
 TRAPHANDLER_NOEC(h44, 44);
 TRAPHANDLER_NOEC(h45, 45);
 TRAPHANDLER_NOEC(h46, 46);
 TRAPHANDLER_NOEC(h47, 47);
 TRAPHANDLER_NOEC(h48, 48);


/*
 * Lab 3: Your code here for _alltraps
 */

_alltraps:								\
	pushl %ds;
	pushl %es;
	pushl %eax;
	pushl %ecx;
	pushl %edx;
	pushl %ebx;
	pushl $0;
	pushl %ebp;
	pushl %esi;
	pushl %edi;
	movw $GD_KD, %ax;
	movw %ax, %es;
	movw %ax, %ds;
	pushl %esp;
	call trap;
	spin: jmp spin
