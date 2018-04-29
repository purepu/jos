// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;
	pte_t pte;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	
	if ((err & FEC_WR) != FEC_WR) {
		panic("pgfault is not caused by writing a page %p\n", addr);
	}

	r = (int) PGNUM(addr);
	pte = uvpt[r];
	if ((pte & PTE_COW) != PTE_COW) {
		panic("pgfault is not caused by writing a copy-on-write page %p\n", addr);
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	
	sys_page_alloc(0, PFTEMP, PTE_W | PTE_P | PTE_U);
	// Copy the content of the old physical page to the newly allocated page.
	memcpy(PFTEMP, ROUNDDOWN(addr, PGSIZE), PGSIZE);

	sys_page_map(0, PFTEMP, 0, ROUNDDOWN(addr, PGSIZE), PTE_W | PTE_P | PTE_U);
	sys_page_unmap(0, PFTEMP);

	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	int perm;

	// LAB 4: Your code here.
	//panic("duppage not implemented");
	
	pte_t pte = uvpt[pn];
	if (((pte & PTE_W) == PTE_W) || ((pte & PTE_COW) == PTE_COW)) {
		perm = PTE_COW;
	} else {
		perm = 0;
	}
	
	r = sys_page_map(0, (void *)(pn * PGSIZE), envid, (void *)(pn * PGSIZE), perm | PTE_U | PTE_P);
	if (r < 0) {
		return r;
	}

	if (perm == PTE_COW) {
		r = sys_page_map(0, (void *)(pn * PGSIZE), 0, (void *)(pn * PGSIZE), perm | PTE_U | PTE_P);
		if (r < 0) {
			return r;
		}
	}

	//sys_page_map(envid_t srcenv, void *srcva, envid_t dstenv, void *dstva, int perm)
	
	
	return 0;
}

// Whether the va is mapped to a physical page. If yes, return 1, otherwise return 0.
// va does not need to be page aligned. 
static
int
is_mapped(void *va)
{
	pte_t pte;
	pde_t pde = uvpd[PDX(va)];
	if ((pde & PTE_P) == PTE_P) {
		pte = uvpt[PGNUM(va)];
		if ((pte & PTE_P) == PTE_P) {
			return 1;
		}
	}
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	//panic("fork not implemented");
	envid_t envid;
	unsigned pgnum;
	int r;

	set_pgfault_handler(pgfault);

	// Allocate a new child environment.
	// The kernel will initialize it with a copy of our register state,
	// so that the child will appear to have called sys_exofork() too -
	// except that in the child, this "fake" call to sys_exofork()
	// will return 0 instead of the envid of the child.
	envid = sys_exofork();
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	for (pgnum = 0; pgnum < PGNUM(USTACKTOP); pgnum++) {
		if (is_mapped((void *) (pgnum * PGSIZE))) {
			r = duppage(envid, pgnum);
			if (r < 0) {
				panic("duppage failed %x\n", pgnum * PGSIZE);
			}
		}
	}

	sys_page_alloc(envid, (void *) (UXSTACKTOP - PGSIZE), PTE_W | PTE_P | PTE_U);


	// Start the child environment running
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);

	return envid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
