/* Program entry and system call for Linux 2.4 MIPS (o32), from ntun's
 * mips.S: number in v0, arguments in a0-a3 and on the stack (16, 20),
 * error flag in a3. Linux 2.4 has no exit_group: plain exit. */
	.text
	.set	nomips16
	.set	noreorder

	.globl	__start
	.ent	__start
__start:
	lui	$gp, %hi(_gp)
	addiu	$gp, $gp, %lo(_gp)
	lw	$a0, 0($sp)		/* argc */
	addiu	$a1, $sp, 4		/* argv */
	li	$t0, -8
	and	$sp, $sp, $t0
	addiu	$sp, $sp, -32
	jal	main
	nop
	move	$a0, $v0
	li	$v0, 4001		/* exit */
	syscall
	.end	__start

/* long raw_syscall(long n, long a, long b, long c, long d, long e, long f)
 * a0 = n, a1-a3 = a, b, c; d, e, f on the caller's stack (16, 20, 24) */
	.globl	raw_syscall
	.ent	raw_syscall
raw_syscall:
	move	$v0, $a0
	move	$a0, $a1
	move	$a1, $a2
	move	$a2, $a3
	lw	$a3, 16($sp)
	lw	$t0, 20($sp)
	lw	$t1, 24($sp)
	addiu	$sp, $sp, -32
	sw	$t0, 16($sp)
	sw	$t1, 20($sp)
	syscall
	addiu	$sp, $sp, 32
	beqz	$a3, 1f
	nop
	subu	$v0, $zero, $v0		/* -errno */
1:	jr	$ra
	nop
	.end	raw_syscall

	.section .note.GNU-stack,"",@progbits
