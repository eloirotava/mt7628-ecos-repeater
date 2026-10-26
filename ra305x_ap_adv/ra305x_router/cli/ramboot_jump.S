/* Copied to uncached 0xa0000100 after DMA is idle and interrupts are off.
 * Register-only memmove: source may overlap its fixed load destination.
 */
    .text
    .set noreorder
    .set noat
    .globl ramboot_jump_start
    .globl ramboot_jump_end
ramboot_jump_start:
    /* Flush/invalidate D-cache before writing through the uncached alias. */
    lui $t0, 0x8000
    lui $t1, 0x8001
1:
    cache 0x01, 0($t0)
    addiu $t0, $t0, 32
    bne $t0, $t1, 1b
    nop
    sync
    sltu $t0, $a0, $a1
    beq $t0, $zero, 3f
    nop
    addu $t0, $a0, $a2
    sltu $t1, $a1, $t0
    beq $t1, $zero, 3f
    nop
    /* Overlapping destination above source: copy backwards. */
    addu $a0, $a0, $a2
    addu $a1, $a1, $a2
2:
    addiu $a0, $a0, -1
    addiu $a1, $a1, -1
    lbu $t0, 0($a0)
    sb $t0, 0($a1)
    addiu $a2, $a2, -1
    bne $a2, $zero, 2b
    nop
    b 5f
    nop
3:
    lbu $t0, 0($a0)
    sb $t0, 0($a1)
    addiu $a0, $a0, 1
    addiu $a1, $a1, 1
    addiu $a2, $a2, -1
    bne $a2, $zero, 3b
    nop
5:
    sync
    /* Discard cached instructions from the previous zload stub. */
    lui $t0, 0x8000
    lui $t1, 0x8001
6:
    cache 0x00, 0($t0)
    addiu $t0, $t0, 32
    bne $t0, $t1, 6b
    nop
    sync
    /* A failing stub must return to a safe uncached watchdog wait loop. */
    lui $ra, 0xa000
    ori $ra, $ra, 0x100 + (7f - ramboot_jump_start)
    jr $a3
    nop
7:
    b 7b
    nop
ramboot_jump_end:
    .set at
    .set reorder
