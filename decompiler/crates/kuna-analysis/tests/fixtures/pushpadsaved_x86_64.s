	.text
	.globl	helper
	.type	helper, @function
helper:
	movl	$7, %eax
	ret
	.size	helper, .-helper

	.globl	keep
	.type	keep, @function
# long keep(long a, long b, long c): c survives the call to helper on the stack
keep:
	pushq	%rdx
	call	helper
	popq	%rdx
	addq	%rdx, %rax
	ret
	.size	keep, .-keep

	.globl	pad
	.type	pad, @function
# long pad(long a, long b): pushes an unset rdx as a slot the call releases unread
pad:
	pushq	%rdx
	pushq	%rsi
	call	helper
	addq	$16, %rsp
	ret
	.size	pad, .-pad

	.globl	caller
	.type	caller, @function
# long caller(long *p): rdx is a value caller also tests before each call
caller:
	pushq	%rbx
	movq	(%rdi), %rdx
	testq	%rdx, %rdx
	je	.L1
	movq	%rdi, %rbx
	movq	%rdi, %rsi
	call	keep
	movq	(%rbx), %rdx
	testq	%rdx, %rdx
	je	.L1
	movq	%rbx, %rdi
	movq	%rbx, %rsi
	call	pad
.L1:
	popq	%rbx
	ret
	.size	caller, .-caller

	.globl	main
	.type	main, @function
main:
	subq	$24, %rsp
	movq	%rdi, 8(%rsp)
	leaq	8(%rsp), %rdi
	call	caller
	addq	$24, %rsp
	ret
	.size	main, .-main
	.section	.note.GNU-stack,"",@progbits
