/*
	MMX crypt core loop
	$Date: 2002/11/03 05:25:22 $
*/

#ifdef __CYGWIN__
#define ENTRY(s) .globl _##s; _##s:
#else
#define ENTRY(s) .globl s; s:
#endif

#define F1(MM0,MM1,MM2,MM3,OFFSET) \
movq OFFSET(%esi),%mm4; \
movq 8+OFFSET(%esi),%mm5; \
movq OFFSET+128(%esi),%mm6; \
movq 8+OFFSET+128(%esi),%mm7; \
pxor MM1,%mm4; \
pxor MM3,%mm6; \
pextrw $0, %mm4,%eax; \
pxor 32768(%ebx,%eax),MM0; \
pextrw $0, %mm6,%eax; \
pxor 32768(%ebx,%eax),MM2; \
pextrw $1, %mm4,%eax; \
pxor (%ebx,%eax),MM0; \
pextrw $1, %mm6,%eax; \
pxor (%ebx,%eax),MM2;

#define F2(MM0,MM1,MM2,MM3) \
pextrw $2, %mm4,%eax; \
pxor 98304(%ebx,%eax),MM0; \
pextrw $2, %mm6,%eax; \
pxor 98304(%ebx,%eax),MM2; \
pextrw $3, %mm4,%eax; \
pxor 65536(%ebx,%eax),MM0; \
pextrw $3, %mm6,%eax; \
pxor 65536(%ebx,%eax),MM2;

#define F3(MM0,MM1,MM2,MM3) \
pxor MM0,%mm5; \
pxor MM2,%mm7; \
pextrw $0, %mm5,%eax; \
pxor 32768(%ebx,%eax),MM1; \
pextrw $0, %mm7,%eax; \
pxor 32768(%ebx,%eax),MM3; \
pextrw $1, %mm5,%eax; \
pxor (%ebx,%eax),MM1; \
pextrw $1, %mm7,%eax; \
pxor (%ebx,%eax),MM3;

#define F4(MM0,MM1,MM2,MM3) \
pextrw $2, %mm5,%eax; \
pxor 98304(%ebx,%eax),MM1; \
pextrw $2, %mm7,%eax; \
pxor 98304(%ebx,%eax),MM3; \
pextrw $3, %mm5,%eax; \
pxor 65536(%ebx,%eax),MM1; \
pextrw $3, %mm7,%eax; \
pxor 65536(%ebx,%eax),MM3;


#define H(MM0,MM1,MM2,MM3,OFFSET) \
F1(MM0,MM1,MM2,MM3,OFFSET) F2(MM0,MM1,MM2,MM3) \
F3(MM0,MM1,MM2,MM3) F4(MM0,MM1,MM2,MM3)

#ifdef HAVE_SSE

#define PREFETCH_AHEAD 32

#define I(MM0,MM1,MM2,MM3) \
	prefetchnta PREFETCH_AHEAD(%esi); \
	prefetchnta PREFETCH_AHEAD+128(%esi); \
	H(MM0,MM1,MM2,MM3,0) \
	H(MM0,MM1,MM2,MM3,16) \
	prefetchnta PREFETCH_AHEAD+32(%esi); \
	prefetchnta PREFETCH_AHEAD+32+128(%esi); \
	H(MM0,MM1,MM2,MM3,32) \
	H(MM0,MM1,MM2,MM3,48) \
	prefetchnta PREFETCH_AHEAD+64(%esi); \
	prefetchnta PREFETCH_AHEAD+64+128(%esi); \
	H(MM0,MM1,MM2,MM3,64) \
	H(MM0,MM1,MM2,MM3,80) \
	prefetchnta PREFETCH_AHEAD+96(%esi); \
	prefetchnta PREFETCH_AHEAD+96+128(%esi); \
	H(MM0,MM1,MM2,MM3,96) \
	H(MM0,MM1,MM2,MM3,112)

#else

#define I(MM0,MM1,MM2,MM3) \
	H(MM0,MM1,MM2,MM3,0) \
	H(MM0,MM1,MM2,MM3,16) \
	H(MM0,MM1,MM2,MM3,32) \
	H(MM0,MM1,MM2,MM3,48) \
	H(MM0,MM1,MM2,MM3,64) \
	H(MM0,MM1,MM2,MM3,80) \
	H(MM0,MM1,MM2,MM3,96) \
	H(MM0,MM1,MM2,MM3,112)

#endif


	.align 4096
ENTRY(crypt_core_mmx)
	pushl %ebp
	movl %esp,%ebp
	subl $8,%esp

	pushl %edi
	pushl %esi
	pushl %ebx

	movl 12(%ebp),%eax

	movl (%eax),%ebx

	// mm0:	l2:l1
	// mm1:	r2:r1

	pxor %mm0,%mm0
	pxor %mm1,%mm1

	pxor %mm2,%mm2
	pxor %mm3,%mm3

	movl $25,%edi

	.align 16
loop:
	movl 16(%ebp),%esi

	// inner loop
	I(%mm0,%mm1,%mm2,%mm3)

	decl %edi

	// swap %mm0,%mm1
	// swap %mm2,%mm3
	movq %mm0,%mm4
	movq %mm2,%mm5
	movq %mm1,%mm0
	movq %mm3,%mm2
	movq %mm4,%mm1
	movq %mm5,%mm3

	jnz loop

	movl 8(%ebp),%eax

	movq %mm0,(%eax)
	movq %mm1,8(%eax)
	movq %mm2,16(%eax)
	movq %mm3,24(%eax)

	emms

	popl %ebx
	popl %esi
	popl %edi
	leave
	ret

	.data
	.align 32
b2a:
	.ascii	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
	.ascii	"wxyz"

	.text
	.align 32
ENTRY(output_conversion_mmx)
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	pushl	%ebx

	subl	$4, %esp

	// %edx: res
	movl	28(%esp), %edx
	// %ebp: crs
	movl	24(%esp), %ebp

	// bitmask (0x3f << 3)
	movl	$504,%edi

	// %ebx: l1
	movl	(%edx),%ebx
	// 3,2
	movl	%ebx,%eax
	movl	%ebx,%ecx
	andl	%edi,%eax
	shrl	$6,%ecx
	movq	1536(%ebp,%eax),%mm0
	andl	%edi,%ecx
	movq	1024(%ebp,%ecx),%mm1
	// 1,0
	movl	%ebx,%eax
	shrl	$22,%ebx
	shrl	$16,%eax
	andl	%edi,%ebx
	andl	%edi,%eax
	por	512(%ebp,%eax),%mm0
	por	(%ebp,%ebx),%mm1

	// %ebx: l2
	movl	4(%edx),%ebx
	// 7,6
	movl	%ebx,%eax
	movl	%ebx,%ecx
	andl	%edi,%eax
	shrl	$6,%ecx
	por	3584(%ebp,%eax),%mm0
	andl	%edi,%ecx
	por	3072(%ebp,%ecx),%mm1
	// 5,4
	movl	%ebx,%eax
	shrl	$22,%ebx
	shrl	$16,%eax
	andl	%edi,%ebx
	andl	%edi,%eax
	por	2048(%ebp,%ebx),%mm0
	por	2560(%ebp,%eax),%mm1

	// %ebx: r1	
	movl	8(%edx),%ebx
	// 11,10
	movl	%ebx,%eax
	movl	%ebx,%ecx
	andl	%edi,%eax
	shrl	$6,%ecx
	por	5632(%ebp,%eax),%mm0
	andl	%edi,%ecx
	por	5120(%ebp,%ecx),%mm1
	// 9,8
	movl	%ebx,%eax
	shrl	$22,%ebx
	shrl	$16,%eax
	andl	%edi,%ebx
	andl	%edi,%eax
	por	4096(%ebp,%ebx),%mm0
	por	4608(%ebp,%eax),%mm1

	// %ebx: r2
	movl	12(%edx),%ebx
	// 15,14
	movl	%ebx,%eax
	movl	%ebx,%ecx
	andl	%edi,%eax
	shrl	$6,%ecx
	por	7680(%ebp,%eax),%mm0
	andl	%edi,%ecx
	por	7168(%ebp,%ecx),%mm1
	// 13,12
	movl	%ebx,%eax
	shrl	$22,%ebx
	shrl	$16,%eax
	andl	%edi,%ebx
	andl	%edi,%eax
	por	6144(%ebp,%ebx),%mm0
	por	6656(%ebp,%eax),%mm1

	movl	$b2a,%edi
	movl	$63,%esi
	movl	32(%esp),%ecx

	por	%mm1,%mm0
	
	// skip copying salt

	movd	%mm0,%eax
	punpckhdq %mm0,%mm0

	movl	%eax,%edx
	shrl	$2,%edx
	andl	%esi,%edx
	movb	(%edi,%edx),%dl
	movb	%dl,6(%ecx)

	movl	%eax,%edx
	shrl	$8,%edx
	andl	%esi,%edx
	movb	(%edi,%edx),%dl
	movb	%dl,5(%ecx)

	movl	%eax,%edx
	shrl	$14,%edx
	andl	%esi,%edx
	movb	(%edi,%edx),%dl
	movb	%dl,4(%ecx)

	movl	%eax,%edx
	shrl	$20,%edx
	andl	%esi,%edx
	movb	(%edi,%edx),%dl
	movb	%dl,3(%ecx)

	movl	%eax,%edx
	shrl	$26,%edx
	andl	%esi,%edx
	movb	(%edi,%edx),%dl
	movb	%dl,2(%ecx)

	movd	%mm0,%ebx

	andl	$3,%eax
	movl	%ebx,%edx
	shrl	$28,%edx
	sall	$4,%eax
	orl	%edx,%eax
	andl	%esi,%eax
	movb	(%edi,%eax),%al
	movb	%al,7(%ecx)

	movl	%ebx,%eax
	shrl	$22,%eax
	andl	%esi,%eax
	movb	(%edi,%eax),%al
	movb	%al,8(%ecx)

	movl	%ebx,%eax
	shrl	$16,%eax
	andl	%esi,%eax
	movb	(%edi,%eax),%al
	movb	%al,9(%ecx)

	movl	%ebx,%eax
	shrl	$10,%eax
	andl	%esi,%eax
	movb	(%edi,%eax),%al
	movb	%al,10(%ecx)

	movl	%ebx,%eax
	shrl	$4,%eax
	andl	%esi,%eax
	movb	(%edi,%eax),%al
	movb	%al,11(%ecx)

	sall	$2,%ebx
	andl	%esi,%ebx
	movb	(%edi,%ebx),%al
	movb	%al,12(%ecx)

	movb	$0, 13(%ecx)

	emms

	popl	%eax
	popl	%ebx
	popl	%esi
	popl	%edi
	popl	%ebp
	ret
