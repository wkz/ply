strncmp:
	mov	r0, 0
	mov	r1, #LENGTH
	mov	r2, [r10 + LEFT]
	mov	r3, [r10 + RIGHT]

next:	jeq	r1, #0, done
	ldxb	r0, [r2]
	ldxb	r4, [r3]
	sub	r0, r4
	jeq	r4, #0, done
	jne	r0, #0, done
	sub	r1, #1
	add	r2, #1
	add	r3, #1
	ja	next
done:	
