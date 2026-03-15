.model tiny
.code
org 100h
LOCALS @@

PASSWORD_LEN equ 9
READ_CHUNK   equ 128

start:
    call init_runtime
    call take_password
    call check_password
    test dx, dx
    jz   @@incorrect_password

    call draw_acces_granted
    jmp  @@program_exit

@@incorrect_password:
    call draw_acces_not_granted

@@program_exit:
    call dos_exit

init_runtime proc
    push cs
    pop  ds
    ret
init_runtime endp

dos_exit proc
    mov  ax, 4C00h
    int  21h
    ret
dos_exit endp

draw_acces_granted proc
    mov  ah, 09h
    mov  dx, offset success_message
    int  21h
    ret
draw_acces_granted endp

draw_acces_not_granted proc
    mov  ah, 09h
    mov  dx, offset fail_message
    int  21h
    ret
draw_acces_not_granted endp

; Unbounded input is copied into the real runtime stack.
; We read by chunks into a temporary buffer and then move bytes to SS:SP.
; This avoids corrupting the target area with the interrupt's own stack frames.
take_password proc
    mov  bp, sp
    mov  word ptr [typed_len], 0
    mov  byte ptr [input_terminated], 0

    mov  ah, 09h
    mov  dx, offset prompt_message
    int  21h

@@read_loop:
    xor  bx, bx
    mov  dx, offset read_buffer
    mov  cx, READ_CHUNK
    mov  ah, 3Fh
    int  21h
    jc   @@done_empty

    or   ax, ax
    jz   @@done_input

    mov  si, offset read_buffer
    mov  cx, ax

@@copy_loop:
    lodsb
    dec  sp
    mov  bx, sp
    mov  ss:[bx], al
    cmp  al, 0Dh
    jne  @@copy_next
    mov  byte ptr [input_terminated], 1
    jmp  @@done_input

@@copy_next:
    inc  word ptr [typed_len]
    loop @@copy_loop

    jmp  @@read_loop

@@done_input:
    mov  bx, bp
    dec  bx
    mov  sp, bp
    ret

@@done_empty:
    mov  bx, bp
    dec  bx
    mov  sp, bp
    ret
take_password endp

check_password proc
    cmp  byte ptr [input_terminated], 1
    jne  @@return_false
    cmp  word ptr [typed_len], PASSWORD_LEN
    jne  @@return_false

    mov  si, bx
    mov  di, offset correct_password
    mov  cx, PASSWORD_LEN

@@cmp_loop:
    mov  al, ss:[si]
    cmp  al, [di]
    jne  @@return_false
    dec  si
    inc  di
    loop @@cmp_loop

    mov  dx, 0001h
    ret

@@return_false:
    xor  dx, dx
    ret
check_password endp

.data

prompt_message   db "Password: $"
success_message  db 0Dh, 0Ah, "acces granted$"
fail_message     db 0Dh, 0Ah, "Access denied$"

read_buffer      db READ_CHUNK dup (0)
typed_len        dw 0
correct_password db "StackDead"
input_terminated db 0

end start
