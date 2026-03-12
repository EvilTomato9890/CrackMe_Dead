.model tiny
.code
org 100h
LOCALS @@

PASSWORD_LEN       equ 5
REAL_INPUT_BYTES   equ 8
OVERWRITE_BYTES    equ 6
DECLARED_INPUT_MAX equ REAL_INPUT_BYTES + OVERWRITE_BYTES
LOCAL_BUF_BYTES    equ 2 + REAL_INPUT_BYTES

SUCCESS_AX         equ 1357h
SUCCESS_BX         equ 2468h
SUCCESS_CX         equ 0BADh

start:
    call init_runtime
    call take_password_and_check
    test dx, dx
    jz   @@denied

    call arm_success_state
    call draw_acces_granted
    jmp  @@program_exit

@@denied:
    call draw_acces_denied

@@program_exit:
    call dos_exit

init_runtime proc
    push cs
    pop  ds
    ret
init_runtime endp

dos_exit proc
    mov ax, 4C00h
    int 21h
    ret
dos_exit endp

draw_acces_granted proc
    cmp ax, SUCCESS_AX
    jne @@reject
    cmp bx, SUCCESS_BX
    jne @@reject
    cmp cx, SUCCESS_CX
    jne @@reject

    mov ah, 09h
    mov dx, offset success_message
    int 21h
    call dos_exit
    ret

@@reject:
    call draw_acces_denied
draw_acces_granted endp

draw_acces_denied proc
    mov ah, 09h
    mov dx, offset fail_message
    int 21h
    call dos_exit
draw_acces_denied endp

arm_success_state proc
success_state_gadget label near
    mov ax, SUCCESS_AX
    mov bx, SUCCESS_BX
    mov cx, SUCCESS_CX
    ret
arm_success_state endp

cmp_password proc
    push cx
    mov  cx, PASSWORD_LEN

@@loop:
    mov al, [si]
    cmp al, [di]
    jne @@done
    inc si
    inc di
    loop @@loop

@@done:
    pop cx
    ret
cmp_password endp


take_password_and_check proc
    push bp
    mov  bp, sp
    sub  sp, LOCAL_BUF_BYTES

    mov ah, 09h
    mov dx, offset prompt_message
    int 21h

    mov byte ptr [bp - LOCAL_BUF_BYTES], DECLARED_INPUT_MAX
    mov byte ptr [bp - LOCAL_BUF_BYTES + 1], 0

    lea dx, [bp - LOCAL_BUF_BYTES]
    mov ah, 0Ah
    int 21h

    mov ah, 09h
    mov dx, offset newline_message
    int 21h

    xor dx, dx
    mov al, [bp - LOCAL_BUF_BYTES + 1]
    cmp al, PASSWORD_LEN
    jne @@done

    lea si, [bp - LOCAL_BUF_BYTES + 2]
    mov di, offset correct_password
    call cmp_password
    jne @@done

    mov dx, 0001h

@@done:
    mov sp, bp
    pop bp
    ret
take_password_and_check endp

.data

prompt_message  db "Password: $"
newline_message db 0Dh, 0Ah, "$"
success_message db "acces granted$"
fail_message    db "acces denied$"

correct_password db "stack"

end start
