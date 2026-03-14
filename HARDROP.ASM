.186
.model tiny
.code
org 100h

LOCAL_BUF_LEN equ 16
PASSWORD_LEN  equ 12
EXPLOIT_INPUT_LEN equ 32
CAESAR_SHIFT  equ 3

MAGIC_ONE     equ 0B16Bh
MAGIC_TWO     equ 0C0DEh
EXPLOIT_DIGEST equ 09Dh

start:
    call init_runtime
    call invoke_vulnerable_path
    test dx, dx
    jz   start_failed
    call grant_wrapper
    jmp  dos_exit

start_failed:
    call draw_failed

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

draw_failed proc
    mov  ah, 09h
    mov  dx, offset fail_message
    int  21h
    jmp  dos_exit
draw_failed endp

invoke_vulnerable_path proc
    push bp
    mov  bp, sp
    sub  sp, 16
    call take_password_and_check
    mov  sp, bp
    pop  bp
    ret
invoke_vulnerable_path endp

check_flags proc
    mov  al, [flag_one]
    cmp  al, 11h
    jne  check_flags_bad
    mov  al, [flag_two]
    cmp  al, 22h
    jne  check_flags_bad
    mov  al, [flag_three]
    cmp  al, 33h
    jne  check_flags_bad
    mov  dx, 0001h
    ret

check_flags_bad:
    xor  dx, dx
    ret
check_flags endp

grant_wrapper proc
    call check_flags
    test dx, dx
    jnz  grant_wrapper_after_first_check
    jmp  exploit_fail
grant_wrapper_after_first_check:
    call draw_acces_granted
    call check_flags
    test dx, dx
    jnz  grant_wrapper_after_second_check
    jmp  exploit_fail
grant_wrapper_after_second_check:
    jmp  dos_exit
grant_wrapper endp

validate_password proc
    mov  ax, [last_input_len]
    cmp  ax, PASSWORD_LEN
    jne  validate_password_fail

    mov  si, [last_input_ptr]
    mov  di, offset encrypted_password
    mov  cx, PASSWORD_LEN

validate_password_loop:
    mov  al, [si]
    add  al, CAESAR_SHIFT
    cmp  al, [di]
    jne  validate_password_fail
    inc  si
    inc  di
    loop validate_password_loop

validate_password_success_tail:
    mov  byte ptr [flag_one], 11h
    mov  byte ptr [flag_two], 22h
    mov  byte ptr [flag_three], 33h
    mov  dx, 0001h
    ret

validate_password_fail:
    xor  dx, dx
    ret
validate_password endp

magic_gate_one proc
    pop  ax
    cmp  ax, MAGIC_ONE
    je   magic_gate_one_ok
    jmp  exploit_fail
magic_gate_one_ok:
    ret
magic_gate_one endp

checksum_gate proc
    push si
    push cx

    mov  ax, [last_input_len]
    cmp  ax, EXPLOIT_INPUT_LEN
    jne  checksum_gate_fail

    xor  al, al
    mov  si, [last_input_ptr]
    mov  cx, LOCAL_BUF_LEN

checksum_gate_loop:
    rol  al, 1
    xor  al, [si]
    inc  si
    loop checksum_gate_loop

    cmp  al, EXPLOIT_DIGEST
    jne  checksum_gate_fail

    pop  cx
    pop  si
    ret

checksum_gate_fail:
    pop  cx
    pop  si
    jmp  exploit_fail
checksum_gate endp

magic_gate_two proc
    pop  bx
    cmp  bx, MAGIC_TWO
    je   magic_gate_two_ok
    jmp  exploit_fail
magic_gate_two_ok:
    ret
magic_gate_two endp

stage_loader proc
    jmp  validate_password_success_tail
stage_loader endp

exploit_fail:
    jmp  draw_failed

take_password_and_check proc
    push bp
    mov  bp, sp
    sub  sp, LOCAL_BUF_LEN

    mov  ah, 09h
    mov  dx, offset prompt_message
    int  21h

    lea  ax, [bp - LOCAL_BUF_LEN]
    mov  [last_input_ptr], ax

    xor  bx, bx
    lea  dx, [bp - LOCAL_BUF_LEN]
    mov  cx, EXPLOIT_INPUT_LEN
    mov  ah, 3Fh
    int  21h
    jc   take_password_and_check_fail

    mov  [last_input_len], ax

    call validate_password

    mov  sp, bp
    pop  bp
    ret

take_password_and_check_fail:
    xor  dx, dx
    mov  sp, bp
    pop  bp
    ret
take_password_and_check endp

.data

encrypted_password db "VrphSdvvzrug"
prompt_message     db "Password: $"
success_message    db 0Dh, 0Ah, "acces granted$"
fail_message       db 0Dh, 0Ah, "failed$"

flag_one           db 0
flag_two           db 0
flag_three         db 0

last_input_ptr     dw 0
last_input_len     dw 0

end start
