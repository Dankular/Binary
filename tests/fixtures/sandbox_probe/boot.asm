; Minimal 16-bit real-mode MBR boot sector used purely to prove that QEMU's
; software CPU emulator (TCG, i.e. no /dev/kvm, no hardware virtualization)
; actually executes x86 instructions correctly inside a plain container.
; Writes "TCG-OK" directly to the COM1 UART (port 0x3F8) so it shows up on
; `-serial stdio`, then halts via the isa-debug-exit device (port 0xF4) so
; the QEMU process itself exits with a distinguishing status code.
BITS 16
ORG 0x7C00

start:
    mov si, msg
.print:
    lodsb
    cmp al, 0
    je .done
    mov dx, 0x3F8      ; COM1 data register
    out dx, al
    jmp .print
.done:
    mov al, 0x11        ; exit code payload for isa-debug-exit
    mov dx, 0xF4
    out dx, al
    hlt

msg: db "TCG-OK", 0

times 510-($-$$) db 0
dw 0xAA55
