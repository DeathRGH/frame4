#ifndef SYSCALL_H
#define SYSCALL_H

#define SYSCALL(name, number)        \
  __asm__(".intel_syntax noprefix"); \
  __asm__(".globl " #name "");       \
  __asm__("" #name ":");             \
  __asm__("movq rax, " #number "");  \
  __asm__("jmp syscall_macro");

unsigned long syscall(unsigned long n, ...);

#endif
