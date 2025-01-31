# Frame4
A ps4debug edit used with PS4 Toolbox.

### Features
- Process List
- Module List
- Virtual Memory Map (Both Kernel and Userland)
- Read/Write Memory (Both Kernel and Userland)
- Read/~~Write~~ Physical Memory (Kernel Context)
- Debugger (Userland)
- Function Calling (RPC)
- UART Server on port 3321
- HTTP Server on port 2812
- Application File Redirector (AFR)
- Set Fan Threshold Temperature
- Console Info (PSID, UPD/SDK Version, Kernel Info, ...)
- System Notifications
- Loading ELFs
- Loading SPRXs
- ...

### Patches
- Disable ASLR
- Mount "/user" On Any Process
- Disable Coredump
- Remove Firmware Checks For PKGs (param.sfo, elf/prx Still Need Backporting)
- 5.05 Async IO (blkno) Spam Removed
- 2MB Page Kernel Panic Patched (9.00 And Above)
- Kernel ELF Loading Patched ("vm_fault_copy_wired: page missing")
- Virtual Query Patched To Allow `sceKernelVirtualQuery` On Pages Flagged As System
- ...

### Syscalls
Frame4 installs the following custom syscalls:
- **107** sys_proc_list
- **108** sys_proc_rw
- **109** sys_proc_cmd
- **110** sys_kern_base
- **111** sys_kern_rw
- **112** sys_console_cmd
- **115** sys_kern_cmd

### Supported PS4 Firmwares
- 5.05
- 6.72
- 7.02
- 9.00
- 11.00 (Please note 11.00 is barely tested, any feedback will help!)
###### If you are on 6.72 or 7.02, it is recommended to update to 9.00!

### Libs
- [C#](https://github.com/DeathRGH/libframe4-cs)
- [JavaScript](https://github.com/DeathRGH/libframe4-js)

### Goals
- [x] Make frame4 load side by side with ps4debug
- [ ] Switch the syscalls (107-112) used for cmds to not interfere with ps4debug
- [ ] Move away from the multi compilation setup and merge everything (similar to what has been done for ps5debug by Dizz)
- [ ] Implement sprx loading without relying on goldhen
- [ ] Fix on-console scanner
- [ ] Stop hijacking ShellCore and instead create our own process
- [ ] Move stuff to userland that doesn't need to be in kernel

### Fatal Trap Hooks
Adds detailed info to fatal traps and initiates a clean reboot.
```
Fatal trap 12: page fault while in kernel mode
#
# registers:
#    rdi 0x880AE1DE0
#    rsi 0xFFFFFFFFADBB0000
#    rdx 0x1000
#    rcx 0x200
#    r8  0xFFFFFFFFD7049740
#    r9  0x92660BA0A
#    rax 0xFFFFFF806F71FA28
#    rbx 0xFFFFB8E8075F10B0
#    rbp 0xFFFFFF806F71F980
#    r10 0x880AE2DE0
#    r11 0xFFFFFF806F71FB80
#    r12 0x0
#    r13 0xFFFFFFFFD9524010
#    r14 0x8949C03148000041
#    r15 0xFFFFB8E807582DA0
#    rip 0xFFFFFFFFD70494D6
#    rsp 0x20
#
# kernelbase: 0xFFFFFFFFD6DD8000
#
# backtrace (0xFFFFFF806F71F970):
#    7 <kernelbase> + 0x7DE222
#    11 <kernelbase> + 0x274C010
#    13 <kernelbase> + 0xB7B72
#    16 <kernelbase> + 0x274C010
#    20 <kernelbase> + 0xB7A82
#    59 <kernelbase> + 0x2DF981
#    67 <kernelbase> + 0x274C010
#    71 <kernelbase> + 0x2DF338
#    79 <kernelbase> + 0x3F36E4
#    99 <kernelbase> + 0x274C010
#    103 <kernelbase> + 0x17D83A
#    108 <kernelbase> + 0x271740
#    116 <kernelbase> + 0x274C010
#    122 <kernelbase> + 0x2714BD
#    123 <kernelbase> + 0x2714D6
#    125 <kernelbase> + 0x2714DE
#
```

### Backtrace Hooks
Adds detailed info on the crash logs so you never have to calculate a module offset.
```
...
#
# backtrace:
# 0x0000000000BB7BF1 </data/default_mp.elf> + 0x7B7BF1
# 0x0000000000B924EA </data/default_mp.elf> + 0x7924EA
# 0x00000000009D75A4 </data/default_mp.elf> + 0x5D75A4
# 0x000000000083BE99 </data/default_mp.elf> + 0x43BE99
# 0x00000008000075C2 </i8fsuSWSEf/common/lib/libkernel.sprx> + 0x75C2
# 0x0000000000000000
#
...
```

### Contributing
If you want to contribute, feel free to make a pull request or open an issue.

### Credits
- [Alexandro Sanchez](https://github.com/AlexAltea) Original ps4ksdk
- [Dizz](https://twitter.com/DizzMods) Http server, updated ksdk, multi fw support
- [Golden]() Original ps4debug
- [GoldHEN Team](https://github.com/GoldHEN) SPRX loader
- [OSM](https://twitter.com/LegendaryOSM) Core dump patch
- [RS Glitching](https://www.youtube.com/@RSGLITCHING) Updating most of the kernel addresses to 11.00 and testing
- [theorywrong](https://twitter.com/TheoryWrong) Original AFR
- [TLH](https://github.com/TetzkatLipHoka) Help with on-console scanner

##### And everyone else that I forgot or helped with the original ps4debug!
