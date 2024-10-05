# Frame4
A ps4debug edit used with PS4 Toolbox.

### Features
- Process List
- Virtual Memory Map
- Reading/Writing Memory (Both Kernel and Userland)
- Debugger (Userland)
- Function Calling (RPC)
- UART Server on port 3321
- HTTP Server on port 2812
- Application File Redirector (AFR)
- Set Fan Threshold Temperature
- Basic Console Info
- System Notifications
- Loading ELFs
- Loading SPRXs
- ...

### Supported PS4 Firmwares
- 5.05
- 6.72
- 7.XX
- 8.XX
- 9.XX
- 10.XX
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
- [ ] Stop hijacking shell core and instead create our own process
- [ ] Move stuff to userland that doesn't need to be in kernel

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
