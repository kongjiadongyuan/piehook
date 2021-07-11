# piehook
A small tool to "customize" your own PIE/ASLR

## Install
```bash
git clone --recursive https://github.com/kongjiadongyuan/piehook.git
cd piehook
make
```

## How to use

```bash
> cd bin
> sudo ./pie_interface --help
Usage: ./pie_interface [-h|--help] [-i|--info]
          [-l|--load [MOD_DIR]] [-u|--unload]
          [-t|--text TEXT_SEG_BASE] [-s|--stack STACK_BASE] [-p|--heap HEAP_OFFSET] [-g|--stackmagic]
          [-1|--enable-piehook] [-2|--enable-heaphook] [-3|--enable-stackhook]
          [-4|--disable-piehook] [-5|--disable-heaphook] [-6|--disable-stackhook]
          [-e|--encodejson JSONFILE] [-d|--decodejson JSONFILE]

    -h, --help	Show this help message
    -i, --info	Show the hooked address
    -l, --load	Load the piehook kernel module (MOD_DIR means the directory of piehook project, default is ../kernel_module)
    -u, --unload	Unload the piehook kernel module (DO NOT CHANGE THE NAME OF MODULE "piehook")
    -t, --text TEXT_SEG_BASE	Enable text base PIE hook (TEXT_SEG_BASE means 0x555555554000 + OFFSET)
    -s, --stack STACK_BASE	Enable stack base hook (STACK_BASE means the top of user stack area)
    -p, --heap HEAP_OFFSET	Enable heap base hook (HEAP_OFFSET means OFFSET from the end of text area)
    -g, --stackmagic STACK_OFFSET	Enable stack offset hook(the offset need to be fine-tuning manually)
    -1~6	enable or disable the corresponding hook
    -e, --encodejson JSONFILE	export the setting message to JSONFILE in format of json
    -d, --decodejson JSONFILE	import the setting message from JSONFILE in format of json
```

```bash
# load the kernel module
> sudo ./pie_interface -l


# get pie_hook status
> sudo ./pie_interface -i
PIE Hook: OFF
Heap Hook: OFF
Stack Hook: OFF

PIE Hook Addr: 0x555555554000
Heap Hook Offset: 0
Stack Hook Base: 0x7ffffffff000
Stack Hook Offset: 0
# As you can see, hooks are not enabled yet, so progresses can get address randomized normally.


# enable pie hook
# now the progress will load the binary itself at a fixed address
> sudo ./pie_interface -1
[-] INFO: PIE Hook Enabled, Text Offset: 0x555555554000
> cat /proc/self/maps
555555554000-555555556000 r--p 00000000 08:01 1179775                    /usr/bin/cat
555555556000-55555555b000 r-xp 00002000 08:01 1179775                    /usr/bin/cat
55555555b000-55555555d000 r--p 00007000 08:01 1179775                    /usr/bin/cat
55555555e000-55555555f000 r--p 00009000 08:01 1179775                    /usr/bin/cat
55555555f000-555555560000 rw-p 0000a000 08:01 1179775                    /usr/bin/cat
555556fba000-555556fdb000 rw-p 00000000 00:00 0                          [heap]
7fa3d1fbd000-7fa3d22a2000 r--p 00000000 08:01 1315514                    /usr/lib/locale/locale-archive
7fa3d22a2000-7fa3d22c4000 r--p 00000000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d22c4000-7fa3d240c000 r-xp 00022000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d240c000-7fa3d2458000 r--p 0016a000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d2458000-7fa3d2459000 ---p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d2459000-7fa3d245d000 r--p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d245d000-7fa3d245f000 rw-p 001ba000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fa3d245f000-7fa3d2465000 rw-p 00000000 00:00 0 
7fa3d246b000-7fa3d248d000 rw-p 00000000 00:00 0 
7fa3d248d000-7fa3d248e000 r--p 00000000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fa3d248e000-7fa3d24ac000 r-xp 00001000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fa3d24ac000-7fa3d24b4000 r--p 0001f000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fa3d24b4000-7fa3d24b5000 r--p 00026000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fa3d24b5000-7fa3d24b6000 rw-p 00027000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fa3d24b6000-7fa3d24b7000 rw-p 00000000 00:00 0 
7ffda6a75000-7ffda6a96000 rw-p 00000000 00:00 0                          [stack]
7ffda6aac000-7ffda6aaf000 r--p 00000000 00:00 0                          [vvar]
7ffda6aaf000-7ffda6ab1000 r-xp 00000000 00:00 0                          [vdso]
# /usr/bin/cat will appear only at 0x555555554000 now

# change text base
> sudo ./pie_interface -t 0x5555deadb000
[-] INFO: Text base hooked successfully, TEXT_BASE: 0x5555deadb000
> cat /proc/self/maps
5555deadb000-5555deadd000 r--p 00000000 08:01 1179775                    /usr/bin/cat
5555deadd000-5555deae2000 r-xp 00002000 08:01 1179775                    /usr/bin/cat
5555deae2000-5555deae4000 r--p 00007000 08:01 1179775                    /usr/bin/cat
5555deae5000-5555deae6000 r--p 00009000 08:01 1179775                    /usr/bin/cat
5555deae6000-5555deae7000 rw-p 0000a000 08:01 1179775                    /usr/bin/cat
5555df242000-5555df263000 rw-p 00000000 00:00 0                          [heap]
7ff73d0e5000-7ff73d3ca000 r--p 00000000 08:01 1315514                    /usr/lib/locale/locale-archive
7ff73d3ca000-7ff73d3ec000 r--p 00000000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d3ec000-7ff73d534000 r-xp 00022000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d534000-7ff73d580000 r--p 0016a000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d580000-7ff73d581000 ---p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d581000-7ff73d585000 r--p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d585000-7ff73d587000 rw-p 001ba000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7ff73d587000-7ff73d58d000 rw-p 00000000 00:00 0 
7ff73d593000-7ff73d5b5000 rw-p 00000000 00:00 0 
7ff73d5b5000-7ff73d5b6000 r--p 00000000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7ff73d5b6000-7ff73d5d4000 r-xp 00001000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7ff73d5d4000-7ff73d5dc000 r--p 0001f000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7ff73d5dc000-7ff73d5dd000 r--p 00026000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7ff73d5dd000-7ff73d5de000 rw-p 00027000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7ff73d5de000-7ff73d5df000 rw-p 00000000 00:00 0 
7fffc1f47000-7fffc1f68000 rw-p 00000000 00:00 0                          [stack]
7fffc1fac000-7fffc1faf000 r--p 00000000 00:00 0                          [vvar]
7fffc1faf000-7fffc1fb1000 r-xp 00000000 00:00 0                          [vdso]
# /usr/bin/cat will appear only at 0x5555deadb000 now

# now we disable pie hook
> sudo ./pie_interface -4
[-] INFO: PIE Hook Disabled
> sudo ./pie_interface -i
PIE Hook: OFF
Heap Hook: OFF
Stack Hook: OFF

PIE Hook Addr: 0x5555deadb000
Heap Hook Offset: 0
Stack Hook Base: 0x7ffffffff000
Stack Hook Offset: 0
> cat /proc/self/maps
561e54096000-561e54098000 r--p 00000000 08:01 1179775                    /usr/bin/cat
561e54098000-561e5409d000 r-xp 00002000 08:01 1179775                    /usr/bin/cat
561e5409d000-561e5409f000 r--p 00007000 08:01 1179775                    /usr/bin/cat
561e540a0000-561e540a1000 r--p 00009000 08:01 1179775                    /usr/bin/cat
561e540a1000-561e540a2000 rw-p 0000a000 08:01 1179775                    /usr/bin/cat
561e54aee000-561e54b0f000 rw-p 00000000 00:00 0                          [heap]
7fb183420000-7fb183705000 r--p 00000000 08:01 1315514                    /usr/lib/locale/locale-archive
7fb183705000-7fb183727000 r--p 00000000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb183727000-7fb18386f000 r-xp 00022000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb18386f000-7fb1838bb000 r--p 0016a000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb1838bb000-7fb1838bc000 ---p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb1838bc000-7fb1838c0000 r--p 001b6000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb1838c0000-7fb1838c2000 rw-p 001ba000 08:01 1579837                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
7fb1838c2000-7fb1838c8000 rw-p 00000000 00:00 0 
7fb1838ce000-7fb1838f0000 rw-p 00000000 00:00 0 
7fb1838f0000-7fb1838f1000 r--p 00000000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fb1838f1000-7fb18390f000 r-xp 00001000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fb18390f000-7fb183917000 r--p 0001f000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fb183917000-7fb183918000 r--p 00026000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fb183918000-7fb183919000 rw-p 00027000 08:01 1579328                    /usr/lib/x86_64-linux-gnu/ld-2.28.so
7fb183919000-7fb18391a000 rw-p 00000000 00:00 0 
7ffe9384d000-7ffe9386e000 rw-p 00000000 00:00 0                          [stack]
7ffe93958000-7ffe9395b000 r--p 00000000 00:00 0                          [vvar]
7ffe9395b000-7ffe9395d000 r-xp 00000000 00:00 0                          [vdso]
# now the program will get randomized addresses normally.

# unload the kernel module
> sudo ./pie_interface -u
[-] INFO: Unload Module Successfully
```

## Parameters

Maybe you have found that *pie_hook* supports four important parameters:

```bash
[-t|--text TEXT_SEG_BASE] [-s|--stack STACK_BASE] [-p|--heap HEAP_OFFSET] [-g|--stackmagic]
```

*TEXT_SEG_BASE* for binary base address;

*HEAP_OFFSET* for heap base address;

*STACK_BASE*, *STACKMAGIC* for stack address.

The first two parameters are easy to understand, but what do *STACK_BASE* and *STACK_MAGIC* mean? We have to go further to figure out.

When kernel loads a binary, it will randomly choose a base address to place the stack, like this:

![stack](images\README\stack.png)

However, that's not enough, let's take a look at a progress on my virtual machine, it's just */bin/cat*.

Here's the output of command *tel $rsp* (the result must be different on your machine):

```bash
> tel $rsp 700
0x00007fffffffda98│+0x0000: 0x0000555555559506  →   mov rbp, rax	 ← $rsp
0x00007fffffffdaa0│+0x0008: 0x0000000000000000
0x00007fffffffdaa8│+0x0010: 0x00000000ffffffff
0x00007fffffffdab0│+0x0018: 0x00007fbf783be000  →  0x0000000000000000
0x00007fffffffdab8│+0x0020: 0x0000000000020000
0x00007fffffffdac0│+0x0028: 0x0000000000000000
0x00007fffffffdac8│+0x0030: 0x0000555555556ddb  →   mov r14, rax
0x00007fffffffdad0│+0x0038: 0x0000000000000000
0x00007fffffffdad8│+0x0040: 0x000000006562b026
0x00007fffffffdae0│+0x0048: 0x00007fbf7840dac0  →  0x00007fbf7840d9f0  →  0x00007fbf7840d758  →  0x00007fbf7840d730  →  0x00007fbf783e2000  →  0x00010102464c457f
0x00007fffffffdae8│+0x0050: 0x00007fffffffdc28  →  0x0000555555556f80  →   xor ebp, ebp
0x00007fffffffdaf0│+0x0058: 0x0000000000020000
0x00007fffffffdaf8│+0x0060: 0x00007fffffffdd28  →  0x00007fffffffe254  →  0x4c45485300746163 ("cat"?)
0x00007fffffffdb00│+0x0068: 0x00007fffffffdc60  →  0x0000000178374e08
0x00007fffffffdb08│+0x0070: 0x00007fbf783ee38f  →  <_dl_lookup_symbol_x+335> add rsp, 0x30
0x00007fffffffdb10│+0x0078: 0x0000000000000001
0x00007fffffffdb18│+0x0080: 0x00007fffffffdc60  →  0x0000000178374e08
0x00007fffffffdb20│+0x0088: 0x0000000000000001
0x00007fffffffdb28│+0x0090: 0x0000000000001000
0x00007fffffffdb30│+0x0098: 0x00007fbf783bd010  →  0x0000000000000000
0x00007fffffffdb38│+0x00a0: 0x00007fbf7840d730  →  0x00007fbf783e2000  →  0x00010102464c457f
0x00007fffffffdb40│+0x00a8: 0x00007fffffffdb70  →  0x0000000000000014
0x00007fffffffdb48│+0x00b0: 0x0100010000002000
0x00007fffffffdb50│+0x00b8: 0x0000000000000014
0x00007fffffffdb58│+0x00c0: 0x0000000000000003
0x00007fffffffdb60│+0x00c8: 0x00007fbf7840dac0  →  0x00007fbf7840d9f0  →  0x00007fbf7840d758  →  0x00007fbf7840d730  →  0x00007fbf783e2000  →  0x00010102464c457f
0x00007fffffffdb68│+0x00d0: 0x0000000000000000
0x00007fffffffdb70│+0x00d8: 0x0000000000000014
0x00007fffffffdb78│+0x00e0: 0x0000000000000003
0x00007fffffffdb80│+0x00e8: 0x0000000000000001
0x00007fffffffdb88│+0x00f0: 0x000003e800002190
0x00007fffffffdb90│+0x00f8: 0x0000000000000005
0x00007fffffffdb98│+0x0100: 0x0000000000008800
0x00007fffffffdba0│+0x0108: 0x0000000000000000
0x00007fffffffdba8│+0x0110: 0x0000000000000400
0x00007fffffffdbb0│+0x0118: 0x0000000000000000
0x00007fffffffdbb8│+0x0120: 0x0000000060eb0f59
0x00007fffffffdbc0│+0x0128: 0x000000001f179352
0x00007fffffffdbc8│+0x0130: 0x0000000060eb0f59
0x00007fffffffdbd0│+0x0138: 0x000000001f179352
0x00007fffffffdbd8│+0x0140: 0x0000000060eb0d5e
0x00007fffffffdbe0│+0x0148: 0x000000001f179352
0x00007fffffffdbe8│+0x0150: 0x0000000000000000
0x00007fffffffdbf0│+0x0158: 0x0000000000000000
0x00007fffffffdbf8│+0x0160: 0x0000000000000000
0x00007fffffffdc00│+0x0168: 0x0000000000000000
0x00007fffffffdc08│+0x0170: 0xa8201192ab92c500
0x00007fffffffdc10│+0x0178: 0x00007fbf783f3530  →  <_dl_fini+0> push rbp
0x00007fffffffdc18│+0x0180: 0x0000000000000000
0x00007fffffffdc20│+0x0188: 0x000055555555a100  →   push r15
0x00007fffffffdc28│+0x0190: 0x0000555555556f80  →   xor ebp, ebp
0x00007fffffffdc30│+0x0198: 0x00007fffffffdd20  →  0x0000000000000001
0x00007fffffffdc38│+0x01a0: 0x0000000000000000
0x00007fffffffdc40│+0x01a8: 0x0000000000000000
0x00007fffffffdc48│+0x01b0: 0x00007fbf7821809b  →  <__libc_start_main+235> mov edi, eax
0x00007fffffffdc50│+0x01b8: 0x00007fbf783ab660  →  0x00007fbf78217970  →  <init_cacheinfo+0> push r15
0x00007fffffffdc58│+0x01c0: 0x00007fffffffdd28  →  0x00007fffffffe254  →  0x4c45485300746163 ("cat"?)
0x00007fffffffdc60│+0x01c8: 0x0000000178374e08
0x00007fffffffdc68│+0x01d0: 0x0000555555556370  →   push r15
0x00007fffffffdc70│+0x01d8: 0x0000000000000000
0x00007fffffffdc78│+0x01e0: 0xec966f2abcfa0095
0x00007fffffffdc80│+0x01e8: 0x0000555555556f80  →   xor ebp, ebp
0x00007fffffffdc88│+0x01f0: 0x00007fffffffdd20  →  0x0000000000000001
0x00007fffffffdc90│+0x01f8: 0x0000000000000000
0x00007fffffffdc98│+0x0200: 0x0000000000000000
0x00007fffffffdca0│+0x0208: 0xb9c33a7e465a0095
0x00007fffffffdca8│+0x0210: 0xb94235c2fe5c0095
0x00007fffffffdcb0│+0x0218: 0x0000000000000000
0x00007fffffffdcb8│+0x0220: 0x0000000000000000
0x00007fffffffdcc0│+0x0228: 0x0000000000000000
0x00007fffffffdcc8│+0x0230: 0x00007fffffffdd38  →  0x00007fffffffe258  →  "SHELL=/usr/bin/zsh"
0x00007fffffffdcd0│+0x0238: 0x00007fbf7840d190  →  0x0000555555554000  →  0x00010102464c457f
0x00007fffffffdcd8│+0x0240: 0x00007fbf783f3476  →  <_dl_init+118> cmp ebx, 0xffffffff
0x00007fffffffdce0│+0x0248: 0x0000000000000000
0x00007fffffffdce8│+0x0250: 0x0000000000000000
0x00007fffffffdcf0│+0x0258: 0x0000555555556f80  →   xor ebp, ebp
0x00007fffffffdcf8│+0x0260: 0x00007fffffffdd20  →  0x0000000000000001
0x00007fffffffdd00│+0x0268: 0x0000000000000000
0x00007fffffffdd08│+0x0270: 0x0000555555556faa  →   hlt 
0x00007fffffffdd10│+0x0278: 0x00007fffffffdd18  →  0x000000000000001c
0x00007fffffffdd18│+0x0280: 0x000000000000001c
0x00007fffffffdd20│+0x0288: 0x0000000000000001
0x00007fffffffdd28│+0x0290: 0x00007fffffffe254  →  0x4c45485300746163 ("cat"?)
0x00007fffffffdd30│+0x0298: 0x0000000000000000
0x00007fffffffdd38│+0x02a0: 0x00007fffffffe258  →  "SHELL=/usr/bin/zsh"
0x00007fffffffdd40│+0x02a8: 0x00007fffffffe26b  →  "LANG=en_US.UTF-8"
0x00007fffffffdd48│+0x02b0: 0x00007fffffffe27c  →  0x00313d4c564c4853 ("SHLVL=1"?)
0x00007fffffffdd50│+0x02b8: 0x00007fffffffe284  →  "XDG_VTNR=2"
0x00007fffffffdd58│+0x02c0: 0x00007fffffffe28f  →  "LOGNAME=kongjiadongyuan"
0x00007fffffffdd60│+0x02c8: 0x00007fffffffe2a7  →  "PWD=/home/kongjiadongyuan/piehook/bin"
0x00007fffffffdd68│+0x02d0: 0x00007fffffffe2cd  →  "DISPLAY=:0"
0x00007fffffffdd70│+0x02d8: 0x00007fffffffe2d8  →  "DESKTOP_AUTOSTART_ID=10fbfe0563588dbfa116260171147[...]"
0x00007fffffffdd78│+0x02e0: 0x00007fffffffe31e  →  "XDG_SESSION_CLASS=user"
0x00007fffffffdd80│+0x02e8: 0x00007fffffffe335  →  "GIO_LAUNCHED_DESKTOP_FILE=/etc/xdg/autostart/org.g[...]"
0x00007fffffffdd88│+0x02f0: 0x00007fffffffe38d  →  "COLORTERM=truecolor"
0x00007fffffffdd90│+0x02f8: 0x00007fffffffe3a1  →  "XDG_SESSION_ID=1"
0x00007fffffffdd98│+0x0300: 0x00007fffffffe3b2  →  "DESKTOP_SESSION=gnome"
0x00007fffffffdda0│+0x0308: 0x00007fffffffe3c8  →  "XDG_SESSION_DESKTOP=gnome"
0x00007fffffffdda8│+0x0310: 0x00007fffffffe3e2  →  "GNOME_DESKTOP_SESSION_ID=this-is-deprecated"
0x00007fffffffddb0│+0x0318: 0x00007fffffffe40e  →  "GDMSESSION=gnome"
0x00007fffffffddb8│+0x0320: 0x00007fffffffe41f  →  "USERNAME=kongjiadongyuan"
0x00007fffffffddc0│+0x0328: 0x00007fffffffe438  →  "WAYLAND_DISPLAY=wayland-0"
0x00007fffffffddc8│+0x0330: 0x00007fffffffe452  →  "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/[...]"
0x00007fffffffddd0│+0x0338: 0x00007fffffffe488  →  "TERMINATOR_UUID=urn:uuid:8e333e71-5c49-4245-8e09-4[...]"
0x00007fffffffddd8│+0x0340: 0x00007fffffffe4c6  →  "VTE_VERSION=5402"
0x00007fffffffdde0│+0x0348: 0x00007fffffffe4d7  →  "_=/usr/bin/cat"
0x00007fffffffdde8│+0x0350: 0x00007fffffffe4e6  →  "TERMINATOR_DBUS_NAME=net.tenshu.Terminator25ef4b21[...]"
0x00007fffffffddf0│+0x0358: 0x00007fffffffe532  →  "XDG_MENU_PREFIX=gnome-"
0x00007fffffffddf8│+0x0360: 0x00007fffffffe549  →  "QT_ACCESSIBILITY=1"
0x00007fffffffde00│+0x0368: 0x00007fffffffe55c  →  "GDM_LANG=en_US.UTF-8"
0x00007fffffffde08│+0x0370: 0x00007fffffffe571  →  "QT_IM_MODULE=ibus"
0x00007fffffffde10│+0x0378: 0x00007fffffffe583  →  "XDG_SESSION_TYPE=wayland"
0x00007fffffffde18│+0x0380: 0x00007fffffffe59c  →  "OLDPWD=/home/kongjiadongyuan/piehook"
0x00007fffffffde20│+0x0388: 0x00007fffffffe5c1  →  "TERM=xterm-256color"
0x00007fffffffde28│+0x0390: 0x00007fffffffe5d5  →  "GTK_MODULES=gail:atk-bridge"
0x00007fffffffde30│+0x0398: 0x00007fffffffe5f1  →  "XDG_CURRENT_DESKTOP=GNOME"
0x00007fffffffde38│+0x03a0: 0x00007fffffffe60b  →  "SSH_AUTH_SOCK=/run/user/1000/keyring/ssh"
0x00007fffffffde40│+0x03a8: 0x00007fffffffe634  →  "SESSION_MANAGER=local/debian:@/tmp/.ICE-unix/929,u[...]"
0x00007fffffffde48│+0x03b0: 0x00007fffffffe684  →  "PATH=/home/kongjiadongyuan/.opam/default/bin:/home[...]"
0x00007fffffffde50│+0x03b8: 0x00007fffffffe762  →  "HOME=/home/kongjiadongyuan"
0x00007fffffffde58│+0x03c0: 0x00007fffffffe77d  →  "XDG_SEAT=seat0"
0x00007fffffffde60│+0x03c8: 0x00007fffffffe78c  →  "XMODIFIERS=@im=ibus"
0x00007fffffffde68│+0x03d0: 0x00007fffffffe7a0  →  "XDG_RUNTIME_DIR=/run/user/1000"
0x00007fffffffde70│+0x03d8: 0x00007fffffffe7bf  →  "GIO_LAUNCHED_DESKTOP_FILE_PID=1585"
0x00007fffffffde78│+0x03e0: 0x00007fffffffe7e2  →  "USER=kongjiadongyuan"
0x00007fffffffde80│+0x03e8: 0x00007fffffffe7f7  →  "TERMINATOR_DBUS_PATH=/net/tenshu/Terminator2"
0x00007fffffffde88│+0x03f0: 0x00007fffffffe824  →  "ZSH=/home/kongjiadongyuan/.oh-my-zsh"
0x00007fffffffde90│+0x03f8: 0x00007fffffffe849  →  "PAGER=less"
0x00007fffffffde98│+0x0400: 0x00007fffffffe854  →  0x00522d3d5353454c ("LESS=-R"?)
0x00007fffffffdea0│+0x0408: 0x00007fffffffe85c  →  "LSCOLORS=Gxfxcxdxbxegedabagacad"
0x00007fffffffdea8│+0x0410: 0x00007fffffffe87c  →  "LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so[...]"
0x00007fffffffdeb0│+0x0418: 0x00007fffffffee5e  →  "GOPATH=/home/kongjiadongyuan/gopath"
0x00007fffffffdeb8│+0x0420: 0x00007fffffffee82  →  "GOROOT=/home/kongjiadongyuan/goroot"
0x00007fffffffdec0│+0x0428: 0x00007fffffffeea6  →  "OPAMNOENVNOTICE=true"
0x00007fffffffdec8│+0x0430: 0x00007fffffffeebb  →  "OPAM_SWITCH_PREFIX=/home/kongjiadongyuan/.opam/def[...]"
0x00007fffffffded0│+0x0438: 0x00007fffffffeef2  →  "CAML_LD_LIBRARY_PATH=/home/kongjiadongyuan/.opam/d[...]"
0x00007fffffffded8│+0x0440: 0x00007fffffffef75  →  "OCAML_TOPLEVEL_PATH=/home/kongjiadongyuan/.opam/de[...]"
0x00007fffffffdee0│+0x0448: 0x00007fffffffefba  →  "MANPATH=:/home/kongjiadongyuan/.opam/default/man"
0x00007fffffffdee8│+0x0450: 0x0000000000000000
0x00007fffffffdef0│+0x0458: 0x0000000000000021 ("!"?)
0x00007fffffffdef8│+0x0460: 0x00007fbf783e2000  →  0x00010102464c457f
0x00007fffffffdf00│+0x0468: 0x0000000000000010
0x00007fffffffdf08│+0x0470: 0x00000000178bfbff
0x00007fffffffdf10│+0x0478: 0x0000000000000006
0x00007fffffffdf18│+0x0480: 0x0000000000001000
0x00007fffffffdf20│+0x0488: 0x0000000000000011
0x00007fffffffdf28│+0x0490: 0x0000000000000064 ("d"?)
0x00007fffffffdf30│+0x0498: 0x0000000000000003
0x00007fffffffdf38│+0x04a0: 0x0000555555554040  →  0x0000000400000006
0x00007fffffffdf40│+0x04a8: 0x0000000000000004
0x00007fffffffdf48│+0x04b0: 0x0000000000000038 ("8"?)
0x00007fffffffdf50│+0x04b8: 0x0000000000000005
0x00007fffffffdf58│+0x04c0: 0x000000000000000b
0x00007fffffffdf60│+0x04c8: 0x0000000000000007
0x00007fffffffdf68│+0x04d0: 0x00007fbf783e4000  →  0x00010102464c457f
0x00007fffffffdf70│+0x04d8: 0x0000000000000008
0x00007fffffffdf78│+0x04e0: 0x0000000000000000
0x00007fffffffdf80│+0x04e8: 0x0000000000000009
0x00007fffffffdf88│+0x04f0: 0x0000555555556f80  →   xor ebp, ebp
0x00007fffffffdf90│+0x04f8: 0x000000000000000b
0x00007fffffffdf98│+0x0500: 0x00000000000003e8
0x00007fffffffdfa0│+0x0508: 0x000000000000000c
0x00007fffffffdfa8│+0x0510: 0x00000000000003e8
0x00007fffffffdfb0│+0x0518: 0x000000000000000d
0x00007fffffffdfb8│+0x0520: 0x00000000000003e8
0x00007fffffffdfc0│+0x0528: 0x000000000000000e
0x00007fffffffdfc8│+0x0530: 0x00000000000003e8
0x00007fffffffdfd0│+0x0538: 0x0000000000000017
0x00007fffffffdfd8│+0x0540: 0x0000000000000000
0x00007fffffffdfe0│+0x0548: 0x0000000000000019
0x00007fffffffdfe8│+0x0550: 0x00007fffffffe039  →  0xa8201192ab92c5d9
0x00007fffffffdff0│+0x0558: 0x000000000000001a
0x00007fffffffdff8│+0x0560: 0x0000000000000000
0x00007fffffffe000│+0x0568: 0x000000000000001f
0x00007fffffffe008│+0x0570: 0x00007fffffffefeb  →  0x6e69622f7273752f
0x00007fffffffe010│+0x0578: 0x000000000000000f
0x00007fffffffe018│+0x0580: 0x00007fffffffe049  →  0x000034365f363878 ("x86_64"?)
0x00007fffffffe020│+0x0588: 0x0000000000000000
0x00007fffffffe028│+0x0590: 0x0000000000000000
0x00007fffffffe030│+0x0598: 0x0000000000000000
0x00007fffffffe038│+0x05a0: 0x201192ab92c5d900
0x00007fffffffe040│+0x05a8: 0x4aa31e62c0ff7da8
0x00007fffffffe048│+0x05b0: 0x0034365f36387800
0x00007fffffffe050│+0x05b8: 0x0000000000000000
0x00007fffffffe058│+0x05c0: 0x0000000000000000
0x00007fffffffe060│+0x05c8: 0x0000000000000000
0x00007fffffffe068│+0x05d0: 0x0000000000000000
0x00007fffffffe070│+0x05d8: 0x0000000000000000
0x00007fffffffe078│+0x05e0: 0x0000000000000000
0x00007fffffffe080│+0x05e8: 0x0000000000000000
0x00007fffffffe088│+0x05f0: 0x0000000000000000
0x00007fffffffe090│+0x05f8: 0x0000000000000000
0x00007fffffffe098│+0x0600: 0x0000000000000000
0x00007fffffffe0a0│+0x0608: 0x0000000000000000
0x00007fffffffe0a8│+0x0610: 0x0000000000000000
0x00007fffffffe0b0│+0x0618: 0x0000000000000000
0x00007fffffffe0b8│+0x0620: 0x0000000000000000
0x00007fffffffe0c0│+0x0628: 0x0000000000000000
0x00007fffffffe0c8│+0x0630: 0x0000000000000000
0x00007fffffffe0d0│+0x0638: 0x0000000000000000
0x00007fffffffe0d8│+0x0640: 0x0000000000000000
0x00007fffffffe0e0│+0x0648: 0x0000000000000000
0x00007fffffffe0e8│+0x0650: 0x0000000000000000
0x00007fffffffe0f0│+0x0658: 0x0000000000000000
0x00007fffffffe0f8│+0x0660: 0x0000000000000000
0x00007fffffffe100│+0x0668: 0x0000000000000000
0x00007fffffffe108│+0x0670: 0x0000000000000000
0x00007fffffffe110│+0x0678: 0x0000000000000000
0x00007fffffffe118│+0x0680: 0x0000000000000000
0x00007fffffffe120│+0x0688: 0x0000000000000000
0x00007fffffffe128│+0x0690: 0x0000000000000000
0x00007fffffffe130│+0x0698: 0x0000000000000000
0x00007fffffffe138│+0x06a0: 0x0000000000000000
0x00007fffffffe140│+0x06a8: 0x0000000000000000
0x00007fffffffe148│+0x06b0: 0x0000000000000000
0x00007fffffffe150│+0x06b8: 0x0000000000000000
0x00007fffffffe158│+0x06c0: 0x0000000000000000
0x00007fffffffe160│+0x06c8: 0x0000000000000000
0x00007fffffffe168│+0x06d0: 0x0000000000000000
0x00007fffffffe170│+0x06d8: 0x0000000000000000
0x00007fffffffe178│+0x06e0: 0x0000000000000000
0x00007fffffffe180│+0x06e8: 0x0000000000000000
0x00007fffffffe188│+0x06f0: 0x0000000000000000
0x00007fffffffe190│+0x06f8: 0x0000000000000000
0x00007fffffffe198│+0x0700: 0x0000000000000000
0x00007fffffffe1a0│+0x0708: 0x0000000000000000
0x00007fffffffe1a8│+0x0710: 0x0000000000000000
0x00007fffffffe1b0│+0x0718: 0x0000000000000000
0x00007fffffffe1b8│+0x0720: 0x0000000000000000
0x00007fffffffe1c0│+0x0728: 0x0000000000000000
0x00007fffffffe1c8│+0x0730: 0x0000000000000000
0x00007fffffffe1d0│+0x0738: 0x0000000000000000
0x00007fffffffe1d8│+0x0740: 0x0000000000000000
0x00007fffffffe1e0│+0x0748: 0x0000000000000000
0x00007fffffffe1e8│+0x0750: 0x0000000000000000
0x00007fffffffe1f0│+0x0758: 0x0000000000000000
0x00007fffffffe1f8│+0x0760: 0x0000000000000000
0x00007fffffffe200│+0x0768: 0x0000000000000000
0x00007fffffffe208│+0x0770: 0x0000000000000000
0x00007fffffffe210│+0x0778: 0x0000000000000000
0x00007fffffffe218│+0x0780: 0x0000000000000000
0x00007fffffffe220│+0x0788: 0x0000000000000000
0x00007fffffffe228│+0x0790: 0x0000000000000000
0x00007fffffffe230│+0x0798: 0x0000000000000000
0x00007fffffffe238│+0x07a0: 0x0000000000000000
0x00007fffffffe240│+0x07a8: 0x0000000000000000
0x00007fffffffe248│+0x07b0: 0x0000000000000000
0x00007fffffffe250│+0x07b8: 0x0074616300000000
0x00007fffffffe258│+0x07c0: "SHELL=/usr/bin/zsh"
0x00007fffffffe260│+0x07c8: "sr/bin/zsh"
0x00007fffffffe268│+0x07d0: 0x3d474e414c006873 ("sh"?)
0x00007fffffffe270│+0x07d8: "en_US.UTF-8"
0x00007fffffffe278│+0x07e0: 0x564c485300382d46 ("F-8"?)
0x00007fffffffe280│+0x07e8: 0x5f47445800313d4c ("L=1"?)
0x00007fffffffe288│+0x07f0: 0x4c00323d524e5456 ("VTNR=2"?)
0x00007fffffffe290│+0x07f8: "OGNAME=kongjiadongyuan"
0x00007fffffffe298│+0x0800: "ongjiadongyuan"
0x00007fffffffe2a0│+0x0808: 0x50006e617579676e ("ngyuan"?)
0x00007fffffffe2a8│+0x0810: "WD=/home/kongjiadongyuan/piehook/bin"
0x00007fffffffe2b0│+0x0818: "/kongjiadongyuan/piehook/bin"
0x00007fffffffe2b8│+0x0820: "dongyuan/piehook/bin"
0x00007fffffffe2c0│+0x0828: "/piehook/bin"
0x00007fffffffe2c8│+0x0830: 0x534944006e69622f ("/bin"?)
0x00007fffffffe2d0│+0x0838: 0x00303a3d59414c50 ("PLAY=:0"?)
0x00007fffffffe2d8│+0x0840: "DESKTOP_AUTOSTART_ID=10fbfe0563588dbfa116260171147[...]"
0x00007fffffffe2e0│+0x0848: "AUTOSTART_ID=10fbfe0563588dbfa11626017114704683000[...]"
0x00007fffffffe2e8│+0x0850: "T_ID=10fbfe0563588dbfa1162601711470468300000009290[...]"
0x00007fffffffe2f0│+0x0858: "bfe0563588dbfa1162601711470468300000009290007"
0x00007fffffffe2f8│+0x0860: "88dbfa1162601711470468300000009290007"
0x00007fffffffe300│+0x0868: "62601711470468300000009290007"
0x00007fffffffe308│+0x0870: "470468300000009290007"
0x00007fffffffe310│+0x0878: "0000009290007"
0x00007fffffffe318│+0x0880: 0x4458003730303039 ("90007"?)
0x00007fffffffe320│+0x0888: "G_SESSION_CLASS=user"
0x00007fffffffe328│+0x0890: "N_CLASS=user"
0x00007fffffffe330│+0x0898: 0x4f49470072657375 ("user"?)
0x00007fffffffe338│+0x08a0: "_LAUNCHED_DESKTOP_FILE=/etc/xdg/autostart/org.gnom[...]"
0x00007fffffffe340│+0x08a8: "D_DESKTOP_FILE=/etc/xdg/autostart/org.gnome.Settin[...]"
0x00007fffffffe348│+0x08b0: "P_FILE=/etc/xdg/autostart/org.gnome.SettingsDaemon[...]"
0x00007fffffffe350│+0x08b8: "etc/xdg/autostart/org.gnome.SettingsDaemon.MediaKe[...]"
0x00007fffffffe358│+0x08c0: "autostart/org.gnome.SettingsDaemon.MediaKeys.deskt[...]"
0x00007fffffffe360│+0x08c8: "t/org.gnome.SettingsDaemon.MediaKeys.desktop"
0x00007fffffffe368│+0x08d0: "ome.SettingsDaemon.MediaKeys.desktop"
0x00007fffffffe370│+0x08d8: "ingsDaemon.MediaKeys.desktop"
0x00007fffffffe378│+0x08e0: "on.MediaKeys.desktop"
0x00007fffffffe380│+0x08e8: "Keys.desktop"
0x00007fffffffe388│+0x08f0: 0x4c4f4300706f746b ("ktop"?)
0x00007fffffffe390│+0x08f8: "ORTERM=truecolor"
0x00007fffffffe398│+0x0900: "ruecolor"
0x00007fffffffe3a0│+0x0908: 0x5345535f47445800
0x00007fffffffe3a8│+0x0910: "SION_ID=1"
0x00007fffffffe3b0│+0x0918: 0x4f544b5345440031 ("1"?)
0x00007fffffffe3b8│+0x0920: "P_SESSION=gnome"
0x00007fffffffe3c0│+0x0928: 0x00656d6f6e673d4e ("N=gnome"?)
0x00007fffffffe3c8│+0x0930: "XDG_SESSION_DESKTOP=gnome"
0x00007fffffffe3d0│+0x0938: "ION_DESKTOP=gnome"
0x00007fffffffe3d8│+0x0940: "TOP=gnome"
0x00007fffffffe3e0│+0x0948: 0x5f454d4f4e470065 ("e"?)
0x00007fffffffe3e8│+0x0950: "DESKTOP_SESSION_ID=this-is-deprecated"
0x00007fffffffe3f0│+0x0958: "SESSION_ID=this-is-deprecated"
0x00007fffffffe3f8│+0x0960: "ID=this-is-deprecated"
0x00007fffffffe400│+0x0968: "is-deprecated"
0x00007fffffffe408│+0x0970: 0x4447006465746163 ("cated"?)
0x00007fffffffe410│+0x0978: "MSESSION=gnome"
0x00007fffffffe418│+0x0980: 0x5500656d6f6e673d ("=gnome"?)
0x00007fffffffe420│+0x0988: "SERNAME=kongjiadongyuan"
0x00007fffffffe428│+0x0990: "kongjiadongyuan"
0x00007fffffffe430│+0x0998: 0x006e617579676e6f ("ongyuan"?)
0x00007fffffffe438│+0x09a0: "WAYLAND_DISPLAY=wayland-0"
0x00007fffffffe440│+0x09a8: "DISPLAY=wayland-0"
0x00007fffffffe448│+0x09b0: "wayland-0"
0x00007fffffffe450│+0x09b8: 0x535f535542440030 ("0"?)
0x00007fffffffe458│+0x09c0: "ESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
0x00007fffffffe460│+0x09c8: "US_ADDRESS=unix:path=/run/user/1000/bus"
0x00007fffffffe468│+0x09d0: "SS=unix:path=/run/user/1000/bus"
0x00007fffffffe470│+0x09d8: "path=/run/user/1000/bus"
0x00007fffffffe478│+0x09e0: "n/user/1000/bus"
0x00007fffffffe480│+0x09e8: 0x007375622f303030 ("000/bus"?)
0x00007fffffffe488│+0x09f0: "TERMINATOR_UUID=urn:uuid:8e333e71-5c49-4245-8e09-4[...]"
0x00007fffffffe490│+0x09f8: "OR_UUID=urn:uuid:8e333e71-5c49-4245-8e09-452ff6aa0[...]"
0x00007fffffffe498│+0x0a00: "urn:uuid:8e333e71-5c49-4245-8e09-452ff6aa040b"
0x00007fffffffe4a0│+0x0a08: ":8e333e71-5c49-4245-8e09-452ff6aa040b"
0x00007fffffffe4a8│+0x0a10: "1-5c49-4245-8e09-452ff6aa040b"
0x00007fffffffe4b0│+0x0a18: "245-8e09-452ff6aa040b"
0x00007fffffffe4b8│+0x0a20: "-452ff6aa040b"
0x00007fffffffe4c0│+0x0a28: 0x5456006230343061 ("a040b"?)
0x00007fffffffe4c8│+0x0a30: "E_VERSION=5402"
0x00007fffffffe4d0│+0x0a38: 0x5f00323034353d4e ("N=5402"?)
0x00007fffffffe4d8│+0x0a40: "=/usr/bin/cat"
0x00007fffffffe4e0│+0x0a48: 0x4554007461632f6e ("n/cat"?)
0x00007fffffffe4e8│+0x0a50: "RMINATOR_DBUS_NAME=net.tenshu.Terminator25ef4b219e[...]"
0x00007fffffffe4f0│+0x0a58: "_DBUS_NAME=net.tenshu.Terminator25ef4b219e3b005583[...]"
0x00007fffffffe4f8│+0x0a60: "ME=net.tenshu.Terminator25ef4b219e3b005583550f2b0f[...]"
0x00007fffffffe500│+0x0a68: "enshu.Terminator25ef4b219e3b005583550f2b0f9f990c3"
0x00007fffffffe508│+0x0a70: "rminator25ef4b219e3b005583550f2b0f9f990c3"
0x00007fffffffe510│+0x0a78: "25ef4b219e3b005583550f2b0f9f990c3"
0x00007fffffffe518│+0x0a80: "9e3b005583550f2b0f9f990c3"
0x00007fffffffe520│+0x0a88: "83550f2b0f9f990c3"
0x00007fffffffe528│+0x0a90: "0f9f990c3"
0x00007fffffffe530│+0x0a98: 0x454d5f4744580033 ("3"?)
0x00007fffffffe538│+0x0aa0: "NU_PREFIX=gnome-"
0x00007fffffffe540│+0x0aa8: "X=gnome-"
0x00007fffffffe548│+0x0ab0: 0x454343415f545100
0x00007fffffffe550│+0x0ab8: "SSIBILITY=1"
0x00007fffffffe558│+0x0ac0: 0x5f4d444700313d59 ("Y=1"?)
0x00007fffffffe560│+0x0ac8: "LANG=en_US.UTF-8"
0x00007fffffffe568│+0x0ad0: "US.UTF-8"
0x00007fffffffe570│+0x0ad8: 0x4d5f4d495f545100
0x00007fffffffe578│+0x0ae0: "ODULE=ibus"
0x00007fffffffe580│+0x0ae8: 0x535f474458007375 ("us"?)
0x00007fffffffe588│+0x0af0: "ESSION_TYPE=wayland"
0x00007fffffffe590│+0x0af8: "YPE=wayland"
0x00007fffffffe598│+0x0b00: 0x50444c4f00646e61 ("and"?)
0x00007fffffffe5a0│+0x0b08: "WD=/home/kongjiadongyuan/piehook"
0x00007fffffffe5a8│+0x0b10: "/kongjiadongyuan/piehook"
0x00007fffffffe5b0│+0x0b18: "dongyuan/piehook"
0x00007fffffffe5b8│+0x0b20: "/piehook"
0x00007fffffffe5c0│+0x0b28: 0x74783d4d52455400
0x00007fffffffe5c8│+0x0b30: "erm-256color"
0x00007fffffffe5d0│+0x0b38: 0x4b544700726f6c6f ("olor"?)
0x00007fffffffe5d8│+0x0b40: "_MODULES=gail:atk-bridge"
0x00007fffffffe5e0│+0x0b48: "=gail:atk-bridge"
0x00007fffffffe5e8│+0x0b50: "k-bridge"
0x00007fffffffe5f0│+0x0b58: 0x5255435f47445800
0x00007fffffffe5f8│+0x0b60: "RENT_DESKTOP=GNOME"
0x00007fffffffe600│+0x0b68: "KTOP=GNOME"
0x00007fffffffe608│+0x0b70: 0x415f48535300454d ("ME"?)
0x00007fffffffe610│+0x0b78: "UTH_SOCK=/run/user/1000/keyring/ssh"
0x00007fffffffe618│+0x0b80: "=/run/user/1000/keyring/ssh"
0x00007fffffffe620│+0x0b88: "er/1000/keyring/ssh"
0x00007fffffffe628│+0x0b90: "keyring/ssh"
0x00007fffffffe630│+0x0b98: 0x5353455300687373 ("ssh"?)
0x00007fffffffe638│+0x0ba0: "ION_MANAGER=local/debian:@/tmp/.ICE-unix/929,unix/[...]"
0x00007fffffffe640│+0x0ba8: "GER=local/debian:@/tmp/.ICE-unix/929,unix/debian:/[...]"
0x00007fffffffe648│+0x0bb0: "l/debian:@/tmp/.ICE-unix/929,unix/debian:/tmp/.ICE[...]"
0x00007fffffffe650│+0x0bb8: ":@/tmp/.ICE-unix/929,unix/debian:/tmp/.ICE-unix/92[...]"
0x00007fffffffe658│+0x0bc0: "ICE-unix/929,unix/debian:/tmp/.ICE-unix/929"
0x00007fffffffe660│+0x0bc8: "/929,unix/debian:/tmp/.ICE-unix/929"
0x00007fffffffe668│+0x0bd0: "x/debian:/tmp/.ICE-unix/929"
0x00007fffffffe670│+0x0bd8: ":/tmp/.ICE-unix/929"
0x00007fffffffe678│+0x0be0: "CE-unix/929"
0x00007fffffffe680│+0x0be8: 0x4854415000393239 ("929"?)
0x00007fffffffe688│+0x0bf0: "=/home/kongjiadongyuan/.opam/default/bin:/home/kon[...]"
0x00007fffffffe690│+0x0bf8: "ongjiadongyuan/.opam/default/bin:/home/kongjiadong[...]"
0x00007fffffffe698│+0x0c00: "ngyuan/.opam/default/bin:/home/kongjiadongyuan/gor[...]"
0x00007fffffffe6a0│+0x0c08: "opam/default/bin:/home/kongjiadongyuan/goroot/bin:[...]"
0x00007fffffffe6a8│+0x0c10: "ault/bin:/home/kongjiadongyuan/goroot/bin:/home/ko[...]"
0x00007fffffffe6b0│+0x0c18: ":/home/kongjiadongyuan/goroot/bin:/home/kongjiadon[...]"
0x00007fffffffe6b8│+0x0c20: "ongjiadongyuan/goroot/bin:/home/kongjiadongyuan/go[...]"
0x00007fffffffe6c0│+0x0c28: "ngyuan/goroot/bin:/home/kongjiadongyuan/gopath/bin[...]"
0x00007fffffffe6c8│+0x0c30: "oroot/bin:/home/kongjiadongyuan/gopath/bin:/usr/lo[...]"
0x00007fffffffe6d0│+0x0c38: "n:/home/kongjiadongyuan/gopath/bin:/usr/local/bin:[...]"
0x00007fffffffe6d8│+0x0c40: "kongjiadongyuan/gopath/bin:/usr/local/bin:/usr/bin[...]"
0x00007fffffffe6e0│+0x0c48: "ongyuan/gopath/bin:/usr/local/bin:/usr/bin:/bin:/u[...]"
0x00007fffffffe6e8│+0x0c50: "gopath/bin:/usr/local/bin:/usr/bin:/bin:/usr/games[...]"
0x00007fffffffe6f0│+0x0c58: "in:/usr/local/bin:/usr/bin:/bin:/usr/games:/home/k[...]"
0x00007fffffffe6f8│+0x0c60: "local/bin:/usr/bin:/bin:/usr/games:/home/kongjiado[...]"
0x00007fffffffe700│+0x0c68: "n:/usr/bin:/bin:/usr/games:/home/kongjiadongyuan/l[...]"
0x00007fffffffe708│+0x0c70: "in:/bin:/usr/games:/home/kongjiadongyuan/llvm/buil[...]"
0x00007fffffffe710│+0x0c78: "/usr/games:/home/kongjiadongyuan/llvm/build/bin:/h[...]"
0x00007fffffffe718│+0x0c80: "es:/home/kongjiadongyuan/llvm/build/bin:/home/kong[...]"
0x00007fffffffe720│+0x0c88: "/kongjiadongyuan/llvm/build/bin:/home/kongjiadongy[...]"
0x00007fffffffe728│+0x0c90: "dongyuan/llvm/build/bin:/home/kongjiadongyuan/.loc[...]"
0x00007fffffffe730│+0x0c98: "/llvm/build/bin:/home/kongjiadongyuan/.local/bin/"
0x00007fffffffe738│+0x0ca0: "ild/bin:/home/kongjiadongyuan/.local/bin/"
0x00007fffffffe740│+0x0ca8: "/home/kongjiadongyuan/.local/bin/"
0x00007fffffffe748│+0x0cb0: "ngjiadongyuan/.local/bin/"
0x00007fffffffe750│+0x0cb8: "gyuan/.local/bin/"
0x00007fffffffe758│+0x0cc0: "ocal/bin/"
0x00007fffffffe760│+0x0cc8: 0x2f3d454d4f48002f ("/"?)
0x00007fffffffe768│+0x0cd0: "home/kongjiadongyuan"
0x00007fffffffe770│+0x0cd8: "gjiadongyuan"
0x00007fffffffe778│+0x0ce0: 0x474458006e617579 ("yuan"?)
0x00007fffffffe780│+0x0ce8: "_SEAT=seat0"
0x00007fffffffe788│+0x0cf0: 0x444f4d5800307461 ("at0"?)
0x00007fffffffe790│+0x0cf8: "IFIERS=@im=ibus"
0x00007fffffffe798│+0x0d00: 0x00737562693d6d69 ("im=ibus"?)
0x00007fffffffe7a0│+0x0d08: "XDG_RUNTIME_DIR=/run/user/1000"
0x00007fffffffe7a8│+0x0d10: "IME_DIR=/run/user/1000"
0x00007fffffffe7b0│+0x0d18: "/run/user/1000"
0x00007fffffffe7b8│+0x0d20: 0x4700303030312f72 ("r/1000"?)
0x00007fffffffe7c0│+0x0d28: "IO_LAUNCHED_DESKTOP_FILE_PID=1585"
0x00007fffffffe7c8│+0x0d30: "HED_DESKTOP_FILE_PID=1585"
0x00007fffffffe7d0│+0x0d38: "TOP_FILE_PID=1585"
0x00007fffffffe7d8│+0x0d40: "_PID=1585"
0x00007fffffffe7e0│+0x0d48: 0x6b3d524553550035 ("5"?)
0x00007fffffffe7e8│+0x0d50: "ongjiadongyuan"
0x00007fffffffe7f0│+0x0d58: 0x54006e617579676e ("ngyuan"?)
0x00007fffffffe7f8│+0x0d60: "ERMINATOR_DBUS_PATH=/net/tenshu/Terminator2"
0x00007fffffffe800│+0x0d68: "R_DBUS_PATH=/net/tenshu/Terminator2"
0x00007fffffffe808│+0x0d70: "ATH=/net/tenshu/Terminator2"
0x00007fffffffe810│+0x0d78: "/tenshu/Terminator2"
0x00007fffffffe818│+0x0d80: "Terminator2"
0x00007fffffffe820│+0x0d88: 0x3d48535a0032726f ("or2"?)
0x00007fffffffe828│+0x0d90: "/home/kongjiadongyuan/.oh-my-zsh"
0x00007fffffffe830│+0x0d98: "ngjiadongyuan/.oh-my-zsh"
0x00007fffffffe838│+0x0da0: "gyuan/.oh-my-zsh"
0x00007fffffffe840│+0x0da8: "h-my-zsh"
0x00007fffffffe848│+0x0db0: 0x6c3d524547415000
0x00007fffffffe850│+0x0db8: 0x5353454c00737365 ("ess"?)
0x00007fffffffe858│+0x0dc0: 0x4f43534c00522d3d ("=-R"?)
0x00007fffffffe860│+0x0dc8: "LORS=Gxfxcxdxbxegedabagacad"
0x00007fffffffe868│+0x0dd0: "xcxdxbxegedabagacad"
0x00007fffffffe870│+0x0dd8: "gedabagacad"
0x00007fffffffe878│+0x0de0: 0x435f534c00646163 ("cad"?)
0x00007fffffffe880│+0x0de8: "OLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;[...]"
0x00007fffffffe888│+0x0df0: "=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01[...]"
0x00007fffffffe890│+0x0df8: ";34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=4[...]"
0x00007fffffffe898│+0x0e00: "1;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:[...]"
0x00007fffffffe8a0│+0x0e08: "00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33[...]"
0x00007fffffffe8a8│+0x0e10: ";33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=4[...]"
0x00007fffffffe8b0│+0x0e18: "1;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:[...]"
0x00007fffffffe8b8│+0x0e20: "01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su[...]"
0x00007fffffffe8c0│+0x0e28: "=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:s[...]"
0x00007fffffffe8c8│+0x0e30: "1:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:[...]"
0x00007fffffffe8d0│+0x0e38: "33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41[...]"
0x00007fffffffe8d8│+0x0e40: "=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;4[...]"
0x00007fffffffe8e0│+0x0e48: "1:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;[...]"
0x00007fffffffe8e8│+0x0e50: "su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37[...]"
0x00007fffffffe8f0│+0x0e58: ":sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=0[...]"
0x00007fffffffe8f8│+0x0e60: "3:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.t[...]"
0x00007fffffffe900│+0x0e68: "41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31[...]"
0x00007fffffffe908│+0x0e70: ";42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=0[...]"
0x00007fffffffe910│+0x0e78: "4;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.a[...]"
0x00007fffffffe918│+0x0e80: "37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31[...]"
0x00007fffffffe920│+0x0e88: "=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=0[...]"
0x00007fffffffe928│+0x0e90: ".tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.t[...]"
0x00007fffffffe930│+0x0e98: "31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31[...]"
0x00007fffffffe938│+0x0ea0: "=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=0[...]"
0x00007fffffffe940│+0x0ea8: ".arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.l[...]"
0x00007fffffffe948│+0x0eb0: "31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31[...]"
0x00007fffffffe950│+0x0eb8: "=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=0[...]"
0x00007fffffffe958│+0x0ec0: ".taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.l[...]"
0x00007fffffffe960│+0x0ec8: "31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;3[...]"
0x00007fffffffe968│+0x0ed0: "=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=[...]"
0x00007fffffffe970│+0x0ed8: ".lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.[...]"
0x00007fffffffe978│+0x0ee0: "31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;3[...]"
0x00007fffffffe980│+0x0ee8: "=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=[...]"
0x00007fffffffe988│+0x0ef0: ".lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.[...]"
0x00007fffffffe990│+0x0ef8: ";31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;3[...]"
0x00007fffffffe998│+0x0f00: "z=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=[...]"
0x00007fffffffe9a0│+0x0f08: "*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.[...]"
0x00007fffffffe9a8│+0x0f10: ";31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:[...]"
0x00007fffffffe9b0│+0x0f18: "o=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;[...]"
0x00007fffffffe9b8│+0x0f20: "*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=[...]"
0x00007fffffffe9c0│+0x0f28: ";31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.[...]"
0x00007fffffffe9c8│+0x0f30: "p=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;3[...]"
0x00007fffffffe9d0│+0x0f38: "*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=0[...]"
0x00007fffffffe9d8│+0x0f40: "1:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.l[...]"
0x00007fffffffe9e0│+0x0f48: "1;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31[...]"
0x00007fffffffe9e8│+0x0f50: "z=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01[...]"
0x00007fffffffe9f0│+0x0f58: "*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zs[...]"
0x00007fffffffe9f8│+0x0f60: ";31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:[...]"
0x00007fffffffea00│+0x0f68: "=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=0[...]"
0x00007fffffffea08│+0x0f70: ".lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.b[...]"
0x00007fffffffea10│+0x0f78: "31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31[...]"
0x00007fffffffea18│+0x0f80: "01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01[...]"
0x00007fffffffea20│+0x0f88: "zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tb[...]"
0x00007fffffffea28│+0x0f90: "1:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:[...]"
0x00007fffffffea30│+0x0f98: "=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=0[...]"
0x00007fffffffea38│+0x0fa0: ".bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.t[...]"
0x00007fffffffea40│+0x0fa8: "31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:[...]"
0x00007fffffffea48│+0x0fb0: "01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01[...]"
0x00007fffffffea50│+0x0fb8: "tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rp[...]"
0x00007fffffffea58│+0x0fc0: "1:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:[...]"
0x00007fffffffea60│+0x0fc8: "=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01[...]"
0x00007fffffffea68│+0x0fd0: ".tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.wa[...]"
0x00007fffffffea70│+0x0fd8: "1:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:[...]"
0x00007fffffffea78│+0x0fe0: "01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01[...]"
0x00007fffffffea80│+0x0fe8: "rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sa[...]"
0x00007fffffffea88│+0x0ff0: "1:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:[...]"
0x00007fffffffea90│+0x0ff8: "01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01[...]"
0x00007fffffffea98│+0x1000: "war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.al[...]"
0x00007fffffffeaa0│+0x1008: "1:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:[...]"
0x00007fffffffeaa8│+0x1010: "01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01[...]"
0x00007fffffffeab0│+0x1018: "sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zo[...]"
0x00007fffffffeab8│+0x1020: "1:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:[...]"
0x00007fffffffeac0│+0x1028: "01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=0[...]"
0x00007fffffffeac8│+0x1030: "alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7[...]"
0x00007fffffffead0│+0x1038: "1:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:[...]"
0x00007fffffffead8│+0x1040: "01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;[...]"
0x00007fffffffeae0│+0x1048: "zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab[...]"
0x00007fffffffeae8│+0x1050: "1:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*[...]"
0x00007fffffffeaf0│+0x1058: "=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;[...]"
0x00007fffffffeaf8│+0x1060: ".7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm[...]"
0x00007fffffffeb00│+0x1068: "1:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*[...]"
0x00007fffffffeb08│+0x1070: "1;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;[...]"
0x00007fffffffeb10│+0x1078: "ab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd[...]"
0x00007fffffffeb18│+0x1080: ":*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*[...]"
0x00007fffffffeb20│+0x1088: "1;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;[...]"
0x00007fffffffeb28│+0x1090: "wm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpe[...]"
0x00007fffffffeb30│+0x1098: ":*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:[...]"
0x00007fffffffeb38│+0x10a0: "1;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=0[...]"
0x00007fffffffeb40│+0x10a8: "sd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.m[...]"
0x00007fffffffeb48│+0x10b0: ":*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;[...]"
0x00007fffffffeb50│+0x10b8: "1;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif[...]"
0x00007fffffffeb58│+0x10c0: "peg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*[...]"
0x00007fffffffeb60│+0x10c8: "5:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;[...]"
0x00007fffffffeb68│+0x10d0: "=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm[...]"
0x00007fffffffeb70│+0x10d8: ".mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*[...]"
0x00007fffffffeb78│+0x10e0: "1;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;[...]"
0x00007fffffffeb80│+0x10e8: "if=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm[...]"
0x00007fffffffeb88│+0x10f0: ":*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*[...]"
0x00007fffffffeb90│+0x10f8: "1;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;[...]"
0x00007fffffffeb98│+0x1100: "bm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm[...]"
0x00007fffffffeba0│+0x1108: ":*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*[...]"
0x00007fffffffeba8│+0x1110: "1;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;[...]"
0x00007fffffffebb0│+0x1118: "pm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif[...]"
0x00007fffffffebb8│+0x1120: ":*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*[...]"
0x00007fffffffebc0│+0x1128: "1;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01[...]"
0x00007fffffffebc8│+0x1130: "bm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.pn[...]"
0x00007fffffffebd0│+0x1138: ":*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:[...]"
0x00007fffffffebd8│+0x1140: "1;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01[...]"
0x00007fffffffebe0│+0x1148: "if=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.sv[...]"
0x00007fffffffebe8│+0x1150: ":*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35[...]"
0x00007fffffffebf0│+0x1158: "01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=0[...]"
0x00007fffffffebf8│+0x1160: "png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.p[...]"
0x00007fffffffec00│+0x1168: "5:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35[...]"
0x00007fffffffec08│+0x1170: "01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=0[...]"
0x00007fffffffec10│+0x1178: "svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.m[...]"
0x00007fffffffec18│+0x1180: "35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35[...]"
0x00007fffffffec20│+0x1188: "=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=[...]"
0x00007fffffffec28│+0x1190: ".pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.[...]"
0x00007fffffffec30│+0x1198: "35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;3[...]"
0x00007fffffffec38│+0x11a0: "=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=[...]"
0x00007fffffffec40│+0x11a8: ".mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.[...]"
0x00007fffffffec48│+0x11b0: "35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;[...]"
0x00007fffffffec50│+0x11b8: "g=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm[...]"
0x00007fffffffec58│+0x11c0: "*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*[...]"
0x00007fffffffec60│+0x11c8: ";35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;[...]"
0x00007fffffffec68│+0x11d0: "v=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v[...]"
0x00007fffffffec70│+0x11d8: "*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*[...]"
0x00007fffffffec78│+0x11e0: "1;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01[...]"
0x00007fffffffec80│+0x11e8: "gm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vo[...]"
0x00007fffffffec88│+0x11f0: ":*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:[...]"
0x00007fffffffec90│+0x11f8: "1;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;[...]"
0x00007fffffffec98│+0x1200: "4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv[...]"
0x00007fffffffeca0│+0x1208: ":*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*[...]"
0x00007fffffffeca8│+0x1210: "01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;[...]"
0x00007fffffffecb0│+0x1218: "vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf[...]"
0x00007fffffffecb8│+0x1220: "5:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*[...]"
0x00007fffffffecc0│+0x1228: "1;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;3[...]"
0x00007fffffffecc8│+0x1230: "uv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb[...]"
0x00007fffffffecd0│+0x1238: ":*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*[...]"
0x00007fffffffecd8│+0x1240: "1;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;[...]"
0x00007fffffffece0│+0x1248: "sf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi[...]"
0x00007fffffffece8│+0x1250: ":*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*[...]"
0x00007fffffffecf0│+0x1258: ";35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;[...]"
0x00007fffffffecf8│+0x1260: "vb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv[...]"
0x00007fffffffed00│+0x1268: ":*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*[...]"
0x00007fffffffed08│+0x1270: "1;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;3[...]"
0x00007fffffffed10│+0x1278: "vi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=0[...]"
0x00007fffffffed18│+0x1280: ":*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.x[...]"
0x00007fffffffed20│+0x1288: "1;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35[...]"
0x00007fffffffed28│+0x1290: "lv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=0[...]"
0x00007fffffffed30│+0x1298: ":*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.y[...]"
0x00007fffffffed38│+0x12a0: ";35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35[...]"
0x00007fffffffed40│+0x12a8: "=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=0[...]"
0x00007fffffffed48│+0x12b0: ".xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.e[...]"
0x00007fffffffed50│+0x12b8: "35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35[...]"
0x00007fffffffed58│+0x12c0: "=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=0[...]"
0x00007fffffffed60│+0x12c8: ".yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.o[...]"
0x00007fffffffed68│+0x12d0: "35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35[...]"
0x00007fffffffed70│+0x12d8: "=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=0[...]"
0x00007fffffffed78│+0x12e0: ".emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.a[...]"
0x00007fffffffed80│+0x12e8: "35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:[...]"
0x00007fffffffed88│+0x12f0: "=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=0[...]"
0x00007fffffffed90│+0x12f8: ".ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m[...]"
0x00007fffffffed98│+0x1300: "35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36[...]"
0x00007fffffffeda0│+0x1308: "=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=0[...]"
0x00007fffffffeda8│+0x1310: ".au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.m[...]"
0x00007fffffffedb0│+0x1318: "6:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;3[...]"
0x00007fffffffedb8│+0x1320: "=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=[...]"
0x00007fffffffedc0│+0x1328: ".m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.[...]"
0x00007fffffffedc8│+0x1330: "36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;3[...]"
0x00007fffffffedd0│+0x1338: "=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=[...]"
0x00007fffffffedd8│+0x1340: ".midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.[...]"
0x00007fffffffede0│+0x1348: ";36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;3[...]"
0x00007fffffffede8│+0x1350: "a=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=0[...]"
0x00007fffffffedf0│+0x1358: "*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.w[...]"
0x00007fffffffedf8│+0x1360: ";36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36[...]"
0x00007fffffffee00│+0x1368: "c=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=0[...]"
0x00007fffffffee08│+0x1370: "*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.o[...]"
0x00007fffffffee10│+0x1378: ";36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;3[...]"
0x00007fffffffee18│+0x1380: "=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=[...]"
0x00007fffffffee20│+0x1388: ".wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.[...]"
0x00007fffffffee28│+0x1390: "36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;[...]"
0x00007fffffffee30│+0x1398: "=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:"
0x00007fffffffee38│+0x13a0: ".opus=00;36:*.spx=00;36:*.xspf=00;36:"
0x00007fffffffee40│+0x13a8: ";36:*.spx=00;36:*.xspf=00;36:"
0x00007fffffffee48│+0x13b0: "x=00;36:*.xspf=00;36:"
0x00007fffffffee50│+0x13b8: "*.xspf=00;36:"
0x00007fffffffee58│+0x13c0: 0x4f47003a36333b30 ("0;36:"?)
0x00007fffffffee60│+0x13c8: "PATH=/home/kongjiadongyuan/gopath"
0x00007fffffffee68│+0x13d0: "me/kongjiadongyuan/gopath"
0x00007fffffffee70│+0x13d8: "iadongyuan/gopath"
0x00007fffffffee78│+0x13e0: "an/gopath"
0x00007fffffffee80│+0x13e8: 0x544f4f524f470068 ("h"?)
0x00007fffffffee88│+0x13f0: "=/home/kongjiadongyuan/goroot"
0x00007fffffffee90│+0x13f8: "ongjiadongyuan/goroot"
0x00007fffffffee98│+0x1400: "ngyuan/goroot"
0x00007fffffffeea0│+0x1408: 0x504f00746f6f726f ("oroot"?)
0x00007fffffffeea8│+0x1410: "AMNOENVNOTICE=true"
0x00007fffffffeeb0│+0x1418: "OTICE=true"
0x00007fffffffeeb8│+0x1420: 0x5f4d41504f006575 ("ue"?)
0x00007fffffffeec0│+0x1428: "SWITCH_PREFIX=/home/kongjiadongyuan/.opam/default"
0x00007fffffffeec8│+0x1430: "REFIX=/home/kongjiadongyuan/.opam/default"
0x00007fffffffeed0│+0x1438: "ome/kongjiadongyuan/.opam/default"
0x00007fffffffeed8│+0x1440: "jiadongyuan/.opam/default"
0x00007fffffffeee0│+0x1448: "uan/.opam/default"
0x00007fffffffeee8│+0x1450: "m/default"
0x00007fffffffeef0│+0x1458: 0x4c5f4c4d41430074 ("t"?)
0x00007fffffffeef8│+0x1460: "D_LIBRARY_PATH=/home/kongjiadongyuan/.opam/default[...]"
0x00007fffffffef00│+0x1468: "Y_PATH=/home/kongjiadongyuan/.opam/default/lib/stu[...]"
0x00007fffffffef08│+0x1470: "home/kongjiadongyuan/.opam/default/lib/stublibs:/u[...]"
0x00007fffffffef10│+0x1478: "gjiadongyuan/.opam/default/lib/stublibs:/usr/local[...]"
0x00007fffffffef18│+0x1480: "yuan/.opam/default/lib/stublibs:/usr/local/lib/oca[...]"
0x00007fffffffef20│+0x1488: "am/default/lib/stublibs:/usr/local/lib/ocaml/4.05.[...]"
0x00007fffffffef28│+0x1490: "lt/lib/stublibs:/usr/local/lib/ocaml/4.05.0/stubli[...]"
0x00007fffffffef30│+0x1498: "tublibs:/usr/local/lib/ocaml/4.05.0/stublibs:/usr/[...]"
0x00007fffffffef38│+0x14a0: "/usr/local/lib/ocaml/4.05.0/stublibs:/usr/lib/ocam[...]"
0x00007fffffffef40│+0x14a8: "al/lib/ocaml/4.05.0/stublibs:/usr/lib/ocaml/stubli[...]"
0x00007fffffffef48│+0x14b0: "caml/4.05.0/stublibs:/usr/lib/ocaml/stublibs"
0x00007fffffffef50│+0x14b8: "5.0/stublibs:/usr/lib/ocaml/stublibs"
0x00007fffffffef58│+0x14c0: "libs:/usr/lib/ocaml/stublibs"
0x00007fffffffef60│+0x14c8: "r/lib/ocaml/stublibs"
0x00007fffffffef68│+0x14d0: "aml/stublibs"
0x00007fffffffef70│+0x14d8: 0x41434f007362696c ("libs"?)
0x00007fffffffef78│+0x14e0: "ML_TOPLEVEL_PATH=/home/kongjiadongyuan/.opam/defau[...]"
0x00007fffffffef80│+0x14e8: "VEL_PATH=/home/kongjiadongyuan/.opam/default/lib/t[...]"
0x00007fffffffef88│+0x14f0: "=/home/kongjiadongyuan/.opam/default/lib/toplevel"
0x00007fffffffef90│+0x14f8: "ongjiadongyuan/.opam/default/lib/toplevel"
0x00007fffffffef98│+0x1500: "ngyuan/.opam/default/lib/toplevel"
0x00007fffffffefa0│+0x1508: "opam/default/lib/toplevel"
0x00007fffffffefa8│+0x1510: "ault/lib/toplevel"
0x00007fffffffefb0│+0x1518: "/toplevel"
0x00007fffffffefb8│+0x1520: 0x5441504e414d006c ("l"?)
0x00007fffffffefc0│+0x1528: "H=:/home/kongjiadongyuan/.opam/default/man"
0x00007fffffffefc8│+0x1530: "/kongjiadongyuan/.opam/default/man"
0x00007fffffffefd0│+0x1538: 0x6e617579676e6f64
0x00007fffffffefd8│+0x1540: 0x642f6d61706f2e2f
0x00007fffffffefe0│+0x1548: 0x6d2f746c75616665
0x00007fffffffefe8│+0x1550: 0x2f7273752f006e61
0x00007fffffffeff0│+0x1558: 0x007461632f6e6962
0x00007fffffffeff8│+0x1560: 0x0000000000000000
```

We can observe that, the lower address area of the stack (that is, the top of the stack) stores the function call stack (you should be very familiar with it), the higher address area of the stack (that is, the bottom of the stack) stores some strings, including *path*, *environment string*, etc.

But there exists a **hole** between them, just like the area from 0x00007fffffffe050 to 0x00007fffffffe248. If you execute the program repeatedly, you will find that the size of the **hole** changes every time.

So now you know, if we want to control the address of function call stack (not only the page address where the stack locate), we have to control at least two parameters, like this:

![stackmagic](images\README\stackmagic.png)

The last question is, why we call *stack_magic* as "magic", and how does it influences the address of function call stack.

Unfortunately, it's hard to calculate it accurately, and it's also hard to explain the influence it exerts. In linux kernel, there is indeed a variable which is randomly assigned and finally decides where the function call stack starts, but there are other factors, such as the length of those strings (path, env, etc).

In fact, when we try to use this tool to do something, we do not care about the **absolute offset**, but the **relative offset**. 

For example, when we are solving a format string problem, we may want the address of a variable on the stack to end with *0x90*. Then you enable the stack hook, and set the STACK_BASE to *0x00007fffffffe000* (that's not important in this case), and randomly set the stack_magic to *0x50*. When you execute the program, you find that the address of the variable you care about ends with *0x30*, which means you want the function call stack "grow" by *0x60*, so now you can reset *stack_magic* to let it reduce *0x60* (pay attention to the increase and decrease relationship here), to *-0x10*, however, we need an unsigned integer here, so *0xf0* is also a good choice (*-0x10 + 0x100*, which doesn't affect the lowest byte of the address).

Sounds complicated right? You can deepen understanding with the help of graph above. OR, just try again and again and again, you can always find the offset you want, and the state space is small anyway (I always do this : P).

## Some Problems

1. When the kernel module is loaded, gdb will fail while directly starting a program.

   ```bash
   > gdb /bin/ls
   gdb> start
   # BOOM
   ```

   I haven't researched the problem yet, so I recommand you to start a program manually, and use gdb to attach it (as we often do in CTF competitions)

   ```bash
   # shell1
   >./target
   
   
   # shell2
   > ps -ef  | grep target
   123 target
   > sudo -E gdb attach 123
   gdb> ...
   ```

2. When you find your kernel is not right, just smile, and reboot it.
   : P
