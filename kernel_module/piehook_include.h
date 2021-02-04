#ifndef PIEHOOK_INCLUDE
#define PIEHOOK_INCLUDE

#include <linux/init.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/binfmts.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/scpi_protocol.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <uapi/linux/personality.h>
#include <linux/kprobes.h>
#endif