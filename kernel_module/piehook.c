#include "piehook_include.h"
#include "piehook_utils.h"
#include "../piehook_define.h"
MODULE_LICENSE("Dual BSD/GPL");


// ===============================================
// DEFINITIONS
// ===============================================


static int piehook_major_num;
static struct class * piehook_class = NULL;
static struct device * piehook_device = NULL;

#define DEVICE_NAME "piehook"
#define CLASS_NAME "piehook_module"
#define PIDMAX 0x10000
#define PIEHOOK_DBG


struct search_helper{
    char *target_name;
    unsigned long *addresses;
    unsigned long address_number;
    unsigned long max_address_number;
};

static long piehook_ioctl(struct file *, unsigned int, unsigned long);
static ssize_t piehook_write(struct file *, const char *, size_t, loff_t *);
static ssize_t piehook_read(struct file *, char *, size_t, loff_t *);

// symbol functions
unsigned long (*piehook_kallsyms_lookup_name)(const char *);
int (*piehook_kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);

// origin functions
int orig_load_elf_binary_initialized;
unsigned long orig_load_elf_binary[2];
unsigned long orig_arch_mmap_rnd;
unsigned long orig_arch_randomize_brk;
unsigned long orig_create_elf_tables;
unsigned long orig_arch_align_stack;
unsigned long orig_randomize_page;

// patch variables
char arch_align_stack_saved[5];

unsigned long arch_mmap_rnd_call[2];
unsigned long randomize_page_call;


// piehook variables
unsigned long pie_rnd_offset;
int piehook_enabled;

// heaphook variables
unsigned long heap_rnd_offset;
int heaphook_enabled;

// stackhook variables
unsigned char *piehook_pidtable;

unsigned long stack_rnd_base;
unsigned long stack_rnd_offset;
int stackhook_enabled;


// ===============================================
// FUNCTIONS
// ===============================================


// piehook
unsigned long 
my_arch_mmap_rnd(void){
    if(!piehook_enabled){
        return ((unsigned long (*)(void))orig_arch_mmap_rnd)();
    }
    else{
        return pie_rnd_offset;
    }
}


// heaphook
unsigned long
my_randomize_page(unsigned long start, unsigned long range){
    unsigned long result;
    if(!heaphook_enabled){
        result = ((unsigned long (*)(unsigned long, unsigned long))orig_randomize_page)(start, range);
    }
    else{
        result = start + ((heap_rnd_offset % range) & ~(((unsigned long)1 << 12) - 1));
    }
    return result;
}


// stackhook
unsigned long 
my_arch_align_stack(unsigned long sp){
    unsigned long result;
    result = STACKTOP_MAX;
    if(piehook_pidtable[current->pid] == 0){
        // first time
        if(stackhook_enabled){
            result = stack_rnd_base & ~0xfff;
        }
        else{
            sp -= get_random_int() % 8192;
            result = sp & ~0xf;
        }
    }
    else{
        // second time
        if(!(current->personality & ADDR_NO_RANDOMIZE)){
            if(stackhook_enabled){
                sp -= stack_rnd_offset % 8192;
                result = sp & ~0xf;
            }
            else{
                sp -= get_random_int() % 8192;
                result = sp & ~0xf;
            }
        }
    }
    piehook_pidtable[current->pid] = (piehook_pidtable[current->pid] ? 0 : 1);
    return result;   
}

int 
cmp_and_insert(void *data, const char *namebuf, struct module *module, unsigned long addr){
    struct search_helper *sh;
    sh = (struct search_helper *)data;
    if(sh->address_number == sh->max_address_number){
        return 0;
    }
    if(strcmp(sh->target_name, namebuf) == 0){
        sh->addresses[sh->address_number] = addr;
        sh->address_number += 1;
    }
    return 0;
}

struct search_helper *piehook_find_symbol(const char *name, unsigned long max_address_number){
    struct search_helper *sh;
    sh = (struct search_helper *)kmalloc(sizeof(struct search_helper), GFP_KERNEL);
    sh->target_name = (char *)kmalloc(strlen(name), GFP_KERNEL);
    strcpy(sh->target_name, name);
    sh->max_address_number = max_address_number;
    sh->address_number = 0;
    sh->addresses = (unsigned long *)kmalloc(sh->max_address_number * sizeof(unsigned long), GFP_KERNEL);
    piehook_kallsyms_on_each_symbol(cmp_and_insert, sh);
    return sh;
}

void release_search_helper(struct search_helper *sh){
    kfree(sh->addresses);
    kfree(sh->target_name);
    kfree(sh);
}

static ssize_t piehook_write(struct file *filp, const char *buff, size_t len, loff_t *off){
    char *msg = (char *)kmalloc(32, GFP_KERNEL);
    short count;
    printk(KERN_INFO "[piehook] Write hook.\n");
    count = copy_from_user(msg, buff, len > 32 ? 32 : len);
    printk(KERN_INFO "[piehook] %32s.\n", msg);
    kfree(msg);
    return len;
}

static ssize_t piehook_read(struct file *filp, char *buff, size_t len, loff_t *off){
    
    return 0;
}

static long piehook_ioctl(struct file *file, unsigned int cmd, unsigned long param){
    struct piehook_param p;
    struct piehook_info inf;
    unsigned long rnd_offset = 0, rnd_base = 0;
    unsigned long result;
    result = 0;
    memset(&p, 0, sizeof(p));
    memset(&inf, 0, sizeof(inf));
    if(cmd == PIEHOOK_CONFIG || 
       cmd == STACKHOOK_CONFIG_BASE || 
       cmd == STACKHOOK_CONFIG_OFFSET || 
       cmd == HEAPHOOK_CONFIG){
        if(copy_from_user(&p, (void *)param, sizeof(struct piehook_param))){
            printk(KERN_ERR"%s: copy_from_user error\n", __func__);
            return -1;
        }
        rnd_offset = p.rnd_offset;
        rnd_base = p.rnd_base;
    }
    switch (cmd)
    {

    // pie hook
    case PIEHOOK_ENABLE:
    {
        local_irq_disable();
        disable_write_protection();
        piehook_enabled = 1;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case PIEHOOK_DISABLE:
    {
        local_irq_disable();
        disable_write_protection();
        piehook_enabled = 0;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case PIEHOOK_CONFIG:
    {
        if(rnd_offset & (((unsigned long)1 << 12) - 1)){
            result |= UNALIGNED;
            rnd_offset &= ~(((unsigned long)1 << 12) - 1);
        }

        if(rnd_offset & (~(((unsigned long)1 << (28 + 12)) - 1))){
            result |= ILLEGAL;
            break;
        }
        local_irq_disable();
        disable_write_protection();
        pie_rnd_offset = rnd_offset;
        enable_write_protection();
        local_irq_enable();
        break;
    }

    // heap hook
    case HEAPHOOK_ENABLE:
    {
        local_irq_disable();
        disable_write_protection();
        heaphook_enabled = 1;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case HEAPHOOK_DISABLE:
    {
        local_irq_disable();
        disable_write_protection();
        heaphook_enabled = 0;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case HEAPHOOK_CONFIG:
    {
        if(rnd_offset & (((unsigned long)1 << 12) - 1)){
            result |= UNALIGNED;
            rnd_offset &= ~(((unsigned long)1 << 12) - 1);
        }
        local_irq_disable();
        disable_write_protection();
        heap_rnd_offset = rnd_offset;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    
    // stack hook
    case STACKHOOK_ENABLE:
    {
        local_irq_disable();
        disable_write_protection();
        stackhook_enabled = 1;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case STACKHOOK_DISABLE:
    {
        local_irq_disable();
        disable_write_protection();
        stackhook_enabled = 0;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case STACKHOOK_CONFIG_BASE:
    {
        printk(KERN_INFO"0x%lx\n", rnd_base);
        if(rnd_base & (((unsigned long)1 << 12) - 1)){
            result |= UNALIGNED;
            rnd_base &= ~(((unsigned long)1 << 12) - 1);
        }
        if((STACKTOP_MAX - rnd_base) & ~(((unsigned long)1 << (22 + 12)) - 1) ||
            STACKTOP_MAX < rnd_base){
            result |= ILLEGAL;
            break;
        }
        local_irq_disable();
        disable_write_protection();
        stack_rnd_base = rnd_base;
        enable_write_protection();
        local_irq_enable();
        break;
    }
    case STACKHOOK_CONFIG_OFFSET:
    {
        local_irq_disable();
        disable_write_protection();
        stack_rnd_offset = rnd_offset;
        enable_write_protection();
        local_irq_enable();
        break;
    }

    case INFO:
    {
        inf.pie_rnd_offset = pie_rnd_offset;
        inf.heap_rnd_offset = heap_rnd_offset;
        inf.stack_rnd_base = stack_rnd_base;
        inf.stack_rnd_offset = stack_rnd_offset;
        inf.piehook_enabled = piehook_enabled;
        inf.heaphook_enabled = heaphook_enabled;
        inf.stackhook_enabled = stackhook_enabled;

        if(copy_to_user((void *)param, &inf, sizeof(inf))){
            printk(KERN_ERR "%s: copy_to_user error.\n", __func__);
        }
        break;
    }

    default:
    {
        printk(KERN_INFO "[piehook] Unknown ioctl cmd (0x%x). \n", cmd);
    }
    }

    p.result = result;
    if(cmd == PIEHOOK_CONFIG || cmd == STACKHOOK_CONFIG_BASE || cmd == STACKHOOK_CONFIG_OFFSET || cmd == HEAPHOOK_CONFIG){
        if(copy_to_user((void *)param, &p, sizeof(struct piehook_param))){
            printk(KERN_ERR "%s: copy_to_user error.\n", __func__);
            return -1;
        }
    }
    return 0;
}

unsigned long trick_lookup_name(const char *name){
    unsigned long retval;
    int tmp;
    struct kprobe kp = {
        .symbol_name = name,
    };
    tmp = register_kprobe(&kp);
    if(tmp < 0){
        printk("[piehook] trick_lookup_name ERR: %d\n", tmp);
        return 0;
    }
    retval = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return retval;
}


void hook_pie(void)
{
    struct search_helper *sh;
    unsigned long call1, call2;


    pie_rnd_offset = 0;
    // find address of arch_mmap_rnd (only once) and load_elf_binary (twice).
    orig_arch_mmap_rnd = piehook_kallsyms_lookup_name("arch_mmap_rnd");
    printk(KERN_INFO "[piehook] found: arch_mmap_rnd:\t0x%lx\n", orig_arch_mmap_rnd);

    if (!orig_load_elf_binary_initialized)
    {
        sh = piehook_find_symbol("load_elf_binary", 2);
        orig_load_elf_binary[0] = sh->addresses[0];
        orig_load_elf_binary[1] = sh->addresses[1];
        release_search_helper(sh);
        orig_load_elf_binary_initialized = 1;
        printk(KERN_INFO "[piehook] found: load_elf_binary[0]:\t0x%lx\n", orig_load_elf_binary[0]);
        printk(KERN_INFO "[piehook] found: load_elf_binary[1]:\t0x%lx\n", orig_load_elf_binary[1]);
    }


    call1 = search_call(orig_load_elf_binary[0], orig_arch_mmap_rnd, 0x10000);
    call2 = search_call(orig_load_elf_binary[1], orig_arch_mmap_rnd, 0x10000);

    printk(KERN_INFO "[piehook] found: arch_mmap_rnd call1:\t0x%lx\n", call1);
    printk(KERN_INFO "[piehook] found: arch_mmap_rnd call2:\t0x%lx\n", call2);

    local_irq_disable();
    disable_write_protection();
    
    edit_call(call1, (unsigned long )(&my_arch_mmap_rnd));
    edit_call(call2, (unsigned long )(&my_arch_mmap_rnd));
    
    enable_write_protection();
    local_irq_enable();

    arch_mmap_rnd_call[0] = call1;
    arch_mmap_rnd_call[1] = call2;
}

void dehook_pie(void){
    local_irq_disable();
    disable_write_protection();

    edit_call(arch_mmap_rnd_call[0], orig_arch_mmap_rnd);
    edit_call(arch_mmap_rnd_call[1], orig_arch_mmap_rnd);
    
    enable_write_protection();
    local_irq_enable();
}

void hook_heap(void){
    heap_rnd_offset = 0;
    orig_randomize_page = piehook_kallsyms_lookup_name("randomize_page");
    orig_arch_randomize_brk = piehook_kallsyms_lookup_name("arch_randomize_brk");
    printk(KERN_INFO "[piehook] found: randomize_page:\t0x%lx\n", orig_randomize_page);
    printk(KERN_INFO "[piehook] found: arch_randomize_brk:\t0x%lx\n", orig_arch_randomize_brk);

    randomize_page_call = search_call(orig_arch_randomize_brk, orig_randomize_page, 0x1000);
    printk(KERN_INFO "[piehook] found: call:\t0x%lx\n", randomize_page_call);

    local_irq_disable();
    disable_write_protection();
    edit_call(randomize_page_call, (unsigned long )&my_randomize_page);
    enable_write_protection();
    local_irq_enable();
}

void dehook_heap(void){
    local_irq_disable();
    disable_write_protection();
    edit_call(randomize_page_call, orig_randomize_page);
    enable_write_protection();
    local_irq_enable();
}

void hook_stack(void){
    unsigned long i;
    stack_rnd_base = STACKTOP_MAX;
    stack_rnd_offset = 0;
    orig_arch_align_stack = piehook_kallsyms_lookup_name("arch_align_stack");
    printk("[piehook] found: arch_align_stack:\t0x%lx\n", orig_arch_align_stack);
    memcpy(arch_align_stack_saved, (void *)orig_arch_align_stack, 5);
    piehook_pidtable = (unsigned char *)kmalloc(PIDMAX * sizeof(char), GFP_KERNEL);
    for(i = 0; i < PIDMAX; i ++){
        piehook_pidtable[i] = 0;
    }
    
    local_irq_disable();
    disable_write_protection();
    *(unsigned char *)orig_arch_align_stack = 0xe9;
    edit_call(orig_arch_align_stack, (unsigned long)&my_arch_align_stack);
    enable_write_protection();
    local_irq_enable();
}

void dehook_stack(void){
    local_irq_disable();
    disable_write_protection();
    memcpy((void *)orig_arch_align_stack, arch_align_stack_saved, 5);
    enable_write_protection();
    local_irq_enable();
    kfree(piehook_pidtable);
    piehook_pidtable = NULL;
}

void hook(void){
    printk(KERN_INFO"[piehook] \tHooking PIE. \n");
    hook_pie();
    printk(KERN_INFO"[piehook] \tHooking heap. \n");
    hook_heap();
    printk(KERN_INFO"[piehook] \tHooking stack. \n");
    hook_stack();
}

void dehook(void){
    printk(KERN_INFO"[piehook] \tRestoring PIE. \n");
    dehook_pie();   
    printk(KERN_INFO"[piehook] \tRestoring heap. \n");
    dehook_heap();
    printk(KERN_INFO"[piehook] \tRestoring stack. \n");
    dehook_stack();
}

int prepare_symbol_functions(void){
    // Linux kernel unexported kallsyms_* functions in latest version.
    // So we have to find their address with some tricks
    piehook_kallsyms_lookup_name = (void *)trick_lookup_name("kallsyms_lookup_name");
    piehook_kallsyms_on_each_symbol = (void *)trick_lookup_name("kallsyms_on_each_symbol");
    if((unsigned long)piehook_kallsyms_lookup_name == 0 || (unsigned long)piehook_kallsyms_on_each_symbol == 0){
        return -1;
    }
    return 0;
}

static int __init piehook_init(void){
    static struct file_operations fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = piehook_ioctl,
        .write = piehook_write,
        .read = piehook_read
    };
    printk(KERN_INFO "----------------------------------------------------------------- \n");
    printk(KERN_INFO "[piehook] Start initializing the module. \n");

    printk(KERN_INFO "[piehook] Prepare symbol functions.\n");

    if(prepare_symbol_functions() < 0){
        printk("[piehook] prepare_symbol_functions failed.\n");
        return -1;
    }
    
    printk(KERN_INFO "[piehook] Initialize variables.\n");
    orig_load_elf_binary_initialized = 0;
    
    piehook_enabled = 0;
    heaphook_enabled = 0;
    stackhook_enabled = 0;

    printk(KERN_INFO "[piehook] Registering chrdev. \n");
    piehook_major_num = register_chrdev(0, "piehook", &fops);
    if(piehook_major_num < 0){
        printk(KERN_ALERT "[piehook] Failed to register a major number. \n");
        return piehook_major_num;
    }

    // register dev class.
    printk(KERN_INFO "[piehook] Registering class device. \n");
    piehook_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(piehook_class)){
        unregister_chrdev(piehook_major_num, DEVICE_NAME);
        printk(KERN_ALERT "[piehook] Device class register failed. \n");
        return PTR_ERR(piehook_class);
    }
    printk(KERN_INFO "[piehook] Class device register success. \n");

    // create device.
    printk(KERN_INFO "[piehook] Creating device. \n");
    piehook_device = device_create(piehook_class, NULL, MKDEV(piehook_major_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(piehook_device)){
        class_destroy(piehook_class);
        unregister_chrdev(piehook_major_num, DEVICE_NAME);
        printk(KERN_ALERT "[piehook] Failed to create the device. \n");
        return PTR_ERR(piehook_device);
    }

    printk(KERN_INFO "[piehook] Start hooking functions. \n");
    hook();
    printk(KERN_INFO "[piehook] Hooking functions OK. \n");

    printk(KERN_INFO "[piehook] Module successfully initialized. \n");
    printk(KERN_INFO "----------------------------------------------------------------- \n");
    
    return 0;
}

static void __exit piehook_exit(void){
    printk(KERN_INFO "----------------------------------------------------------------- \n");
    printk(KERN_INFO "[piehook] Start to unload module. \n");
    device_destroy(piehook_class, MKDEV(piehook_major_num, 0));
    class_destroy(piehook_class);
    unregister_chrdev(piehook_major_num, DEVICE_NAME);
    printk(KERN_INFO "[piehook] Restoring function hooks. \n");
    dehook();
    printk(KERN_INFO "[piehook] Restore OK. \n");
    printk(KERN_INFO "[piehook] Module successfully unloaded. \n");
    printk(KERN_INFO "----------------------------------------------------------------- \n");
}


module_init(piehook_init);
module_exit(piehook_exit);

MODULE_AUTHOR("kongjiadongyuan");
