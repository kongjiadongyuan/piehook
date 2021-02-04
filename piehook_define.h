#define PIEHOOK_ENABLE  0x10000
#define PIEHOOK_DISABLE 0x10001
#define PIEHOOK_CONFIG  0x10002

#define HEAPHOOK_ENABLE 0x10003
#define HEAPHOOK_DISABLE 0x10004
#define HEAPHOOK_CONFIG 0x10005

#define STACKHOOK_ENABLE 0x10006
#define STACKHOOK_DISABLE 0x10007
#define STACKHOOK_CONFIG_BASE 0x10008
#define STACKHOOK_CONFIG_OFFSET 0x10009

#define INFO 0x1000a

#define STACKTOP_MAX 0x7ffffffff000
#define HEAPOFF_MAX 0x2000000
#define TEXT_MIN 0x555555554000

#define UNALIGNED 1
#define ILLEGAL 2


struct piehook_param{
    unsigned long rnd_offset;
    unsigned long rnd_base;
    int result;
};

struct piehook_info{
    unsigned long pie_rnd_offset;
    unsigned long heap_rnd_offset;
    unsigned long stack_rnd_base;
    unsigned long stack_rnd_offset;
    int piehook_enabled;
    int heaphook_enabled;
    int stackhook_enabled;
};
