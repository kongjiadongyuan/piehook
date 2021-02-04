#include "pie_interface.h"

extern int optind, opterr, optopt;
extern char *optargi;

typedef struct parameter {
    char *key;
    size_t num_val;
    struct parameter *next;
} PARAM;

typedef struct hook_options {
    size_t text;
    size_t stack;
    size_t heap;
    size_t stackmagic;
} HOOK_OPTIONS;

static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"text", required_argument, NULL, 't'},
    {"stack", required_argument, NULL, 's'},
    {"heap", required_argument, NULL, 'p'},
    {"stackmagic", required_argument, NULL,'g'},
    {"encodejson", required_argument, NULL, 'e'},
    {"decodejson", required_argument, NULL, 'd'},
    {"load", optional_argument, NULL, 'l'},
    {"unload", no_argument, NULL, 'u'},
    {"info", no_argument, NULL, 'i'},
    {"enable-piehook", no_argument, NULL, '1'},
    {"enable-heaphook", no_argument, NULL, '2'},
    {"enable-stackhook", no_argument, NULL, '3'},
    {"disable-piehook", no_argument, NULL, '4'},
    {"disable-heaphook", no_argument, NULL, '5'},
    {"disable-stackhook", no_argument, NULL, '6'},
    {NULL, 0, NULL, 0}
};

static char short_options[] = "hil::ut:s:p:g:e:d:123456";

static char help_msg[] = "Usage: %s [-h|--help] [-i|--info]\n"
                         "          [-l|--load [MOD_DIR]] [-u|--unload]\n"
                         "          [-t|--text TEXT_SEG_BASE] [-s|--stack STACK_BASE] [-p|--heap HEAP_OFFSET] [-g|--stackmagic]\n"
                         "          [-1|--enable-piehook] [-2|--enable-heaphook] [-3|--enable-stackhook]\n"
                         "          [-4|--disable-piehook] [-5|--disable-heaphook] [-6|--disable-stackhook]\n"
                         "          [-e|--encodejson JSONFILE] [-d|--decodejson JSONFILE]\n\n"
                         "    -h, --help\tShow this help message\n"
                         "    -i, --info\tShow the hooked address\n"
                         "    -l, --load\tLoad the piehook kernel module (MOD_DIR means the directory of piehook project, default is ../piehook)\n"
                         "    -u, --unload\tUnload the piehook kernel module (DO NOT CHANGE THE NAME OF MODULE \"piehook\")\n"
                         "    -t, --text TEXT_SEG_BASE\tEnable text base PIE hook (TEXT_SEG_BASE means 0x555555554000 + OFFSET)\n"
                         "    -s, --stack STACK_BASE\tEnable stack base hook (STACK_BASE means the top of user stack area)\n"
                         "    -p, --heap HEAP_OFFSET\tEnable heap base hook (HEAP_OFFSET means OFFSET from the end of text area)\n"
                         "    -g, --stackmagic STACK_OFFSET\tEnable stack offset hook(the offset need to be fine-tuning manually)\n"
                         "    -1~6\tenable or disable the corresponding hook\n"
                         "    -e, --encodejson JSONFILE\texport the setting message to JSONFILE in format of json\n"
                         "    -d, --decodejson JSONFILE\timport the setting message from JSONFILE in format of json\n";

int info = 0;

size_t string2Addr(char *s);
void errorMsg(const char *format, ...);
void infoMsg(const char *format, ...); 
int doTextHook(size_t addr);
int doStackBaseHook(size_t addr);
int doStackOffsetHook(size_t offset);
int doHeapHook(size_t offset);
int encodeJson(PARAM *params, char *filename);
int decodeJson(char *filename);
PARAM* insertParamList(PARAM *root, char *key, size_t val);
int doLoadMod(char *path);
int doUnloadMod();
int doShowInfo();
int doGetInfo(struct piehook_info *p); 
int doEnableTextHook();
int doEnableHeapHook();
int doEnableStackHook();
int doDisableTextHook();
int doDisableHeapHook();
int doDisableStackHook();

int main(int argc, char *argv[]) {
    int opt;
    int long_index = -1;
    size_t addr = 0;
    PARAM *params = NULL;

    if(getuid()) {
        errorMsg("Run as ROOT!!!");
        return 0;
    }

    while(EOF != (opt = getopt_long(argc, argv, short_options, long_options, &long_index))) {
        switch (opt) {
        case 'h':
            fprintf(stderr, help_msg, argv[0]);
            break;

        case 'i':
            info = 1;
            break;
        
        case 'l':
            if (optarg) {
                doLoadMod(optarg);
            }
            else {
                doLoadMod("../piehook");
            }
            break;

        case 'u':
            doUnloadMod();
            break;
        
        case 't':
            addr = string2Addr(optarg);
            params = insertParamList(params, "text", addr);
            doTextHook(addr);
           break;

        case 's':
            addr = string2Addr(optarg);
            params = insertParamList(params, "stack", addr);
            doStackBaseHook(addr);
            break;
        
        case 'p':
            // addr -> heap offset
            addr = string2Addr(optarg);
            params = insertParamList(params, "heap", addr);
            doHeapHook(addr);
            break;

        case 'g':
            // addr -> stack offset
            addr = string2Addr(optarg);
            params = insertParamList(params, "stackmagic", addr);
            doStackOffsetHook(addr);
            break;

        case 'e':
            encodeJson(params, optarg);
            break;
        
        case 'd':
            decodeJson(optarg);
            break;

        case '1':
            doEnableTextHook();
            break;

        case '2':
            doEnableHeapHook();
            break;

        case '3':
            doEnableStackHook();
            break;

        case '4':
            doDisableTextHook();
            break;
        
        case '5':
            doDisableHeapHook();
            break;
        
        case '6':
            doDisableStackHook();
            break;
        
        case '?':
        default:
            fprintf(stderr, "\n");
            fprintf(stderr, help_msg, argv[0]);
            break;
        }
    }

    if (info) {
        doShowInfo();
    }
}

int doEnableTextHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.piehook_enabled) {
        if(ioctl(fd, PIEHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable PIE hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("PIE Hook Enabled, Text Offset: %#lx", pi.pie_rnd_offset + TEXT_MIN);
    close(fd);
    return 0;
}

int doEnableHeapHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.heaphook_enabled) {
        if(ioctl(fd, HEAPHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable Heap hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("Heap Hook Enabled, Heap Base Offset: %#lx", pi.heap_rnd_offset);
    close(fd);
    return 0;
}

int doEnableStackHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.stackhook_enabled) {
        if(ioctl(fd, STACKHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable Stack hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("Stack Hook Enabled, Stack Base: %#lx, Stack Offset: %#lx", pi.stack_rnd_base, pi.stack_rnd_offset);
    close(fd);
    return 0;
}

int doDisableTextHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (pi.piehook_enabled) {
        if(ioctl(fd, PIEHOOK_DISABLE) < 0) {
            errorMsg("Cannot Disable PIE hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("PIE Hook Disabled");
    close(fd);
    return 0;
}

int doDisableHeapHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (pi.heaphook_enabled) {
        if(ioctl(fd, HEAPHOOK_DISABLE) < 0) {
            errorMsg("Cannot Disable Heap hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("Heap Hook Disabled");
    close(fd);
    return 0;
}

int doDisableStackHook() {
    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (pi.stackhook_enabled) {
        if(ioctl(fd, STACKHOOK_DISABLE) < 0) {
            errorMsg("Cannot Disable Stack hook");
            close(fd);
            return -1;
        }
    }

    infoMsg("Stack Hook Disabled");
    close(fd);
    return 0;
}


int doGetInfo(struct piehook_info *p) {
    if (!p) {
        errorMsg("Get info with null pointer");
        return -1;
    }

    int fd = open("/dev/piehook", O_RDWR);

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    if(ioctl(fd, INFO, p) < 0) {
        errorMsg("Cannot get info");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int doShowInfo() {
    struct piehook_info p = {0};
    char on[] = "ON";
    char off[] = "OFF";
    if (!doGetInfo(&p)) {
        printf("PIE Hook: %s\n", p.piehook_enabled? on: off);
        printf("Heap Hook: %s\n", p.heaphook_enabled? on: off);
        printf("Stack Hook: %s\n\n", p.stackhook_enabled? on: off);
        printf("PIE Hook Addr: %#lx\nHeap Hook Offset: %#lx\nStack Hook Base: %#lx\nStack Hook Offset: %#lx\n", TEXT_MIN + p.pie_rnd_offset, p.heap_rnd_offset, p.stack_rnd_base, p.stack_rnd_offset);
        return 0;
    }
    return -1;
}

int doLoadMod(char *path){
    char *buf;
    char format[] = "cd %s;make clean;make;insmod %s/piehook.ko";
    pid_t status;
    buf = (char *)calloc(strlen(format) + 2*strlen(path) + 1, 1);
    sprintf(buf, format, path, path);
    status = system(buf);
    if (status == -1) {
        errorMsg("System Error");
    }
    else {
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0){
                infoMsg("Load Module Successfully");
                return 0;
            }
            else {
                errorMsg("Load Module Failed");
                return -1;
            }
        }
        else {
            errorMsg("Load Module Failed");
            return -1;
        }
    }
    return -1;
}

int doUnloadMod() {
    pid_t status;
    status =  system("rmmod piehook");
    if (status == -1) {
        errorMsg("System Error");
    }
    else {
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0){
                infoMsg("Unload Module Successfully");
                return 0;
            }
            else {
                errorMsg("Unload Module Failed");
                return -1;
            }
        }
        else {
            errorMsg("Unload Module Failed");
            return -1;
        }
    }
    return -1;
}

int decodeJson(char *filename) {
    FILE *fp = fopen(filename, "rb"); 
    long file_size = 0;
    char *buf;
    size_t addr;
    if (!fp) {
        errorMsg("Cannot open %s", filename);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    if(!file_size) {
        errorMsg("Something error with input json file %s", filename);
        return -1;
    }
    rewind(fp);
    buf = (char *)malloc(file_size + 1);
    fread(buf, sizeof(char), file_size, fp);
    buf[file_size] = '\0';
    // printf("%s\n", buf);
    fclose(fp);

    cJSON *root = cJSON_Parse(buf);
    cJSON *json_text = cJSON_GetObjectItem(root, "text");
    if (json_text) {
        addr = string2Addr(json_text->valuestring);
        doTextHook(addr);
    }
    cJSON *json_heap = cJSON_GetObjectItem(root, "heap");
    if (json_heap) {
        addr = string2Addr(json_heap->valuestring);
        doHeapHook(addr);
    }
    cJSON *json_stackoff = cJSON_GetObjectItem(root, "stackmagic");
    if (json_stackoff) {
        addr = string2Addr(json_stackoff->valuestring);
        doStackOffsetHook(addr);
    }
    cJSON *json_stackbase = cJSON_GetObjectItem(root, "stack");
    if (json_stackbase) {
        addr = string2Addr(json_stackbase->valuestring);
        doStackBaseHook(addr);
    }
    return 0;
}


int encodeJson(PARAM *params, char* filename) {
    cJSON *root;
    PARAM *param;
    char buf[0x20];
    FILE* fp = NULL;
    root = cJSON_CreateObject();
    for (param = params; param != NULL; param=param->next) {
        sprintf(buf, "%#lx", param->num_val);
        cJSON_AddStringToObject(root, param->key, buf);
        // printf("%s\n", buf);
    }
    
    fp = fopen(filename, "w");
    if (!fp) {
        errorMsg("Cannot open %s", filename);
        return -1;
    }
    fprintf(fp, "%s", cJSON_PrintUnformatted(root));
    if(root) {
        cJSON_Delete(root);
    }
    fclose(fp);
    return 0;
}

PARAM* insertParamList(PARAM *root, char *key, size_t val) {
    PARAM* temp_param = NULL;
    temp_param = root;
    root = (PARAM *)malloc(sizeof(PARAM));
    if (!root) {
        errorMsg("Parameter alloc failed");
        return NULL;
    }
    root->next = temp_param;
    root->key = strdup(key);
    root->num_val = val;
    return root;
}

size_t string2Addr(char *s) {
    int len = strlen(s);
    if(len == 0) {
        return 0;
    }
    if ( len > 2 && (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2))) {
        return strtoull(s, NULL, 16);
    }
    if ( len > 2 && (!strncmp(s, "0b", 2) || !strncmp(s, "0B", 2))) {
        return strtoull(s + 2, NULL, 2);
    }
    return strtoull(s, NULL, 10);
}

void errorMsg(const char *format, ...) {
    va_list ap;
    char prefix[] = "[-] ERROR: ";
    int len = strlen(prefix) + strlen(format) + 1;
    char *temp_str = (char *)malloc(len + 1);
    strcpy(temp_str, prefix);
    strcat(temp_str, format);
    temp_str[len - 1] = '\n';
    temp_str[len] = '\0';

    va_start(ap, format);
    vfprintf(stderr, temp_str, ap);    

    free(temp_str);
    va_end(ap);
}

void infoMsg(const char *format, ...) {
    va_list ap;
    char prefix[] = "[-] INFO: ";
    int len = strlen(prefix) + strlen(format) + 1;
    char *temp_str = (char *)malloc(len + 1);
    strcpy(temp_str, prefix);
    strcat(temp_str, format);
    temp_str[len - 1] = '\n';
    temp_str[len] = '\0';

    va_start(ap, format);
    vfprintf(stderr, temp_str, ap);    

    free(temp_str);
    va_end(ap);
}

int doTextHook(size_t addr) {
    if(addr < TEXT_MIN) {
        errorMsg("Text base out of range");
        return -1;
    }   

    int fd = open("/dev/piehook", O_RDWR);
    struct piehook_param p = {0, 0, 0};

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.piehook_enabled) {
        if(ioctl(fd, PIEHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable PIE hook");
            close(fd);
            return -1;
        }
    }

    p.rnd_offset = addr - TEXT_MIN;
    if(ioctl(fd, PIEHOOK_CONFIG, &p) < 0) {
        errorMsg("Cannot config PIE hook");
        close(fd);
        return -1;
    }

    if(p.result & 2) {
        errorMsg("Address is invalid, check your input");
        close(fd);
        return -1;
    }
    if (p.result & 1) {
        infoMsg("Text base hooked, but address is not aligned, TEXT_BASE: %#lx", addr & (~0xfff));
        close(fd);
        return 0;
    }
    infoMsg("Text base hooked successfully, TEXT_BASE: %#lx", addr & (~0xfff));
    close(fd);
    return 0;
} 

int doStackBaseHook(size_t addr){
    if(addr > STACKTOP_MAX) {
        errorMsg("Stack base out of range");
        return -1;
    }   
    int fd = open("/dev/piehook", O_RDWR);
    struct piehook_param p = {0, 0, 0};

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.stackhook_enabled) {
        if(ioctl(fd, STACKHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable Stack hook");
            close(fd);
            return -1;
        }
    }

    p.rnd_base = addr;
    if(ioctl(fd, STACKHOOK_CONFIG_BASE, &p) < 0) {
        errorMsg("Cannot config Stack hook");
        close(fd);
        return -1;
    }
    if(p.result & 2) {
        errorMsg("Address is invalid, check your input");
        close(fd);
        return -1;
    }
    if (p.result & 1) {
        infoMsg("Stack base hooked, but address is not aligned, STACK_BASE: %#lx", addr & (~0xfff));
        close(fd);
        return 0;
    }
    infoMsg("Stack base hooked successfully, STACK_BASE: %#lx", addr & (~0xfff));
    close(fd);
    return 0;
}

int doStackOffsetHook(size_t offset){
    int fd = open("/dev/piehook", O_RDWR);
    struct piehook_param p = {0, 0, 0};

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.stackhook_enabled) {
        if(ioctl(fd, STACKHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable Stack hook");
            close(fd);
            return -1;
        }
    }

    p.rnd_offset = offset;
    if(ioctl(fd, STACKHOOK_CONFIG_OFFSET, &p) < 0) {
        errorMsg("Cannot config Stack Offset hook");
        close(fd);
        return -1;
    }
    if(p.result & 2) {
        errorMsg("Address is invalid, check your input");
        close(fd);
        return -1;
    }
    infoMsg("Stack offset hooked successfully, STACK_OFFSET: %#lx", offset);
    close(fd);
    return 0;
}

int doHeapHook(size_t offset){
    if(offset > HEAPOFF_MAX) {
        errorMsg("Heap offset out of range");
        return -1;
    }   

    int fd = open("/dev/piehook", O_RDWR);
    struct piehook_param p = {0, 0, 0};

    if(fd < 0){
        errorMsg("Cannot open /dev/piehook, please load the module first [-l|--load]");
        return -1;
    }

    struct piehook_info pi = {0};
    if (doGetInfo(&pi)) {
        errorMsg("Get info failed");
        close(fd);
        return -1;
    }

    if (!pi.heaphook_enabled) {
        if(ioctl(fd, HEAPHOOK_ENABLE) < 0) {
            errorMsg("Cannot enable Heap hook");
            close(fd);
            return -1;
        }
    }

    p.rnd_offset = offset;
    if(ioctl(fd, HEAPHOOK_CONFIG, &p) < 0) {
        errorMsg("Cannot config Heap hook");
        close(fd);
        return -1;
    }
    if(p.result & 2) {
        errorMsg("Address is invalid, check your input");
        close(fd);
        return -1;
    }
    if (p.result & 1) {
        infoMsg("Heap base hooked, but address is not aligned, HEAP_BASE: %#lx", offset & (~0xfff));
        close(fd);
        return 0;
    }
    infoMsg("Heap base hooked successfully, HEAP_BASE: %#lx", offset & (~0xfff));
    close(fd);
    return 0;
}