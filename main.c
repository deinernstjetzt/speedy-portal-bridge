#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#define LOG(msg) LOGF(msg, 0)

#define LOGF(fmt, ...) do {                             \
    printf("%s: " fmt "\n", g_invoc_name, __VA_ARGS__); \
} while (0)

static const char* g_map_names[] = {
    "testchmb_a_00.bsp",
    "testchmb_a_01.bsp",
    "testchmb_a_02.bsp",
    "testchmb_a_03.bsp",
    "testchmb_a_04.bsp",
    "testchmb_a_05.bsp",
    "testchmb_a_06.bsp",
    "testchmb_a_07.bsp",
    "testchmb_a_08.bsp",
    "testchmb_a_09.bsp",
    "testchmb_a_10.bsp",
    "testchmb_a_11.bsp",
    "testchmb_a_13.bsp",
    "testchmb_a_14.bsp",
    "testchmb_a_15.bsp",
    "escape_00.bsp",
    "escape_01.bsp",
    "escape_02.bsp",
    "advanced_chambers"
};

static const size_t g_map_names_len = sizeof(g_map_names) / sizeof(g_map_names[0]);
static const char* g_invoc_name = "speedy-portal-bridge";

char* read_from_proccess(pid_t pid, void* addr) {
    size_t cap = 0;
    char* res = NULL;
    bool done = false;

    while (!done) {
        uint32_t word = ptrace(PTRACE_PEEKDATA, pid, addr + cap * 4, NULL);
        res = realloc(res, (cap + 1) * 4);

        if (res == NULL) {
            puts("Out of memory!");
            abort();
        }

        memcpy(res + cap * 4, &word, 4);
        
        for (int i = 0; i < 4; ++i) {
            done |= res[cap * 4 + i] == '\0';
        }

        cap += 1;
    }

    return res;
}

char* wait_for_openat(pid_t pid) {
    static const int sys_open = 5;
    static const int sys_openat = 295;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) goto error;
    if (waitpid(pid, NULL, WUNTRACED | WCONTINUED) < 0) goto error;

    char* result = NULL;

    while (result == NULL) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) goto error;
        if (waitpid(pid, NULL, WUNTRACED | WCONTINUED) < 0) goto error;

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) goto error;

        void* fileptr = NULL;

        if (regs.orig_rax == sys_open) {
            fileptr = (void*) (regs.rbx & 0xFFFFFFFF); /* read ebx only */
        } else if (regs.orig_rax == sys_openat) {
            fileptr = (void*) (regs.rcx & 0xFFFFFFFF); /* read ecx only */
        }

        if (fileptr != NULL) {
            result = read_from_proccess(pid, fileptr);
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) goto error;
        if (waitpid(pid, NULL, WUNTRACED | WCONTINUED) < 0) goto error;
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    waitpid(pid, NULL, WUNTRACED | WCONTINUED);
    return result;

error:
    perror("Error waiting for openat");
    return NULL;
}

char* extract_map_name(const char* filename) {
    size_t len = strlen(filename);

    if (len == 0) {
        return NULL;
    }

    size_t start = len - 1;

    while (start > 0 && filename[start - 1] != '/') {
        start -= 1;
    }

    size_t result_len = len - start;
    char* result = calloc(result_len, sizeof(char));

    if (result == NULL) {
        puts("Out of memory!");
        abort();
    }

    memcpy(result, filename + start, result_len);
    return result;
}

bool is_valid_number(const char* s) {
    for (; *s; s++) {
        if (*s < '0' || *s > '9') {
            return false;
        }
    }

    return true;
}

int pidof_wrapper(const char* name) {
    char buf[128];

    strcpy(buf, "pidof -s ");
    strncpy(&buf[9], name, 128 - 9);

    FILE* res = popen(buf, "r");

    if (res == NULL) {
        return -1;
    }
        
    fgets(buf, 128, res);

    char* next = NULL;
    int pid = strtol(buf, &next, 10);

    if (next == buf) {
        return -1;
    }

    return pid;
}

int wait_for_process(const char* name) {
    int res = 0;

    while ((res = pidof_wrapper(name)) < 0) {
        usleep(500000);
    }

    return res;
}

int main(int argc, char** argv) {
    if (argc) {
        g_invoc_name = argv[0];
    }

    pid_t speedy_pid; 
    pid_t portal_pid;

    if (argc == 1) {
        LOG("attempting to find instance of portal");
        portal_pid = wait_for_process("hl2_linux");
        
        if (portal_pid < 0) {
            LOG("couldn't find an instance of portal");
            return EXIT_FAILURE;
        }

        LOGF("found instance of portal with pid %d", portal_pid);
        LOG("attempting to find instance of speedy");

        speedy_pid = wait_for_process("speedy");

        if (speedy_pid < 0) {
            LOG("couldn't find an instance of speedy");
            return EXIT_FAILURE;
        }

        LOGF("found instance of speedy with pid %d", speedy_pid);
    } else if (argc == 3) {
        if (!is_valid_number(argv[1]) || !is_valid_number(argv[2])) {
            LOG("invalid process id");
            return EXIT_FAILURE;
        }

        speedy_pid = strtol(argv[2], NULL, 10);
        portal_pid = strtol(argv[1], NULL, 10);

        if (kill(speedy_pid, 0) < 0) {
            LOGF("process %d does not exist", speedy_pid);
            return EXIT_FAILURE;
        }

        if (kill(portal_pid, 0) < 0) {
            LOGF("process %d does not exist", portal_pid);
            return EXIT_FAILURE;
        }
    } else {
        printf("Usage: %s <portal pid> <speedy pid>\n", g_invoc_name);
        return EXIT_FAILURE;
    }

    LOGF("starting bridge between portal (%d) and speedy (%d)", portal_pid, speedy_pid);
    
    char* res = NULL;
    const char* current_map = NULL;
    int current_map_idx = -1;

    while ((res = wait_for_openat(portal_pid))) {
        char* name;
        bool sendsig;

        sendsig = false;

        if ((name = extract_map_name(res))) {
            for (size_t i = 0; i < g_map_names_len; ++i) {
                if (strcmp(name, g_map_names[i]) == 0 && current_map != g_map_names[i] && current_map_idx < (int) i) {
                    current_map = g_map_names[i];
                    current_map_idx = i;
                    sendsig = true;

                    LOGF("reached checkpoint %d", current_map_idx);
                }
            }
        }

        if (sendsig) {
            kill(speedy_pid, SIGUSR1);
        }

        free(name);
        free(res);
    }

    return EXIT_SUCCESS;
}
