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

int main(int argc, char** argv) {
    const char* invoc_name = argc ? argv[0] : "speedy-portal-bridge";

    if (argc < 3) {
        printf("Usage: %s <portal pid> <speedy pid>\n", invoc_name);
        return EXIT_FAILURE;
    }

    if (!is_valid_number(argv[1]) || !is_valid_number(argv[2])) {
        printf("%s: invalid process id\n", invoc_name);
        return EXIT_FAILURE;
    }

    pid_t speedy_pid = strtol(argv[2], NULL, 10);
    pid_t portal_pid = strtol(argv[1], NULL, 10);

    if (kill(speedy_pid, 0) < 0) {
        printf("%s: process %d does not exist\n", invoc_name, speedy_pid);
        return EXIT_FAILURE;
    }

    if (kill(portal_pid, 0) < 0) {
        printf("%s: process %d does not exist\n", invoc_name, portal_pid);
        return EXIT_FAILURE;
    }

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

                    printf("%d\n", current_map_idx);
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
