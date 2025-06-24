/*
    Simple Shell Implementation (SSI)
    Author: Lucia Rivera
    This program implements a basic shell in C that supports foreground and background command execution,
    directory changes, and background job management.
    It references code fragments and techniques from the following helper files:
    - fetch-info.c: for obtaining system and user information.
    - pipe4.c: for tokenizing the command line using strtok.
    - inf.c: for running external processes with fork/execvp - From A2 Appendix, CSC 360 Summer 2025.
    References to helper code are marked with 'Reference:'.
*/

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>

#define MAX_LINE 1024

// Structure for background processes
typedef struct bg_process {
    pid_t pid;
    char command[MAX_LINE];
    struct bg_process* next;
} bg_process;

bg_process* bg_head = NULL;

// Add a process to the background list
void add_bg_process(pid_t pid, char* command) {
    bg_process* new_node = malloc(sizeof(bg_process));
    if (!new_node) {
        perror("malloc");
        exit(1);
    }
    new_node->pid = pid;
    strncpy(new_node->command, command, MAX_LINE);
    new_node->next = bg_head;
    bg_head = new_node;
}

// Remove a process from background list by PID
void remove_bg_process(pid_t pid) {
    bg_process* current = bg_head;
    bg_process* prev = NULL;
    while (current) {
        if (current->pid == pid) {
            if (prev == NULL) {
                bg_head = current->next;
            } else {
                prev->next = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

// Print all background jobs
void print_bglist() {
    int count = 0;
    bg_process* current = bg_head;
    while (current) {
        printf("%d: %s\n", current->pid, current->command);
        count++;
        current = current->next;
    }
    printf("Total Background jobs: %d\n", count);
}

// Check if any background process has finished
void check_bg_processes() {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        bg_process* current = bg_head;
        while (current) {
            if (current->pid == pid) {
                printf("%d: %s has terminated.\n", pid, current->command);
                remove_bg_process(pid);
                break;
            }
            current = current->next;
        }
    }
}


// Split the input line into tokens (arguments)
/* Reference: pipe4.c (tokenizing input with strtok, similar to how pipe4.c splits commands) */
int parse_line(char* line, char** args) {
    int count = 0;
    char* token = strtok(line, " \t\n");
    while (token != NULL && count < MAX_LINE / 2) {
        args[count++] = token;
        token = strtok(NULL, " \t\n");
    }
    args[count] = NULL;
    return count;
}

// Handle built-in commands: cd, exit, bg, bglist, pwd
int handle_builtin(char** args, int arg_count) {
    if (strcmp(args[0], "exit") == 0) {
        exit(0);
    } else if (strcmp(args[0], "cd") == 0) {
        // Reference: fetch-info.c
        const char* path = NULL;
        if (arg_count == 1 || strcmp(args[1], "~") == 0) {
            path = getenv("HOME"); /* fetch-info.c: getenv used to get $HOME for home directory for cd with no argument or ~ */
        } else {
            path = args[1];
        }
        if (chdir(path) != 0) {
            perror("cd");
        }
        return 1;
    } else if (strcmp(args[0], "pwd") == 0) {
        // Reference: fetch-info.c
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("%s\n", cwd); /* fetch-info.c: getcwd used to print current directory */
        } else {
            perror("pwd");
        }
        return 1;
    } else if (strcmp(args[0], "bglist") == 0) {
        print_bglist();
        return 1;
    } else if (strcmp(args[0], "bg") == 0) {
        // Launch a background job
        if (arg_count < 2) {
            fprintf(stderr, "bg: missing command\n");
            return 1;
        }
        // Build the command line string for bglist
        char command_line[MAX_LINE] = "";
        for (int i = 1; i < arg_count; i++) {
            strcat(command_line, args[i]);
            if (i != arg_count - 1)
                strcat(command_line, " ");
        }
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            perror("pipe");
            return 1;
        }
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            close(pipefd[0]); // Close read end
            signal(SIGINT, SIG_DFL);
            execvp(args[1], &args[1]);
            // If execvp fails then write a byte to the pipe to signal failure
            char fail = 1;
            write(pipefd[1], &fail, 1);
            close(pipefd[1]);
            fprintf(stderr, "%s: No such file or directory\n", args[1]);
            exit(1);
        } else if (pid > 0) {
            // Parent process
            close(pipefd[1]); // Close write end

            fd_set set;
            struct timeval timeout;
            FD_ZERO(&set);
            FD_SET(pipefd[0], &set);
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000; // 0.1''

            int rv = select(pipefd[0] + 1, &set, NULL, NULL, &timeout);
            char fail = 0;
            if (rv > 0) {
                // Child failed to execute
                read(pipefd[0], &fail, 1);
                waitpid(pid, NULL, 0);
            } else {
                // No data, the execution was succesful
                add_bg_process(pid, command_line);
            }
            close(pipefd[0]);
        } else {
            perror("fork");
        }
        return 1;
    }
    return 0;
}

int main() {
    // Ignore SIGINT in the shell
    signal(SIGINT, SIG_IGN);

    char line[MAX_LINE];
    char* args[MAX_LINE / 2 + 1];

    while (1) {
        // Check for finished background jobs
        check_bg_processes();

        // Reference: fetch-info.c
        char hostname[1024];
        char cwd[PATH_MAX];
        char* username = getlogin(); /* fetch-info.c: getlogin used for username */
        gethostname(hostname, sizeof(hostname)); /* fetch-info.c: gethostname used for hostname */
        getcwd(cwd, sizeof(cwd)); /* fetch-info.c: getcwd used for current directory */

        printf("%s@%s: %s > ", username, hostname, cwd);
        fflush(stdout);

        // Read user input
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break; // Ctrl+D or error
        }

        // Skip empty lines
        if (strlen(line) == 1 && line[0] == '\n') {
            continue;
        }

        // Parse input into arguments
        int arg_count = parse_line(line, args);
        if (arg_count == 0) continue;

        // Handle built-in commands
        if (handle_builtin(args, arg_count)) {
            continue; // Built-in command executed
        }

        // Foreground execution using fork/execvp
        /* Reference: inf.c (uses fork and execvp to run external programs) */
        pid_t pid = fork();
        if (pid == 0) {
            // Restore default SIGINT handling in child
            signal(SIGINT, SIG_DFL);
            execvp(args[0], args);
            fprintf(stderr, "%s: No such file or directory\n", args[0]);
            exit(1);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0);
        } else {
            perror("fork");
        }
    }

    return 0;
}
