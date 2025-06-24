# Custom-Shell-Implementation-in-C

A basic shell implementation in C that supports foreground and background command execution, directory changes, and background job management.

## 🚀 Features

| Feature         | Description |
|-----------------|-------------|
| **Foreground Execution** | Run commands in the foreground using `fork()` and `execvp()`. |
| **Background Execution** | Run commands in the background with `&` and manage them using `bglist`. |
| **Directory Management** | Use `cd` to change directories and `pwd` to print the current directory. |
| **Job Management** | Track and manage background jobs. |

## ⚙️ Technologies Used

| Technology      | Description |
|-----------------|-------------|
| **C**           | The core programming language used for the shell implementation. |
| **System Calls**| Utilizes system calls like `fork()`, `execvp()`, `waitpid()` for process management. |
| **Signal Handling** | Manages signals like `SIGINT` and `SIGCHLD` for process control. |

## 🌱 Future Improvements

- **Redirect Output**: Capture output to files (e.g., `ls -la > output.txt`).
- **Command History**: Navigate with up/down arrows.
- **Manage Background Jobs**: Commands like `bgkill <pid>`, `bgstop <pid>`, and `bgstart <pid>`.
