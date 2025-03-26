# Directory Overview

### linux-utils

Provides utility functions related to the Linux kernel, such as system call wrappers.

### bpf-comm-api

Defines message APIs used for communication between userspace applications and eBPF programs.

### bpf-comm

Provides utility structures and functions to simplify communication between eBPF and userspace.

### dag-task

Defines data structures related to DAG tasks and includes functions that implement DAG scheduling algorithms.

### dag-bpf

Contains integrated utility functions for interacting with the DAG-BPF kernel module.

### reactor-api

Provides APIs for spawning reactor tasks as nodes in a DAG-task.
For usage examples, refer to the application code in the `app/` directory.
