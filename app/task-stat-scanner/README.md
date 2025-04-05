# Task Stat Scanner

This application reads the BPF map `est_ctx` and
displays its contents interactively. If you want to
inspect a specific thread, you can specify its TID.

Demo:
```
$ cargo build
$ sudo target/debug/task-stat-scanner
No previous history.
tid> 2488371
estimated_exec_time: 387179869
tid> 2488372
estimated_exec_time: 165651448
tid> 2488373
estimated_exec_time: 165441139
tid> 2488374
estimated_exec_time: 332896943
tid> 2488377
estimated_exec_time: 29680318
tid>
CTRL-C
```

NOTE: Before executing it, you must start the scheduler and create the BPF map `est_ctx`.
