#ifndef __MY_OPS_KFUNCS_H
#define __MY_OPS_KFUNCS_H


#include "dag_bpf.h"

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

extern struct bpf_dag_task *bpf_dag_task_alloc(u8 *msg, u32 size) __weak __ksym;
extern void bpf_dag_task_dump(s32 dag_task_id) __weak __ksym;
extern void bpf_dag_task_free(struct bpf_dag_task *dag_task) __weak __ksym;

#endif /* __MY_OPS_KFUNCS_H */
