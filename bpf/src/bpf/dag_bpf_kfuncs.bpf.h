#ifndef __MY_OPS_KFUNCS_H
#define __MY_OPS_KFUNCS_H


#include "dag_bpf.h"

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

extern struct bpf_dag_task *bpf_dag_task_alloc(u32 src_node_tid, u32 src_node_weight) __weak __ksym;
extern void bpf_dag_task_dump(s32 dag_task_id) __weak __ksym;
extern void bpf_dag_task_free(struct bpf_dag_task *dag_task) __weak __ksym;

enum bpf_dag_msg_type {
	BPF_DAG_MSG_NEW_TASK,	// 新しいDAGタスクが作成されたことを伝えるメッセージ（DAGタスクの識別番号はsrc nodeのtid）
};

struct bpf_dag_msg_new_task_payload {
	u32 src_node_tid;
	u32 src_node_weight;
};

#endif /* __MY_OPS_KFUNCS_H */
