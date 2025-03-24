// SPDX-License-Identifier: GPL-2.0-only
#include "dag_bpf.h"
#include "dag_bpf_kfuncs.bpf.h"
#include <bpf/bpf_tracing.h>
char LICENSE[] SEC("license") = "GPL";

u64 cnt = 0;

#define assert(cond)						\
	do {							\
		if (!(cond)) {					\
			bpf_printk("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
		}						\
	} while (0)

#define assert_ret(cond)					\
	do {							\
		if (!(cond)) {					\
			bpf_printk("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
			return;					\
		}						\
	} while (0)

#define assert_ret_err(cond)					\
	do {							\
		if (!(cond)) {					\
			bpf_printk("%s:%d assertion failed",	\
				__FILE__, __LINE__);		\
			return -1;				\
		}						\
	} while (0)

#define USER_RINGBUF_SIZE (4096 * 4096)
// Message queue from USER to BPF
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, USER_RINGBUF_SIZE);
} urb SEC(".maps");

#define MSG_GBUF_SIZE	100 * 1000
static u32 msg_gbuf[MSG_GBUF_SIZE];

static long user_ringbuf_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	long err;
	enum bpf_dag_msg_type type;
	struct bpf_dag_task *dag_task;

	bpf_printk("user_ring_callback is called!");

	err = bpf_dynptr_read(&type, sizeof(type), dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to drain message type.");
		return 1; // stop continuing
	}

	if (type == BPF_DAG_MSG_NEW_TASK) {
		struct bpf_dag_msg_new_task_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message new task type.");
			return 1; // stop continuing
		}
		
		dag_task = bpf_dag_task_alloc(payload.src_node_tid, payload.src_node_weight);
		if (!dag_task) {
			bpf_printk("Failed to newly allocate a DAG task (src_node_tid=%d).", payload.src_node_tid);
			return 1;
		}

		bpf_dag_task_dump(dag_task->id);

		bpf_dag_task_free(dag_task);
	} else {
		bpf_printk("[ WARN ] Unknown message type: BPF_DAG_MSG_???=%d", type);
	}

	return 0;
}

SEC("struct_ops/my_ops_calculate")
u64 BPF_PROG(my_ops_calculate, u64 n)
{
	struct bpf_dag_task *dag_task;
	s32 err;
	u8 buf[100];

	bpf_user_ringbuf_drain(&urb, user_ringbuf_callback, NULL, 0);

	return err;
}

SEC(".struct_ops.link")
struct my_ops my_ops_sample = {
	.calculate = (void *) my_ops_calculate,
};
