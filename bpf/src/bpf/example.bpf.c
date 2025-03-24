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
	int err;
	s32 i;
	u64 msg_len;
	u32 *msg_data;

	err = bpf_dynptr_read(&msg_len, sizeof(msg_len), dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to drain message.");
		return 1; // stop continuing
	}

	msg_len /= 4;
	if (4 * msg_len > MSG_GBUF_SIZE) {
		bpf_printk("Message is too large (size=%d)", msg_len);
		return 1;
	}

	err = bpf_dynptr_read(&msg_gbuf[0], msg_len, dynptr, 0, 0);
	if (err) {
		bpf_printk("Failed to drain message at offset(%d)", 4 * i);
		return 1; // stop continuing
	}

	// bpf_for(i, 0, msg_len) {
	// 	u32 offset = 4 * i;
	// 	if (offset >= MSG_GBUF_SIZE - 4) {
	// 		return 1;
	// 	}
	// 	err = bpf_dynptr_read(&msg_gbuf[i], sizeof(u32), dynptr, 4 * i, 0);
	// 	if (err) {
	// 		bpf_printk("Failed to drain message at offset(%d)", 4 * i);
	// 		return 1; // stop continuing
	// 	}
	// }

	// bpf_dynptr_data(dynptr, offset, len) <-- len must be a constant!
	// msg_data = bpf_dynptr_data(dynptr, 0, 4);
	// if (!msg_data) {
	// 	bpf_printk("bpf_dynptr_data failed");
	// 	return 1;
	// }

	bpf_printk("[DEBUG] msg_len=%d", msg_len);
	bpf_printk("[DEBUG] msg_body[0..31]=%d", *msg_data);

	return 1;
}

SEC("struct_ops/my_ops_calculate")
u64 BPF_PROG(my_ops_calculate, u64 n)
{
	struct bpf_dag_task *dag_task;
	s32 err;
	u8 buf[100];

	bpf_user_ringbuf_drain(&urb, user_ringbuf_callback, NULL, 0);

	dag_task = bpf_dag_task_alloc(buf, 100);
	if (!dag_task) {
		bpf_printk("Failed to allocate a DAG task.");
		return -1;
	}

	bpf_dag_task_dump(dag_task->id);

	bpf_dag_task_free(dag_task);

	return err;
}

SEC(".struct_ops.link")
struct my_ops my_ops_sample = {
	.calculate = (void *) my_ops_calculate,
};
