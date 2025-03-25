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

#define BPF_DAG_TASK_LIMIT 10

struct dag_tasks_map_value {
	struct bpf_dag_task __kptr *dag_task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, BPF_DAG_TASK_LIMIT);
	__type(key, s32);
	__type(value, struct dag_tasks_map_value);
} dag_tasks SEC(".maps");

#define USER_RINGBUF_SIZE (4096 * 4096)
// Message queue from USER to BPF
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, USER_RINGBUF_SIZE);
} urb SEC(".maps");

#define MSG_GBUF_SIZE	100 * 1000
static u32 msg_gbuf[MSG_GBUF_SIZE];

static long handle_new_dag_task(struct bpf_dag_msg_new_task_payload *payload)
{
	s32 key;
	void *value;
	struct bpf_dag_task *dag_task, *old;
	long status;
	struct dag_tasks_map_value local, *v;

	dag_task = bpf_dag_task_alloc(payload->src_node_tid, payload->src_node_weight);
	if (!dag_task) {
		bpf_printk("Failed to newly allocate a DAG task (src_node_tid=%d).", payload->src_node_tid);
		return 1;
	}

	bpf_printk("Successfully allocates a DAG-task! tid=%d, id=%d", payload->src_node_tid, dag_task->id);

	key = payload->src_node_tid;
	local.dag_task = NULL;
	status = bpf_map_update_elem(&dag_tasks, &key, &local, 0);
	if (status) {
		bpf_printk("Failed to update dag_tasks's elem with NULL value");
		bpf_dag_task_free(dag_task);
		return 1;
	}

	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("Failed to lookup dag_tasks's elem");
		bpf_dag_task_free(dag_task);
		return 1;
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return 0;
}

static inline long handle_add_node(struct bpf_dag_msg_add_node_payload *payload)
{
	s32 key, node_id;
	void *value;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	key = payload->dag_task_id;
	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("There is no entry in dag_tasks with key=%d", key);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("dag_tasks[%d]->dag_task is NULL", key);
		return -1;
	}

	node_id = bpf_dag_task_add_node(dag_task, payload->tid, payload->weight);

	bpf_dag_task_dump(dag_task);

	if (node_id >= 0) {
		bpf_printk("Successfully add a node (tid=%d, node_id=%d) to a DAG-task (id=%d)",
			payload->tid, node_id, dag_task->id);
	} else {
		bpf_printk("Failed to add a node (tid=%d) to a DAG-task (id=%d)",
			payload->tid, dag_task->id);
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return 0;
}

static inline long handle_add_edge(struct bpf_dag_msg_add_edge_payload *payload)
{
	s32 key, edge_id;
	void *value;
	struct bpf_dag_task *dag_task, *old;
	struct dag_tasks_map_value *v;

	key = payload->dag_task_id;
	v = bpf_map_lookup_elem(&dag_tasks, &key);
	if (!v) {
		bpf_printk("There is no entry in dag_tasks with key=%d", key);
		return -1;
	}

	dag_task = bpf_kptr_xchg(&v->dag_task, NULL); // acquire ownership
	if (!dag_task) {
		bpf_printk("dag_tasks[%d]->dag_task is NULL", key);
		return -1;
	}

	edge_id = bpf_dag_task_add_edge(dag_task, payload->from_tid, payload->to_tid);

	bpf_dag_task_dump(dag_task);

	if (edge_id >= 0) {
		bpf_printk("Successfully add a edge (%d -> %d, edge_id=%d) to a DAG-task (id=%d)",
			payload->from_tid, payload->to_tid, edge_id, dag_task->id);
	} else {
		bpf_printk("Failed to add a edge (%d -> %d) to a DAG-task (id=%d)",
			payload->from_tid, payload->to_tid, dag_task->id);
	}

	old = bpf_kptr_xchg(&v->dag_task, dag_task);

	if (old)
		bpf_dag_task_free(old);

	return 0;
}

static long user_ringbuf_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	long err;
	enum bpf_dag_msg_type type;
	struct bpf_dag_task *dag_task;

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
		
		err = handle_new_dag_task(&payload);
		if (err) {
			bpf_printk("Failed to handle a new dag task message");
			return 1;
		}

	} else if (type == BPF_DAG_MSG_ADD_NODE) {
		struct bpf_dag_msg_add_node_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message add node.");
			return 1; // stop continuing
		}
		
		err = handle_add_node(&payload);
		if (err) {
			bpf_printk("Failed to handle add_node message");
			return 1;
		}

	} else if (type == BPF_DAG_MSG_ADD_EDGE) {
		struct bpf_dag_msg_add_edge_payload payload;

		err = bpf_dynptr_read(&payload, sizeof(payload), dynptr, sizeof(type), 0);
		if (err) {
			bpf_printk("Failed to drain message add edge.");
			return 1; // stop continuing
		}
		
		err = handle_add_edge(&payload);
		if (err) {
			bpf_printk("Failed to handle add_edge message");
			return 1;
		}

	} else {
		bpf_printk("[ WARN ] Unknown message type: BPF_DAG_MSG_?=%d", type);
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
