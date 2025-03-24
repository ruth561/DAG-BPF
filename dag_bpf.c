// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>

#include "dag_bpf.h"
#include "asm-generic/bug.h"

MODULE_AUTHOR("Takumi Jin");
MODULE_DESCRIPTION("A simple implementation of a kernel module using struct_ops");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");

// MARK: my_ops
struct my_ops {
	int (*calculate)(int n);
};

static struct my_ops gops;

static bool my_ops_is_valid_access(int off, int size,
				   enum bpf_access_type type,
				   const struct bpf_prog *prog,
				   struct bpf_insn_access_aux *info)
{
	if (off == 0 && size == sizeof(u64))
		return true;
	return false;
}

static const struct bpf_func_proto *my_ops_get_func_proto(enum bpf_func_id func_id,
							  const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static struct bpf_verifier_ops my_ops_bpf_verifier_ops = {
	.get_func_proto  = my_ops_get_func_proto,
	.is_valid_access = my_ops_is_valid_access,
};

static int bpf_my_ops_init(struct btf *btf)
{
	pr_info("st_ops->init()\n");

	return 0;
}

static int bpf_my_ops_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	pr_info("st_ops->init_member()\n");

	return 0;
}

static int bpf_my_ops_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	pr_info("st_ops->check_member()\n");

	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_my_ops_reg(void *kdata, struct bpf_link *link)
{
	pr_info("st_ops->reg()\n");

	gops = *(struct my_ops *) kdata;
	return 0;
}

static void bpf_my_ops_unreg(void *kdata, struct bpf_link *link)
{
	pr_info("st_ops->unreg()\n");
	gops.calculate = NULL;
}

static int calculate_stub(int n)
{
	return n;
}

static struct my_ops my_ops_stubs = {
	.calculate = calculate_stub,
};

static struct bpf_struct_ops bpf_my_ops = {
	.verifier_ops	= &my_ops_bpf_verifier_ops,
	.init		= bpf_my_ops_init,
	.init_member	= bpf_my_ops_init_member,
	.check_member	= bpf_my_ops_check_member,
	.reg		= bpf_my_ops_reg,
	.unreg		= bpf_my_ops_unreg,
	.name		= "my_ops",
	.owner		= THIS_MODULE,
	.cfi_stubs	= &my_ops_stubs,
};

// MARK: bpf_dag_task
// The maximum of the number of DAG tasks.
#define BPF_DAG_TASK_LIMIT 10

struct bpf_dag_task_manager {
	u32			nr_dag_tasks;
	bool			inuse[BPF_DAG_TASK_LIMIT];
	struct bpf_dag_task	dag_tasks[BPF_DAG_TASK_LIMIT];
};

static struct bpf_dag_task_manager bpf_dag_task_manager;

static void bpf_dag_task_manager_init(void)
{
	pr_info("bpf_dag_task_manager_init");
	bpf_dag_task_manager.nr_dag_tasks = 0;
	for (int i = 0; i < BPF_DAG_TASK_LIMIT; i++) {
		bpf_dag_task_manager.inuse[i] = false;
	}
}

static u32 consume_u32(void **buf)
{
	u32 *ptr = *buf;
	u32 retval = *ptr;
	ptr++;
	*buf = ptr;
	return retval;
}

static u64 consume_u64(void **buf)
{
	u64 *ptr = *buf;
	u64 retval = *ptr;
	ptr++;
	*buf = ptr;
	return retval;
}

static s32 parse_msg(void *msg, u32 size, struct bpf_dag_task *dag_task)
{
	// void *ptr = msg;
	// u64 msg_size = consume_u64(&ptr);
	// u64 nr_nodes, nr_edges;
	// struct dag_task *dag_task = malloc(sizeof(struct dag_task));

	// nr_nodes = consume_u64(&ptr);
	// printf("[DEBUG] nr_nodes=%llu\n", nr_nodes);
	// dag_task->nr_nodes = nr_nodes;
	// for (int i = 0; i < nr_nodes; i++) {
	// 	u32 tid = consume_u32(&ptr);
	// 	u32 weight = consume_u32(&ptr);

	// 	dag_task->nodes[i].tid = tid;
	// 	dag_task->nodes[i].weight = weight;
	// 	dag_task->nodes[i].prio = -1;
	// }

	// nr_edges = consume_u64(&ptr);
	// printf("[DEBUG] nr_edges=%llu\n", nr_edges);
	// dag_task->nr_edges = nr_edges;
	// for (int i = 0; i < nr_edges; i++) {
	// 	/* node(from) --> node(to) */
	// 	u32 from = consume_u32(&ptr);
	// 	u32 to = consume_u32(&ptr);

	// 	dag_task->edges[i].from = from;
	// 	dag_task->edges[i].to = to;

	// 	u32 nr_outs = dag_task->nodes[from].nr_outs;
	// 	dag_task->nodes[from].outs[nr_outs] = to;
	// 	dag_task->nodes[from].nr_outs = nr_outs + 1;

	// 	u32 nr_ins = dag_task->nodes[to].nr_ins;
	// 	dag_task->nodes[to].ins[nr_ins] = from;
	// 	dag_task->nodes[to].nr_ins = nr_ins + 1;
	// }

	// return dag_task;
	return -1;
}

// MARK: kfuncs
__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_dag_task_free(struct bpf_dag_task *dag_task);

/**
 * msg:
 *
 * return value: dag_task id if succeeded, otherwise -1.
 */
__bpf_kfunc struct bpf_dag_task *bpf_dag_task_alloc(u8 *msg, u32 msg__sz)
{
	s32 err;
	struct bpf_dag_task *dag_task = NULL;

	pr_info("bpf_dag_task_alloc\n");

	if (bpf_dag_task_manager.nr_dag_tasks >= BPF_DAG_TASK_LIMIT) {
		pr_err("DAG-BPF: bpf_dag_task_alloc: There is no slots for a DAG task.");
		return NULL;
	}

	for (int i = 0; i < BPF_DAG_TASK_LIMIT; i++) {
		if (!bpf_dag_task_manager.inuse[i]) {
			dag_task = &bpf_dag_task_manager.dag_tasks[i];
			bpf_dag_task_manager.inuse[i] = true;
			bpf_dag_task_manager.nr_dag_tasks++;
			break;
		}
	}

	if (!dag_task) {
		pr_warn("Failed to allocate a DAG task.");
		return NULL;
	}

	err = parse_msg(msg, msg__sz, dag_task);
	if (err) {
		pr_err("Failed to parse message.");
		bpf_dag_task_free(dag_task);
		return NULL;
	}

	return dag_task;
}

__bpf_kfunc void bpf_dag_task_dump(s32 dag_task_id)
{
	struct bpf_dag_task *dag_task;

	pr_info("[*] bpf_graph_dump\n");

	WARN_ON(dag_task_id < 0);
	WARN_ON(BPF_DAG_TASK_LIMIT <= dag_task_id);
	WARN_ON(!bpf_dag_task_manager.inuse[dag_task_id]);

	dag_task = &bpf_dag_task_manager.dag_tasks[dag_task_id];
	
	pr_info("  nr_nodes: %u\n", dag_task->nr_nodes);
	for (int i = 0; i < dag_task->nr_nodes; i++) {
		pr_info("  node[%d]: tid=%d, weight=%d, prio=%d\n",
			i,
			dag_task->nodes[i].tid,
			dag_task->nodes[i].weight,
			dag_task->nodes[i].prio);
	}

	pr_info("  nr_edges: %u\n", dag_task->nr_edges);
	for (int i = 0; i < dag_task->nr_edges; i++) {
		pr_info("  edge[%d]: %d --> %d\n",
			i, dag_task->edges[i].from, dag_task->edges[i].to);
	}

	for (int i = 0; i < dag_task->nr_nodes; i++) {
		for (int j = 0; j < dag_task->nodes[i].nr_outs; j++) {
			pr_info("  outs: %d --> %d\n", i, dag_task->nodes[i].outs[j]);
		}
	}

	for (int i = 0; i < dag_task->nr_nodes; i++) {
		for (int j = 0; j < dag_task->nodes[i].nr_ins; j++) {
			pr_info("  ins: %d --> %d\n", i, dag_task->nodes[i].ins[j]);
		}
	}
}

__bpf_kfunc void bpf_dag_task_free(struct bpf_dag_task *dag_task)
{
	pr_info("[*] bpf_dag_task_free\n");

	for (int i = 0; i < BPF_DAG_TASK_LIMIT; i++) {
		if (&bpf_dag_task_manager.dag_tasks[i] == dag_task) {
			WARN_ON(!bpf_dag_task_manager.inuse[i]);
			bpf_dag_task_manager.inuse[i] = false;
			bpf_dag_task_manager.nr_dag_tasks--;
			return;
		}
	}
	WARN_ON(true); // unreachable
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(my_ops_kfunc_ids)
BTF_ID_FLAGS(func, bpf_dag_task_alloc, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_dag_task_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_dag_task_dump)
BTF_KFUNCS_END(my_ops_kfunc_ids)

static const struct btf_kfunc_id_set my_ops_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &my_ops_kfunc_ids,
};

// MARK: my_ops/ctl
// =============================================================================
// The following implementations are for files in sysfs:my_ops.
// =============================================================================
static int n = 0;

static ssize_t ctl_show(struct kobject *kobj, struct kobj_attribute *attr,
                        char *buf)
{
	int val;

	if (gops.calculate) {
		val = gops.calculate(n);
	} else {
		pr_info("ops.calculate is NULL...\n");
		val = n;
	}

	return sprintf(buf, "ctl_show: val=%d\n", val);
}

static ssize_t ctl_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int ret;

	ret = kstrtoint(buf, 10, &n);
	if (ret < 0) {
		pr_err("failed to convert buf to int\n");
		return ret;
	}

	pr_info("ctl_store: n=%d\n", n);
	return count;
}

// sysfs:my_ops dir
static struct kobject *my_ops_kobj;
// sysfs:my_ops/ctl file
static struct kobj_attribute ctl_attr = __ATTR(ctl, 0660, ctl_show, ctl_store);

// init/exit
static int __init my_ops_init(void)
{
	int err;

	pr_info("my_ops_init\n");

	memset(&gops, 0, sizeof(struct my_ops));

	my_ops_kobj = kobject_create_and_add("my_ops", kernel_kobj);
	if (!my_ops_kobj) {
		pr_err("failed to create and add my_ops kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_file(my_ops_kobj, &ctl_attr.attr);
	if (err) {
		pr_err("failed to create file sysfs:my_ops/ctl\n");
		return err;
	}

	bpf_dag_task_manager_init();

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &my_ops_kfunc_set);
	if (err) {
		pr_err("failed to register kfuncs (%d)\n", err);
		return err;
	}

	err = register_bpf_struct_ops(&bpf_my_ops, my_ops);
	if (err) {
		pr_err("failed to register struct_ops my_ops\n");
		return err;
	}

	return 0;
}

static void __exit my_ops_exit(void)
{
	pr_info("my_ops_exit\n");

	kobject_put(my_ops_kobj);
}

module_init(my_ops_init);
module_exit(my_ops_exit);
