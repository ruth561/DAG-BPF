// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bpf.h>

#include "dag_bpf.h"
#include "asm-generic/bug.h"
#include "linux/printk.h"

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

// Returns true if val is in the range [low, high).
// Returns false otherwise.
static bool is_in_range(s32 val, s32 low, s32 high)
{
	return (low < high) && (low <= val && val < high);
}

// Returns true if val is in the range [low, high].
// Returns false otherwise.
static bool is_in_range_eq(s32 val, s32 low, s32 high)
{
	return (low <= high) && (low <= val && val <= high);
}

static u32 cnt_nr_nodes(struct bpf_dag_task *dag_task, s32 tid)
{
	u32 cnt = 0;

	for (int i = 0; i < dag_task->nr_nodes; i++) {
		if (dag_task->nodes[i].tid == tid)
			cnt++;
	}
	return cnt;
}

static u32 cnt_nr_edges(struct bpf_dag_task *dag_task, u32 from, s32 to)
{
	u32 cnt = 0;

	for (int i = 0; i < dag_task->nr_edges; i++) {
		if (dag_task->edges[i].from == from &&
		    dag_task->edges[i].to == to)
			cnt++;
	}
	return cnt;
}

// Returns true if a duplicate is found.
static bool check_duplication_ins_outs(u32 *buf, u32 nr_elems)
{
	bool visited[DAG_TASK_MAX_NODES];

	WARN_ON_ONCE(nr_elems > DAG_TASK_MAX_NODES);

	for (int i = 0; i < DAG_TASK_MAX_NODES; i++) {
		visited[i] = false;
	}

	for (int i = 0; i < nr_elems; i++) {
		if (visited[buf[i]])
			return true;
		visited[buf[i]] = true;
	}

	return false;
}

// debug function
static bool bpf_dag_task_is_well_formed(struct bpf_dag_task *dag_task)
{
	if (!is_in_range(dag_task->id, 0, BPF_DAG_TASK_LIMIT))
		return false;

	if (!is_in_range_eq(dag_task->nr_nodes, 0, DAG_TASK_MAX_NODES))
		return false;

	if (!is_in_range_eq(dag_task->nr_edges, 0, DAG_TASK_MAX_EDGES))
		return false;

	for (int i = 0; i < dag_task->nr_nodes; i++) {
		struct node_info *node = &dag_task->nodes[i];

		if (!is_in_range_eq(node->nr_ins, 0, DAG_TASK_MAX_DEG))
			return false;
		
		if (!is_in_range_eq(node->nr_outs, 0, DAG_TASK_MAX_DEG))
			return false;

		if (cnt_nr_nodes(dag_task, node->tid) != 1) {
			pr_err("DAG task has two or more node that share the same tid (=%d)", node->tid);
			return false;
		}

		if (check_duplication_ins_outs(node->ins, node->nr_ins)) {
			pr_err("node->ins has a duplicate");
			return false;
		}

		if (check_duplication_ins_outs(node->outs, node->nr_outs)) {
			pr_err("node->outs has a duplicate");
			return false;
		}

		for (int j = 0; j < node->nr_ins; j++) {
			if (!is_in_range(node->ins[j], 0, dag_task->nr_nodes)) {
				pr_err("node->ins[%d](=%d) is out of range.", j, node->ins[j]);
				return false;
			}
		}

		for (int j = 0; j < node->nr_outs; j++) {
			if (!is_in_range(node->outs[j], 0, dag_task->nr_nodes)) {
				pr_err("node->outs[%d](=%d) is out of range.", j, node->outs[j]);
				return false;
			}
		}
	}

	for (int i = 0; i < dag_task->nr_edges; i++) {
		struct edge_info *edge = &dag_task->edges[i];

		if (!is_in_range(edge->from, 0, dag_task->nr_nodes))
			return false;
	
		if (!is_in_range(edge->to, 0, dag_task->nr_nodes))
			return false;

		if (cnt_nr_edges(dag_task, edge->from, edge->to) != 1) {
			pr_err("DAG task has a duplicate edge (%d -> %d)", edge->from , edge->to);
			return false;
		}

		if (edge->from == edge->to) {
			pr_err("DAG task has a self-loop (%d -> %d)", edge->from, edge->to);
			return false;
		}

		if (edge->from > edge->to) {
			pr_err("DAG task isn't sorted in topological order (%d -> %d)", edge->from, edge->to);
			return false;
		}
	}
	
	return true;
}

/*
 * Data structure for managing all DAG tasks.
 *
 * TODO: Protect with mutual exclusion
 */
struct bpf_dag_task_manager {
	u32			nr_dag_tasks;
	bool			inuse[BPF_DAG_TASK_LIMIT];
	struct bpf_dag_task	dag_tasks[BPF_DAG_TASK_LIMIT];
};

static struct bpf_dag_task_manager bpf_dag_task_manager;

static bool bpf_dag_task_manager_is_well_formed(void)
{
	u32 inuse_cnt;

	if (!(0 <= bpf_dag_task_manager.nr_dag_tasks &&
	      bpf_dag_task_manager.nr_dag_tasks <= BPF_DAG_TASK_LIMIT)) {
		return false;
	}

	inuse_cnt = 0;
	for (int i = 0; i < BPF_DAG_TASK_LIMIT; i++) {
		if (bpf_dag_task_manager.inuse[i]) {
			inuse_cnt++;
			if (!bpf_dag_task_is_well_formed(&bpf_dag_task_manager.dag_tasks[i]))
				return false;
		}
	}

	return bpf_dag_task_manager.nr_dag_tasks == inuse_cnt;
}

static __init void bpf_dag_task_manager_init(void)
{
	pr_info("[*] bpf_dag_task_manager_init");
	bpf_dag_task_manager.nr_dag_tasks = 0;
	for (int i = 0; i < BPF_DAG_TASK_LIMIT; i++) {
		bpf_dag_task_manager.inuse[i] = false;
		bpf_dag_task_manager.dag_tasks[i].id = i;
	}

	WARN_ON_ONCE(!bpf_dag_task_manager_is_well_formed()); // TODO: check only when debug mode
}

// MARK: bpf_dag_task API
static s32 __bpf_dag_task_add_node(struct bpf_dag_task *dag_task, u32 tid, s64 weight)
{
	s32 node_id;

	if (dag_task->nr_nodes == DAG_TASK_MAX_NODES) {
		pr_warn("bpf_dag_task_add_node: The maximum number of DAG nodes (%d) has been reached.", DAG_TASK_MAX_NODES);
		return -1;
	}

	if (cnt_nr_nodes(dag_task, tid) > 0) {
		pr_warn("bpf_dag_task_add_node: The node (tid=%d) already exists.", tid);
		return -1;
	}

	node_id = dag_task->nr_nodes;
	dag_task->nr_nodes++;
	dag_task->nodes[node_id].tid = tid;
	dag_task->nodes[node_id].weight = weight;
	dag_task->nodes[node_id].nr_ins = 0;
	dag_task->nodes[node_id].nr_outs = 0;

	WARN_ON_ONCE(!bpf_dag_task_manager_is_well_formed()); // TODO: check only when debug mode

	return node_id;
}

/*
 * If there is no node whose tid is @tid, then return -1.
 * If the node is found, return the node id.
 */
static s32 get_node_id(struct bpf_dag_task *dag_task, s32 tid)
{
	for (int i = 0; i < dag_task->nr_nodes; i++) {
		if (dag_task->nodes[i].tid == tid)
			return i;
	}

	return -1;
}

static s32 __bpf_dag_task_add_edge(struct bpf_dag_task *dag_task, u32 from_tid, u32 to_tid)
{
	s32 edge_id, from, to;

	from = get_node_id(dag_task, from_tid);
	to = get_node_id(dag_task, to_tid);

	if (from < 0 || to < 0) {
		pr_err("There isn't a corresponding node (from_tid=%d, to_tid=%d)", from_tid, to_tid);
		return -1;
	}

	// from and to are valid!
	WARN_ON_ONCE(!(0 <= from && from < dag_task->nr_nodes));
	WARN_ON_ONCE(!(0 <= to && to < dag_task->nr_nodes));

	if (dag_task->nr_edges == DAG_TASK_MAX_EDGES) {
		pr_warn("The maximum number of DAG edges (%d) has been reached.", DAG_TASK_MAX_EDGES);
		return -1;
	}

	if (cnt_nr_edges(dag_task, from, to) > 0) {
		pr_warn("Edge (%d -> %d) already exists in DAG task (%d)",
			from, to, dag_task->id);
		return -1;
	}

	if (from == to) {
		pr_warn("Self-loop (%d -> %d) is not allowed.", from, to);
		return -1;
	}

	if (from > to) {
		pr_warn("Edge (%d -> %d) violates topological order", from, to);
		return -1;
	}

	edge_id = dag_task->nr_edges;
	dag_task->nr_edges++;

	dag_task->edges[edge_id].from = from;
	dag_task->edges[edge_id].to = to;

	s32 nr_outs = dag_task->nodes[from].nr_outs;
	dag_task->nodes[from].outs[nr_outs] = to;
	dag_task->nodes[from].nr_outs++;

	s32 nr_ins = dag_task->nodes[to].nr_ins;
	dag_task->nodes[to].ins[nr_ins] = from;
	dag_task->nodes[to].nr_ins++;

	WARN_ON_ONCE(!bpf_dag_task_manager_is_well_formed()); // TODO: check only when debug mode

	return edge_id;
}

static s32 bpf_dag_task_init(struct bpf_dag_task *dag_task, u32 src_node_tid, s64 src_node_weight)
{
	s32 ret;

	dag_task->nr_nodes = 0;
	dag_task->nr_edges = 0;

	/*
	 * Adds a source node. The node id of the source node is always 0.
	 */
	ret = __bpf_dag_task_add_node(dag_task, src_node_tid, src_node_weight);
	WARN_ON(ret != 0);
	WARN_ON(dag_task->nr_nodes != 1);
	WARN_ON(dag_task->nr_edges != 0);

	WARN_ON_ONCE(!bpf_dag_task_manager_is_well_formed()); // TODO: check only when debug mode

	return 0;
}

// MARK: kfuncs
__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_dag_task_free(struct bpf_dag_task *dag_task);

/**
 * msg:
 *
 * return value: dag_task id if succeeded, otherwise -1.
 */
__bpf_kfunc struct bpf_dag_task *bpf_dag_task_alloc(u32 src_node_tid,
						    s64 src_node_weight)
{
	s32 err;
	struct bpf_dag_task *dag_task = NULL;

	pr_info("[*] bpf_dag_task_alloc (src_node_tid=%d, src_node_weight=%lld)\n",
		src_node_tid, src_node_weight);

	if (bpf_dag_task_manager.nr_dag_tasks >= BPF_DAG_TASK_LIMIT) {
		pr_err("There is no slots for a DAG task.");
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

	err = bpf_dag_task_init(dag_task, src_node_tid, src_node_weight);
	if (err) {
		pr_err("Failed to init a DAG task.");
		bpf_dag_task_free(dag_task);
		return NULL;
	}

	return dag_task;
}

__bpf_kfunc void bpf_dag_task_dump(struct bpf_dag_task *dag_task)
{
	pr_info("[*] bpf_graph_dump\n");

	pr_info("  id: %d\n", dag_task->id);

	pr_info("  nr_nodes: %u\n", dag_task->nr_nodes);
	for (int i = 0; i < dag_task->nr_nodes; i++) {
		pr_info("  node[%d]: tid=%d, weight=%lld, prio=%lld\n",
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
			pr_info("  ins: %d <-- %d\n", i, dag_task->nodes[i].ins[j]);
		}
	}
}

/**
 * @dag_task: referenced kptr
 * @tid: Thread id of the node.
 * @weight: The weight of the node.
 *
 * @retval: -1 if it was failed, otherwise returns node_id.
 */
__bpf_kfunc s32 bpf_dag_task_add_node(struct bpf_dag_task *dag_task,
				      u32 tid, s64 weight)
{
	return __bpf_dag_task_add_node(dag_task, tid, weight);
}

/**
 * @dag_task: referenced kptr
 * @from:
 * @to:
 *
 * @retval: -1 if it was failed, otherwise returns edge_id.
 */
__bpf_kfunc s32 bpf_dag_task_add_edge(struct bpf_dag_task *dag_task, u32 from, u32 to)
{
	return __bpf_dag_task_add_edge(dag_task, from, to);
}

__bpf_kfunc s64 bpf_dag_task_get_weight(struct bpf_dag_task *dag_task, u32 node_id)
{
	if (node_id < dag_task->nr_nodes) {
		return dag_task->nodes[node_id].weight;
	} else {
		return -1;
	}
}

__bpf_kfunc s32 bpf_dag_task_set_weight(struct bpf_dag_task *dag_task, u32 node_id, s64 weight)
{
	if (node_id < dag_task->nr_nodes) {
		dag_task->nodes[node_id].weight = weight;
		return 0;
	} else {
		return -1;
	}
}

__bpf_kfunc s64 bpf_dag_task_get_prio(struct bpf_dag_task *dag_task, u32 node_id)
{
	if (node_id < dag_task->nr_nodes) {
		return dag_task->nodes[node_id].prio;
	} else {
		return -1;
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

__bpf_kfunc void bpf_dag_task_culc_HELT_prio(struct bpf_dag_task *dag_task)
{
	if (dag_task->nr_nodes == 0)
		return;

	for (s32 i = dag_task->nr_nodes - 1; i >= 0; i--) {
		struct node_info *curr_node = &dag_task->nodes[i];

		if (curr_node->nr_outs == 0) {
			/*
			 * node->prio means the rank defined in HELT algorithm.
			 */
			curr_node->prio = curr_node->weight;
		} else {
			s64 tail_weight_max = 0;
			for (int j = 0; j < curr_node->nr_outs; j++) {
				int node_id = curr_node->outs[j];
				struct node_info *node = &dag_task->nodes[node_id];
				s64 tail_weight_curr = node->prio;
				tail_weight_max = tail_weight_max < tail_weight_curr ? tail_weight_curr : tail_weight_max;
			}
			curr_node->prio = curr_node->weight + tail_weight_max;
		}
	}

	// DEBUG
	// TODO: remove here
	pr_info("[*] bpf_dag_task_culc_HELT_prio");
	bpf_dag_task_dump(dag_task);
}

__bpf_kfunc void bpf_dag_task_culc_HLBS_prio(struct bpf_dag_task *dag_task, s64 now,
					     s64 relative_deadline)
{
	s64 deadline = now + relative_deadline;

	if (dag_task->nr_nodes == 0)
		return;

	for (s32 i = dag_task->nr_nodes - 1; i >= 0; i--) {
		struct node_info *curr_node = &dag_task->nodes[i];

		if (curr_node->nr_outs == 0) {
			/*
			 * node->prio indicates the deadline by which the node must begin execution.
			 */
			curr_node->prio = deadline - curr_node->weight;
		} else {
			s64 tail_deadline_min = S64_MAX;
			for (int j = 0; j < curr_node->nr_outs; j++) {
				int node_id = curr_node->outs[j];
				struct node_info *node = &dag_task->nodes[node_id];
				s64 tail_deadline_curr = node->prio;
				tail_deadline_min = tail_deadline_min < tail_deadline_curr
					? tail_deadline_min : tail_deadline_curr;
			}
			curr_node->prio = tail_deadline_min - curr_node->weight;
		}
	}

	// DEBUG
	// TODO: remove here
	pr_info("[*] bpf_dag_task_culc_HLBS_prio");
	bpf_dag_task_dump(dag_task);
}

__bpf_kfunc void bpf_dag_task_release_dtor(void *dag_task)
{
	pr_info("[*] bpf_dag_task_release_dtor\n");

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
CFI_NOSEAL(bpf_dag_task_release_dtor);

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(my_ops_kfunc_ids)
BTF_ID_FLAGS(func, bpf_dag_task_alloc, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_dag_task_free, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_dag_task_add_node, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_add_edge, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_get_weight, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_set_weight, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_get_prio, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_culc_HELT_prio, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_culc_HLBS_prio, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_dag_task_dump)
BTF_KFUNCS_END(my_ops_kfunc_ids)

BTF_ID_LIST(dag_task_dtor_ids)
BTF_ID(struct, bpf_dag_task)
BTF_ID(func, bpf_dag_task_release_dtor)

static const struct btf_kfunc_id_set my_ops_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &my_ops_kfunc_ids,
};

static int __init dag_task_kfunc_init(void)
{
	int err;
	const struct btf_id_dtor_kfunc dag_task_dtors[] = {
		{
			.btf_id	      = dag_task_dtor_ids[0],
			.kfunc_btf_id = dag_task_dtor_ids[1]
		},
	};

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &my_ops_kfunc_set);
	if (err) {
		pr_err("failed to register kfuncs (%d)\n", err);
		return err;
	}

	err = register_btf_id_dtor_kfuncs(dag_task_dtors,
					  ARRAY_SIZE(dag_task_dtors),
					  THIS_MODULE);
	if (err) {
		pr_err("Failed to register a destructor to BTF ID of bpf_dag_task (%d)\n", err);
		return err;
	}
	return 0;
}

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

	err = dag_task_kfunc_init();
	if (err) {
		pr_err("Failed to init kfunc (%d)", err);
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
