// SPDX-License-Identifier: GPL-2.0
#ifndef __DAG_BPF_H
#define __DAG_BPF_H

#define DAG_TASK_MAX_NODES	20
#define DAG_TASK_MAX_DEG	20
#define DAG_TASK_MAX_EDGES	1000
typedef unsigned long long u64;
typedef long long s64;
typedef int s32;
typedef unsigned int u32;
typedef unsigned char u8;

struct node_info {
	u32 tid;
	s64 weight;

	s64 prio; /* (internal) */

	u32 nr_ins; // 入力辺の数
	u32 ins[DAG_TASK_MAX_DEG];
	u32 nr_outs; // 出力辺の数
	u32 outs[DAG_TASK_MAX_DEG];
};

struct edge_info {
	u32 from;
	u32 to;
};

struct bpf_dag_task {
	u32 id;
	u32 nr_nodes;
	struct node_info nodes[DAG_TASK_MAX_NODES];
	u32 nr_edges;
	struct edge_info edges[DAG_TASK_MAX_EDGES];
	s64 relative_deadline;
	s64 deadline;
};

#endif
