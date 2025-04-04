use std::collections::HashSet;
use std::collections::HashMap;
use std::borrow::Cow;

use petgraph::algo::toposort;
use petgraph::algo::DfsSpace;
use petgraph::graph::DiGraph;

use linux_utils::LinuxTid;

// similar to a thread id
pub type Reactor = LinuxTid;
pub type TaskWeight = i64;

#[derive(Debug, Clone)]
pub struct TaskInfo {
	weight: i64,
	relative_deadline: i64,
	period: i64,
}

#[derive(Debug)]
pub struct DagTask {
	pub id: usize,
	pub nr_nodes: usize,
	pub node_to_reactor: Vec<Reactor>,
	pub node_to_weight: Vec<TaskWeight>,
	pub reactor_to_node: HashMap<Reactor, usize>,
	pub edges: Vec<Vec<usize>>,
	pub relative_deadline: i64,
	pub period: i64,
}

impl DagTask {
	pub fn new(id: usize) -> Self {
		Self {
			id,
			nr_nodes: 0,
			node_to_reactor: vec![],
			node_to_weight: vec![],
			reactor_to_node: HashMap::new(),
			edges: vec![],
			relative_deadline: -1,
			period: -1,
		}
	}
}

#[derive(Debug)]
pub struct TaskGraph {
	pub nr_tasks: usize,
	pub task_to_reactor: Vec<Reactor>, // task_to_reactor[i]: the i-th reactor id
	pub reactor_to_task: HashMap<Reactor, usize>,
	pub task_info: Vec<TaskInfo>,
	pub edges: Vec<Vec<usize>>,
}

impl TaskGraph {
	pub fn new() -> Self {
		Self {
			nr_tasks: 0,
			task_to_reactor: vec![],
			reactor_to_task: HashMap::new(),
			task_info: vec![],
			edges: vec![],
		}
	}

	// Takes a src node as an argument, returns a set of nodes
	// that is reachable from `src`.
	pub fn get_reachable_nodes(&self, src: usize) -> HashSet<usize>
	{
		let mut ans = HashSet::new();
		ans.insert(src);
		let mut visited = vec![false; self.nr_tasks];
		visited[src] = true;
		let mut q = vec![src];
		while let Some(u) = q.pop() {
			for v in &self.edges[u] {
				if visited[*v] {
					continue;
				}

				visited[*v] = true;
				ans.insert(*v);
				q.push(*v);
			}
		}
		ans
	}

	// Splits `self` into connected DAG task graphs.
	// Returns a vector of connected DAG task graphs if `self` is a DAG.
	// Othrewise, returns `None`.
	pub fn to_dag_tasks(&self) -> Option<Vec<DagTask>> {
		let mut g = DiGraph::new();

		let mut nodes = vec![];
		for _ in 0..self.nr_tasks {
			nodes.push(g.add_node(0));
		}

		for src in 0..self.nr_tasks {
			for dst in &self.edges[src] {
				let src_node = nodes[src];
				let dst_node = nodes[*dst];
				g.add_edge(src_node, dst_node, 0);
			}
		}

		let mut space = DfsSpace::new(&g);
		let result = toposort(&g, Some(&mut space));
		if result.is_err() {
			return None;
		}

		// the list of node sorted in topological order
		let nodes: Vec<_> = result.unwrap().iter().map(|x| (x.index())).collect();

		let mut dag_task_id = 0;
		let mut dag_tasks = vec![];
		let mut visited = vec![false; nodes.len()];
		for src in &nodes {
			if visited[*src] {
				continue;
			}

			// start building a DAG task whose src node is `src`!
			let reachable_nodes = self.get_reachable_nodes(*src); // nodes is sorted in topological order
			for node in &reachable_nodes {
				visited[*node] = true;
			}

			// traverse in topological order
			// TODO: more efficient
			let mut node_to_reactor = vec![];
			let mut node_to_weight = vec![];
			let mut reactor_to_node = HashMap::new();
			let mut period = 0;
			let mut relative_deadline = i64::MAX;
			for node in &nodes {
				if reachable_nodes.contains(node) {
					let reactor = self.task_to_reactor[*node];
					let info = &self.task_info[*node];
					node_to_reactor.push(reactor.clone());
					node_to_weight.push(info.weight.clone());
					reactor_to_node.insert(reactor, node_to_reactor.len() - 1);

					// periodは最大のものを選ぶ
					// relative_deadlineは最小のものを選ぶ
					// TODO:
					// いずれにせよ、srcノードが複数ある場合の対処であり、
					// 必要になったら、ここの実装はしっかりと考える
					if info.period > period {
						period = info.period
					}
					if 0 < info.relative_deadline && info.relative_deadline < relative_deadline {
						relative_deadline = info.relative_deadline;
					}
				}
			}

			// build a DAG-task up!
			let mut dag_task = DagTask {
				id: dag_task_id,
				nr_nodes: reachable_nodes.len(),
				node_to_reactor,
				node_to_weight,
				reactor_to_node,
				edges: vec![vec![]; reachable_nodes.len()],
				relative_deadline,
				period,
			};

			for src in &reachable_nodes {
				for dst in &self.edges[*src] {
					let src_reactor = self.task_to_reactor[*src];
					let dst_reactor = self.task_to_reactor[*dst];
					let src_node = dag_task.reactor_to_node.get(&src_reactor).unwrap();
					let dst_node = dag_task.reactor_to_node.get(&dst_reactor).unwrap();
					dag_task.edges[*src_node].push(*dst_node);
				}
			}

			dag_tasks.push(dag_task);
			dag_task_id += 1;
		}

		Some(dag_tasks)
	}
}

/// This strucure is for building a TaskGraph instance.
#[derive(Debug)]
pub struct TaskGraphBuilder {
	pub reactors: HashSet<Reactor>,
	pub reactor_info: HashMap<Reactor, TaskInfo>,
	pub subs: HashMap<Cow<'static, str>, HashSet<Reactor>>, // topic name -> [reactor id]
	pub pubs: HashMap<Cow<'static, str>, HashSet<Reactor>>, // topic name -> [reactor id]
	pub topics: HashSet<Cow<'static, str>>,
}

impl TaskGraphBuilder {
	pub fn new() -> Self {
		Self {
			reactors: HashSet::new(),
			reactor_info: HashMap::new(),
			subs: HashMap::new(),
			pubs: HashMap::new(),
			topics: HashSet::new(),
		}
	}

	/// @reactor: Reactor id
	pub fn reg_reactor(
		&mut self,
		reactor: Reactor,
		subs: Vec<Cow<'static, str>>,
		pubs: Vec<Cow<'static, str>>,
		weight: TaskWeight,
		period: i64,
		relative_deadline: i64,
	) {
		assert!(!self.reactors.contains(&reactor));

		for s in &subs {
			if let Some(reactors) = self.subs.get_mut(s) {
				reactors.insert(reactor);
			} else {
				let mut reactors = HashSet::new();
				reactors.insert(reactor);
				self.subs.insert(s.clone(), reactors);
			}

			self.topics.insert(s.clone());
		}

		for p in &pubs {
			if let Some(reactors) = self.pubs.get_mut(p) {
				reactors.insert(reactor);
			} else {
				let mut reactors = HashSet::new();
				reactors.insert(reactor);
				self.pubs.insert(p.clone(), reactors);
			}

			self.topics.insert(p.clone());
		}

		self.reactors.insert(reactor);
		self.reactor_info.insert(reactor, TaskInfo { weight, relative_deadline, period });
	}

	pub fn build(&self) -> TaskGraph {
		let nr_tasks = self.reactors.len();
		let mut task_to_reactor = vec![];
		let mut task_info = vec![];
		let mut reactor_to_task = HashMap::new();
		let mut edges = vec![vec![]; nr_tasks];

		let mut reactors: Vec<_> = self.reactors.iter().collect();
		reactors.sort();
		for (i, reactor) in reactors.iter().enumerate() {
			task_to_reactor.push(**reactor);
			task_info.push(self.reactor_info.get(reactor).unwrap().clone());
			reactor_to_task.insert(**reactor, i);
		}

		for topic in &self.topics {
			let subs = match self.subs.get(topic) {
				Some(subs) => subs,
				_ => continue,
			};
			let pubs = match self.pubs.get(topic) {
				Some(pubs) => pubs,
				_ => continue,
			};

			for src in pubs {
				for dst in subs {
					let src = reactor_to_task[src];
					let dst = reactor_to_task[dst];
					edges[src].push(dst);
				}
			}
		}

		TaskGraph {
			nr_tasks,
			task_to_reactor,
			task_info,
			reactor_to_task,
			edges,
		}

	}
}

///                                         +--[topic1]---> (reactor2) ---[topic3]--+
///                                         |                                       |
/// (reactor0) ---[topic0]---> (reactor1) --+                                       +---> (reactor4)
///                                         |                                       |
///                                         +--[topic2]---> (reactor3) ---[topic4]--+
#[test]
fn test_dag_tasks_0()
{
	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(0, vec![], vec![Cow::from("topic0")], 1, 10, 10);
	builder.reg_reactor(1, vec![Cow::from("topic0")], vec![Cow::from("topic1"), Cow::from("topic2")], 1, -1, -1);
	builder.reg_reactor(2, vec![Cow::from("topic1")], vec![Cow::from("topic3")], 1, -1, -1);
	builder.reg_reactor(3, vec![Cow::from("topic2")], vec![Cow::from("topic4")], 1, -1, -1);
	builder.reg_reactor(4, vec![Cow::from("topic3"), Cow::from("topic4")], vec![], 1, -1, -1);

	let task_graph = builder.build();
	let dag_tasks = task_graph.to_dag_tasks().unwrap();
	assert_eq!(dag_tasks.len(), 1);
	assert!(dag_tasks[0].node_to_reactor == [0, 1, 2, 3, 4] ||
		dag_tasks[0].node_to_reactor == [0, 1, 3, 2, 4]);
	
	assert!(dag_tasks[0].relative_deadline == 10);
	assert!(dag_tasks[0].period == 10);
}

/// This test case is the same as the above one, except for the rector numbers.
#[test]
fn test_dag_tasks_1()
{
	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(4, vec![], vec![Cow::from("topic0")], 1, 10, 10);
	builder.reg_reactor(3, vec![Cow::from("topic0")], vec![Cow::from("topic1"), Cow::from("topic2")], 1, -1, -1);
	builder.reg_reactor(0, vec![Cow::from("topic1")], vec![Cow::from("topic3")], 1, -1, -1);
	builder.reg_reactor(2, vec![Cow::from("topic2")], vec![Cow::from("topic4")], 1,  -1, -1);
	builder.reg_reactor(1, vec![Cow::from("topic3"), Cow::from("topic4")], vec![], 1, -1, -1);

	let task_graph = builder.build();
	let dag_tasks = task_graph.to_dag_tasks().unwrap();
	assert_eq!(dag_tasks.len(), 1);
	assert!(dag_tasks[0].node_to_reactor == [4, 3, 0, 2, 1] ||
		dag_tasks[0].node_to_reactor == [4, 3, 2, 0, 1]);
}

/// non-DAG case
/// +--------+                                 +--------+
/// | topic0 | <---------- reactor0 <--------- | topic2 |
/// +--------+                                 +--------+
///      |                                          |
///      |                                          |
///      V                +--------+                |
///  reactor1 ----------> | topic1 | ----------> reactor2
///                       +--------+
#[test]
fn test_non_dag_task()
{
	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(0, vec![Cow::from("topic2")], vec![Cow::from("topic0")], 1, 10, 10);
	builder.reg_reactor(1, vec![Cow::from("topic0")], vec![Cow::from("topic1")], 1, 10, 10);
	builder.reg_reactor(2, vec![Cow::from("topic1")], vec![Cow::from("topic2")], 1, 10, 10);

	let task_graph = builder.build();
	let dag_tasks = task_graph.to_dag_tasks();
	assert!(dag_tasks.is_none());
}

/// (reactor 3) -------[topic 3]-------> (reactor 5) -------[topic 2]-------> (reactor 0)
/// 
/// (reactor 2) -------[topic 0]-------> (reactor 1) -------[topic 1]-------> (reactor 4)
///                        |                                                       A
///                        |                                                       |
///                        +-------------------------------------------------------+
#[test]
fn test_dag_tasks_2()
{
	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(0, vec![Cow::from("topic2")], vec![], 1, -1, -1);
	builder.reg_reactor(1, vec![Cow::from("topic0")], vec![Cow::from("topic1")], 1, -1, -1);
	builder.reg_reactor(2, vec![], vec![Cow::from("topic0")], 1, 10, 10);
	builder.reg_reactor(3, vec![], vec![Cow::from("topic3")], 1, 30, 20);
	builder.reg_reactor(4, vec![Cow::from("topic0"), Cow::from("topic1")], vec![], 1, -1, -1);
	builder.reg_reactor(5, vec![Cow::from("topic3")], vec![Cow::from("topic2")], 1, -1, -1);

	let task_graph = builder.build();
	let dag_tasks = task_graph.to_dag_tasks().unwrap();
	assert_eq!(dag_tasks.len(), 2);
	let dag_task0 = &dag_tasks[0];
	assert_eq!(dag_task0.node_to_reactor, [3, 5, 0]);
	let dag_task1 = &dag_tasks[1];
	assert_eq!(dag_task1.node_to_reactor, [2, 1, 4]);

	assert_eq!(dag_task0.period, 30);
	assert_eq!(dag_task0.relative_deadline, 20);
	assert_eq!(dag_task1.period, 10);
	assert_eq!(dag_task1.relative_deadline, 10);
}
