use std::borrow::Cow;
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;

use bpf_comm::urb::UserRingBuffer;
use serde::Deserialize;
use reactor_api::*;


// MARK: YAML -> GraphData

// Data structures used by RD-Gen.
//
// RD-Gen uses the `networkx` library in Python 3.
// The corresponding data structures expected from its output
// should be defined here.
#[derive(Debug, Deserialize)]
pub struct GraphData {
	directed: bool,
	multigraph: bool,
	_graph: Option<GraphAttr>, // Unspecified by RD-Gen
	nodes: Vec<Node>,
	links: Vec<Link>,
}

#[derive(Debug, Deserialize)]
struct GraphAttr {}

// All time-related field is taken as milliseconds
#[derive(Debug, Deserialize)]
struct Node {
	id: usize,
	end_to_end_deadline: Option<u64>,
	execution_time: u64,
	// If `period` is Some(...), this node is timer-driven.
	// If `period` is None, this node is event-driven.
	// The unit of `period` is milliseconds.
	period: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct Link {
	source: usize,
	target: usize,
}

// Build the GraphData instance from the specified YAML file.
pub fn dag_task_from_yaml(file_name: Cow<'static, str>) -> GraphData
{
	let file = File::open(file_name.as_ref())
		.expect("Cannot open the YAML file...");

	let reader = BufReader::new(file);

	let mut graph_data: GraphData = serde_yaml::from_reader(reader).unwrap();

	assert!(graph_data.directed);
	assert!(!graph_data.multigraph);

	graph_data.nodes.sort_by_key(|node| node.id); // Is this process necessary?

	for i in 0..graph_data.nodes.len() {
		assert_eq!(i, graph_data.nodes[i].id);
	}

	graph_data
}

// MARK: GraphData -> ReactorInfo

// ReactorInfo is used to describe a reactor composing the DAG-task.
// For example, whether the reactor is timer-driven or event-driven.
// This data strucuture is used to spawn reactors.
#[derive(Debug)]
pub struct ReactorInfo {
	name: Cow<'static, str>,
	weight: Duration,
	task_type: ReactorType,
	_relative_deadline: Option<u64>, // not used for now
	pub_links: Vec<usize>,
}

#[derive(Debug)]
enum ReactorType {
	TimerDriven {
		period: Duration,
	},
	EventDriven {
		sub_links: Vec<usize>,
	}
}

pub fn graph_data_to_reactor_info(graph_data: GraphData) -> Vec<ReactorInfo>
{
	let mut reactors = vec![];
	for (i, node) in graph_data.nodes.iter().enumerate() {
		let name = Cow::Owned(format!("reactor{i}"));
		let weight = Duration::from_millis(node.execution_time);
		match node.period {
			Some(period) => {
				reactors.push(ReactorInfo{
					name,
					weight,
					task_type: ReactorType::TimerDriven { period: Duration::from_millis(period) },
					_relative_deadline: node.end_to_end_deadline,
					pub_links: vec![],
				});
			},
			None => {
				reactors.push(ReactorInfo {
					name,
					weight,
					task_type: ReactorType::EventDriven { sub_links: vec![] },
					_relative_deadline: node.end_to_end_deadline,
					pub_links: vec![],
				});
			},
		}
	}

	for (i, link) in graph_data.links.iter().enumerate() {
		assert!(link.source < link.target);

		reactors[link.source].pub_links.push(i);
		match &mut reactors[link.target].task_type {
			ReactorType::EventDriven { sub_links } => {
				sub_links.push(i);
			},
			_ => panic!("link destination is not an event-driven node."),
		}
	}

	for reactor in &reactors {
		println!("reactor: {:?}", reactor);
	}

	reactors
}

// MARK: spawn_reactor
fn busy(weight: usize)
{
	for i in 0..weight {
		std::hint::black_box(i);
	}
}

pub fn spawn_reactors(reactors: Vec<ReactorInfo>, busy_unit: usize)
{
	use MsgItem::*;

	let mut handles = vec![];
	let mut tids = vec![];

	for reactor in reactors {
		let name = reactor.name;
		let weight = reactor.weight;
		let publish_topics: Vec<Cow<'static, str>> = reactor
			.pub_links
			.iter()
			.map(|link_id| Cow::Owned(format!("topic{link_id}")))
			.collect();
		let nr_publish_topics = publish_topics.len();
		match reactor.task_type {
			ReactorType::TimerDriven { period } => {
				let f = move || {
					busy(weight.as_millis() as usize * busy_unit);
					let ret = vec![U32(0); nr_publish_topics];
					ret
				};
				let (tid, handle) = spawn_periodic_reactor(
					Cow::from(name),
					f,
					publish_topics,
					period,
					period,
					weight.as_millis() as i64,
				).unwrap();
				handles.push(handle);
				tids.push(tid);
			},
			ReactorType::EventDriven { sub_links } => {
				let sub_topics: Vec<Cow<'static, str>> = sub_links
					.iter()
					.map(|link_id| Cow::Owned(format!("topic{link_id}")))
					.collect();
				let f = move |_| {
					busy(weight.as_millis() as usize * busy_unit);
					let ret = vec![U32(0); nr_publish_topics];
					ret
				};
				let (tid, handle) = spawn_reactor(
					Cow::from(name),
					f,
					sub_topics.clone(),
					publish_topics.clone(),
					weight.as_millis() as i64,
				).unwrap();
				handles.push(handle);
				tids.push(tid);
			}
		}

	}

	println!("[*] tids: {:?}", tids);

	const USER_RING_BUFFER_NAME: &'static str = "urb";
	let mut urb = UserRingBuffer::new(USER_RING_BUFFER_NAME).unwrap();

	commit_reactor_info(&mut urb);

	/* join */
	for handle in handles {
		handle.join().unwrap();
	}
}
