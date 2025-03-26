use std::error::Error;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread::sleep;
use std::thread::JoinHandle;

use std::collections::HashMap;
use std::borrow::Cow;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::vec;

use bpf_comm::urb::UserRingBuffer;
use dag_bpf::send_dag_task_to_bpf;
use linux_utils::gettid;
use linux_utils::prctl_set_name;
use linux_utils::LinuxTid;
use dag_task::dag::TaskGraphBuilder;

type Subscriber = (LinuxTid, Sender<MsgItem>);

struct Topic {
	subscribers: Vec<Subscriber>,
}

struct TopicManager {
	topics: HashMap<Cow<'static, str>, Topic>,
}

static TOPIC_MANAGER: LazyLock<Mutex<TopicManager>> = LazyLock::new(|| {
	Mutex::new(TopicManager { topics: HashMap::new() })
});

impl TopicManager {
	fn subscribe(&mut self, topic_name: Cow<'static, str>, tid: LinuxTid, sender: Sender<MsgItem>)
	{
		println!("[sub] Thread (tid={tid}) subscribes the topic \"{}\"", topic_name);

		if let Some(topic) = self.topics.get_mut(&topic_name) {
			topic.subscribers.push((tid, sender));
		} else {
			let subscribers = vec![(tid, sender)];
			let topic = Topic {
				subscribers
			};
			self.topics.insert(topic_name, topic);
		}
	}

	fn publish(&mut self, topic_name: Cow<'static, str>, msg: MsgItem)
	{
		println!("[pub] publish to {}: msg={:?}", topic_name, msg);

		if let Some(topic) = self.topics.get_mut(&topic_name) {
			for (tid, subscriber) in &mut topic.subscribers {
				println!("[pub] publish to thread (tid={tid}): msg={msg:?}");
				subscriber.send(msg.clone()).unwrap();
			}
		} else {
			// topicのみを作成する。
			// subscribersは空リストとする。
			let subscribers = vec![];
			let topic = Topic {
				subscribers
			};
			self.topics.insert(topic_name, topic);
		}
	}
}

#[derive(Debug, Clone)]
pub enum MsgItem {
	U32(u32),
}

fn register_subscription(tid: LinuxTid, subscribe_topic_names: &Vec<Cow<'static, str>>) -> Vec<Receiver<MsgItem>>
{
	let mut manager = TOPIC_MANAGER.lock().unwrap();

	let mut rcvers = vec![];
	for topic in subscribe_topic_names {
		let (snder, rcver) = std::sync::mpsc::channel();
		manager.subscribe(topic.clone(), tid, snder);
		rcvers.push(rcver);
	}
	rcvers
}

/// topic1 (MsgItem::U32(u32))       topic3 (MsgItem::U32(u32))
///             |         +-----------+         |
///             +-------->|  reactor  |-------->+
///             |         +-----------+         |
/// topic2 (MsgItem::U32(u32))       topic4 (MsgItem::U32(u32))
/// 
/// e.g.)
/// let f = |v: Vec<MsgItem>| -> Vec<MsgItem> { ... }
/// let (tid, handle) = spawn_reactor(
/// 	f,
/// 	vec![Cow::from("topic0"), Cow::from("topic1")],
/// 	vec![Cow::from("topic2"), Cow::from("topic3")]
/// );
/// handle.join().unwrap();
/// 
/// The reactor name will be set to `task_struct->comm`.
pub fn spawn_reactor<F>(
	reactor_name: Cow<'static, str>,
	f: F,
	subscribe_topic_names: Vec<Cow<'static, str>>,
	publish_topic_names: Vec<Cow<'static, str>>,
) -> Result<(LinuxTid, JoinHandle<()>), Box<dyn Error>>
where
	F: Fn(Vec<MsgItem>) -> Vec<MsgItem> + Send + 'static
{
	// thread::spawnで生成した小スレッドのtidを親スレッドに伝達するための一時的なchannel
	let (tid_tx, tid_rx) = mpsc::channel();
	let subscribe_topic_names_cloned = subscribe_topic_names.clone();
	let publish_topic_names_cloned = publish_topic_names.clone();

	let handle = std::thread::spawn(move || {
		prctl_set_name(reactor_name);
		let tid = gettid();
		tid_tx.send(tid).unwrap();
		println!("Thread (tid={tid}) is spawned!");

		// channelを作成する
		let rcvrs = register_subscription(tid, &subscribe_topic_names);

		loop {
			let mut args = vec![];
			for rcvr in &rcvrs {
				let msg = rcvr.recv().unwrap();
				args.push(msg);
			}

			let mut ret = f(args);
			for topic in publish_topic_names.iter().rev() {
				let mut manager = TOPIC_MANAGER.lock().unwrap();
				manager.publish(topic.clone(), ret.pop().unwrap());
			}
		}
	});

	let ch_tid = tid_rx.recv().unwrap();

	// Registers a reactor to TaskGraph.
	let mut task_graph_manager = TASK_GRAPH_MANAGER.lock().unwrap();
	task_graph_manager.task_graph_builder.reg_reactor(
		ch_tid,
		subscribe_topic_names_cloned,
		publish_topic_names_cloned,
	);

	Ok((ch_tid, handle))
} 

/// let f = || -> Vec<MsgItem> { ... }
/// spawn_reactor()
pub fn spawn_periodic_reactor<F>(
	reactor_name: Cow<'static, str>,
	f: F,
	publish_topic_names: Vec<Cow<'static, str>>,
	period: Duration,
) -> Result<(LinuxTid, JoinHandle<()>), Box<dyn Error>>
where
	F: Fn() -> Vec<MsgItem> + Send + 'static
{
	let (tid_tx, tid_rx) = mpsc::channel();
	let publish_topic_names_cloned = publish_topic_names.clone();

	let handle = std::thread::spawn(move || {
		prctl_set_name(reactor_name);
		let tid = gettid();
		tid_tx.send(tid).unwrap();
		println!("Thread (tid={tid}) is spawned!");

		loop {
			sleep(period);

			let mut ret = f();
			for topic in publish_topic_names.iter().rev() {
				let mut manager = TOPIC_MANAGER.lock().unwrap();
				manager.publish(topic.clone(), ret.pop().unwrap());
			}
		}
	});

	let ch_tid = tid_rx.recv().unwrap();

	// Registers a reactor to TaskGraph.
	let mut task_graph_manager = TASK_GRAPH_MANAGER.lock().unwrap();
	task_graph_manager.task_graph_builder.reg_reactor(
		ch_tid,
		vec![],
		publish_topic_names_cloned,
	);

	Ok((ch_tid, handle))
} 

// MARK: task graph manager
struct TaskGraphManager {
	commited: bool,
	task_graph_builder: TaskGraphBuilder, 
}

static TASK_GRAPH_MANAGER: LazyLock<Mutex<TaskGraphManager>> = LazyLock::new(|| {
	Mutex::new(TaskGraphManager { commited: false, task_graph_builder: TaskGraphBuilder::new() })
});

/// Analyzes the information of current spwaned reactors and send it to eBPF program.
pub fn commit_reactor_info(urb: &mut UserRingBuffer)
{
	let mut task_graph_manager = TASK_GRAPH_MANAGER.lock().unwrap();
	if task_graph_manager.commited {
		panic!("Task graph has already been commited.");
	}
	task_graph_manager.commited = true;

	let task_graph = task_graph_manager.task_graph_builder.build();
	let dag_tasks = task_graph.to_dag_tasks().unwrap();

	println!("[DEBUG commit_reactor_info] dag_tasks: {:?}", dag_tasks);

	for dag_task in &dag_tasks {
		send_dag_task_to_bpf(urb, dag_task);
	}
}
