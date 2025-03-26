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

use dag_bpf::utils::gettid;
use dag_bpf::utils::LinuxTid;

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
pub fn spawn_reactor<F>(
	f: F,
	subscribe_topic_names: Vec<Cow<'static, str>>,
	publish_topic_names: Vec<Cow<'static, str>>,
) -> Result<(LinuxTid, JoinHandle<()>), Box<dyn Error>>
where
	F: Fn(Vec<MsgItem>) -> Vec<MsgItem> + Send + 'static
{
	// thread::spawnで生成した小スレッドのtidを親スレッドに伝達するための一時的なchannel
	let (tid_tx, tid_rx) = mpsc::channel();

	let handle = std::thread::spawn(move || {
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

	Ok((ch_tid, handle))
} 

/// let f = || -> Vec<MsgItem> { ... }
/// spawn_reactor()
pub fn spawn_periodic_reactor<F>(
	f: F,
	publish_topic_names: Vec<Cow<'static, str>>,
	period: Duration,
) -> Result<(LinuxTid, JoinHandle<()>), Box<dyn Error>>
where
	F: Fn() -> Vec<MsgItem> + Send + 'static
{
	let (tid_tx, tid_rx) = mpsc::channel();

	let handle = std::thread::spawn(move || {
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

	Ok((ch_tid, handle))
} 
