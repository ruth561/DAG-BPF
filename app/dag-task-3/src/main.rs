use std::time::Duration;
use std::borrow::Cow;

use bpf_comm::urb::UserRingBuffer;
use reactor_api::*;

const BUSY_UNIT: usize = 50000;

fn busy(weight: usize)
{
	for i in 0..weight {
		std::hint::black_box(i);
	}
}

enum TaskType {
	SrcNode {
		period: Duration,
	},
	InnerNode {
		subscribe_topics: Vec<Cow<'static, str>>,
	}
}

struct TaskInfo {
	name: &'static str,
	weight: usize,
	task_type: TaskType,
	publish_topics: Vec<Cow<'static, str>>,
}

fn main()
{
	let tasks = [
		TaskInfo {
			name: "task0",
			weight: 100,
			task_type: TaskType::SrcNode { period: Duration::from_secs(1) },
			publish_topics: vec![Cow::from("topic1"), Cow::from("topic2"), Cow::from("topic3"), Cow::from("topic4"), Cow::from("topic5")],
		},
		TaskInfo {
			name: "task1",
			weight: 700,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic1")], },
			publish_topics: vec![Cow::from("topic8")],
		},
		TaskInfo {
			name: "task2",
			weight: 300,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic2")], },
			publish_topics: vec![Cow::from("topic9")],
		},
		TaskInfo {
			name: "task3",
			weight: 300,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic3")], },
			publish_topics: vec![Cow::from("topic10")],
		},
		TaskInfo {
			name: "task4",
			weight: 600,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic4")], },
			publish_topics: vec![Cow::from("topic6")],
		},
		TaskInfo {
			name: "task5",
			weight: 100,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic5")], },
			publish_topics: vec![Cow::from("topic7")],
		},
		TaskInfo {
			name: "task6",
			weight: 200,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic6"), Cow::from("topic7")], },
			publish_topics: vec![Cow::from("topic11")],
		},
		TaskInfo {
			name: "task7",
			weight: 100,
			task_type: TaskType::InnerNode { subscribe_topics: vec![Cow::from("topic8"), Cow::from("topic9"), Cow::from("topic10"), Cow::from("topic11")], },
			publish_topics: vec![],
		},
	];

	use MsgItem::*;

	let mut handles = vec![];
	let mut tids = vec![];

	let nr_tasks = tasks.len();

	for i in 0..nr_tasks {
		let name = tasks[i].name;
		let weight = tasks[i].weight;
		let publish_topics = tasks[i].publish_topics.clone();
		let nr_publish_topics = publish_topics.len();
		match &tasks[i].task_type {
			TaskType::SrcNode { period } => {
				let f = move || {
					busy(weight * BUSY_UNIT);
					let ret = vec![U32(0); nr_publish_topics];
					ret
				};
				let (tid, handle) = spawn_periodic_reactor(
					Cow::from(name),
					f,
					publish_topics,
					*period,
					*period,
					weight as i64,
				).unwrap();
				handles.push(handle);
				tids.push(tid);
			},
			TaskType::InnerNode { subscribe_topics } => {
				let f = move |_| {
					busy(weight * BUSY_UNIT);
					let ret = vec![U32(0); nr_publish_topics];
					ret
				};
				let (tid, handle) = spawn_reactor(
					Cow::from(name),
					f,
					subscribe_topics.clone(),
					publish_topics.clone(),
					weight as i64,
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
