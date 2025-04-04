use std::time::Duration;
use std::borrow::Cow;

use bpf_comm::urb::UserRingBuffer;
use linux_utils::gettid;
use reactor_api::*;

const BUSY_UNIT: usize = 50000;

fn busy(weight: usize)
{
	for i in 0..weight {
		std::hint::black_box(i);
	}
}

const WEIGHTS: [usize; 5] = [
	100, // task0
	400, // task1
	200, // task2
	200, // task3
	100, // task4
];

const TASKS: [&'static str; 5] = [
	"task0",
	"task1",
	"task2",
	"task3",
	"task4",
];

fn main()
{
	println!("Thread (tid={}) is spawned!", gettid());

	let mut handles = vec![];
	let mut tids = vec![];

	// MARK: task0
	let task0 = || {
		busy(WEIGHTS[0] * BUSY_UNIT);
		let ret = vec![MsgItem::U32(1001), MsgItem::U32(1002), MsgItem::U32(1003)];
		ret
	};
	let (tid, handle) = spawn_periodic_reactor(
		Cow::from(TASKS[0]),
		task0,
		vec![Cow::from("topic1"), Cow::from("topic2"), Cow::from("topic3")],
		Duration::from_secs(1),
		Duration::from_secs(1),
		WEIGHTS[0] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task1
	let task1 = |_| {
		busy(WEIGHTS[1] * BUSY_UNIT);
		let ret = vec![MsgItem::U32(1004)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[1]),
		task1,
		vec![Cow::from("topic1")],
		vec![Cow::from("topic4")],
		WEIGHTS[1] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task2
	let task2 = |_| {
		busy(WEIGHTS[2] * BUSY_UNIT);
		let ret = vec![MsgItem::U32(1005)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[2]),
		task2,
		vec![Cow::from("topic2")],
		vec![Cow::from("topic5")],
		WEIGHTS[2] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task3
	let task3 = |_| {
		busy(WEIGHTS[3] * BUSY_UNIT);
		let ret = vec![MsgItem::U32(1006)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[3]),
		task3,
		vec![Cow::from("topic3")],
		vec![Cow::from("topic6")],
		WEIGHTS[3] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task4
	let task4 = |_| {
		busy(WEIGHTS[4] * BUSY_UNIT);
		let ret = vec![];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[4]),
		task4,
		vec![Cow::from("topic4"), Cow::from("topic5"), Cow::from("topic6")],
		vec![],
		WEIGHTS[4] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	println!("[*] tids: {:?}", tids);

	const USER_RING_BUFFER_NAME: &'static str = "urb";
	let mut urb = UserRingBuffer::new(USER_RING_BUFFER_NAME).unwrap();

	commit_reactor_info(&mut urb);

	/* join */
	for handle in handles {
		handle.join().unwrap();
	}
}
