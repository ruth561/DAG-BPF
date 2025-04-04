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

const WEIGHTS: [usize; 8] = [
	100, // task0
	700, // task1
	300, // task2
	300, // task3
	600, // task4
	100, // task5
	200, // task6
	100, // task7
];

const TASKS: [&'static str; 8] = [
	"task0",
	"task1",
	"task2",
	"task3",
	"task4",
	"task5",
	"task6",
	"task7",
];

fn main()
{
	use MsgItem::*;

	let mut handles = vec![];
	let mut tids = vec![];

	// MARK: task0
	let task0 = || {
		busy(WEIGHTS[0] * BUSY_UNIT);
		let ret = vec![U32(0), U32(0), U32(0), U32(0), U32(0)];
		ret
	};
	let (tid, handle) = spawn_periodic_reactor(
		Cow::from(TASKS[0]),
		task0,
		vec![Cow::from("topic1"), Cow::from("topic2"), Cow::from("topic3"), Cow::from("topic4"), Cow::from("topic5")],
		Duration::from_secs(1),
		Duration::from_secs(1),
		WEIGHTS[0] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task1
	let task1 = |_| {
		busy(WEIGHTS[1] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[1]),
		task1,
		vec![Cow::from("topic1")],
		vec![Cow::from("topic8")],
		WEIGHTS[1] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task2
	let task2 = |_| {
		busy(WEIGHTS[2] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[2]),
		task2,
		vec![Cow::from("topic2")],
		vec![Cow::from("topic9")],
		WEIGHTS[2] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task3
	let task3 = |_| {
		busy(WEIGHTS[3] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[3]),
		task3,
		vec![Cow::from("topic3")],
		vec![Cow::from("topic10")],
		WEIGHTS[3] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	// MARK: task4
	let task4 = |_| {
		busy(WEIGHTS[4] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[4]),
		task4,
		vec![Cow::from("topic4")],
		vec![Cow::from("topic6")],
		WEIGHTS[4] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	let task5 = |_| {
		busy(WEIGHTS[5] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[5]),
		task5,
		vec![Cow::from("topic5")],
		vec![Cow::from("topic7")],
		WEIGHTS[5] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	let task6 = |_| {
		busy(WEIGHTS[6] * BUSY_UNIT);
		let ret = vec![U32(0)];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[6]),
		task6,
		vec![Cow::from("topic6"), Cow::from("topic7")],
		vec![Cow::from("topic11")],
		WEIGHTS[6] as i64,
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	let task7 = |_| {
		busy(WEIGHTS[7] * BUSY_UNIT);
		let ret = vec![];
		ret
	};
	let (tid, handle) = spawn_reactor(
		Cow::from(TASKS[7]),
		task7,
		vec![Cow::from("topic8"), Cow::from("topic9"), Cow::from("topic10"), Cow::from("topic11")],
		vec![],
		WEIGHTS[7] as i64,
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
