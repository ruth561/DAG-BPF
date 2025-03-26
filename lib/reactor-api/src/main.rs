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

fn main()
{
	println!("Thread (tid={}) is spawned!", gettid());

	let mut handles = vec![];
	let mut tids = vec![];

	/* src node */
	let f = || {
		println!("\n[*] periodic src node!");
		busy(1000 * BUSY_UNIT);
		let ret = vec![MsgItem::U32(1729)];
		ret
	};
	let (tid, handle) = spawn_periodic_reactor(
		f,
		vec![Cow::from("topic0")],
		Duration::from_secs(1),
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	/* second node */
	let f = |v| {
		println!("second node! arg={:?}", v);
		busy(1000 * BUSY_UNIT);
		v
	};
	let (tid, handle) = spawn_reactor(
		f,
		vec![Cow::from("topic0")],
		vec![Cow::from("topic1")],
	).unwrap();
	handles.push(handle);
	tids.push(tid);

	/* third node */
	let f = |v| {
		println!("final node! arg={:?}", v);
		busy(1000 * BUSY_UNIT);
		vec![]
	};
	let (tid, handle) = spawn_reactor(
		f,
		vec![Cow::from("topic1")],
		vec![],
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
