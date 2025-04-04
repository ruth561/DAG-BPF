use linux_utils::LinuxTid;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
enum MsgType {
	NewTask = 0,
	AddNode = 1,
	AddEdge = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MsgNewTaskPayload {
	src_node_tid: LinuxTid,
	src_node_weight: u32,
	relative_deadline: i64,
	period: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MsgAddNodePayload {
	dag_task_id: LinuxTid,
	tid: LinuxTid,
	weight: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MsgAddEdgePayload {
	dag_task_id: LinuxTid,
	from_tid: LinuxTid,
	to_tid: LinuxTid,
}

#[derive(Debug)]
pub enum DagBpfMsg {
	NewTask(MsgNewTaskPayload),
	AddNode(MsgAddNodePayload),
	AddEdge(MsgAddEdgePayload),
	Unknown, // fallback for unknown types
}

impl DagBpfMsg {
	pub fn new_task(src_node_tid: LinuxTid, src_node_weight: u32, relative_deadline: i64, period: i64) -> Self
	{
		DagBpfMsg::NewTask(MsgNewTaskPayload { src_node_tid, src_node_weight, relative_deadline, period })
	}

	pub fn add_node(dag_task_id: LinuxTid, tid: LinuxTid, weight: u32) -> Self
	{
		DagBpfMsg::AddNode(MsgAddNodePayload { dag_task_id, tid, weight, })
	}

	pub fn add_edge(dag_task_id: LinuxTid, from_tid: LinuxTid, to_tid: LinuxTid) -> Self
	{
		DagBpfMsg::AddEdge(MsgAddEdgePayload { dag_task_id, from_tid, to_tid, })
	}

	pub fn as_bytes(&self) -> Vec<u8>
	{
		let mut buffer = Vec::with_capacity(std::mem::size_of::<u32>() + std::mem::size_of::<MsgNewTaskPayload>());

		let msg_type = match self {
			DagBpfMsg::NewTask(_) => MsgType::NewTask as i32,
			DagBpfMsg::AddNode(_) => MsgType::AddNode as i32,
			DagBpfMsg::AddEdge(_) => MsgType::AddEdge as i32,
			DagBpfMsg::Unknown => panic!("Unknown msg type"),
		};
		buffer.extend_from_slice(&msg_type.to_ne_bytes());

		let payload = match self {
			DagBpfMsg::NewTask(payload) => as_bytes(payload),
			DagBpfMsg::AddNode(payload) => as_bytes(payload),
			DagBpfMsg::AddEdge(payload) => as_bytes(payload),
			DagBpfMsg::Unknown => panic!("Unknown msg type"),
		};
		buffer.extend_from_slice(payload);

		buffer
	}
}

// util function
// This function converts the instance of type `T` into bytes sequence.
fn as_bytes<'a, T>(val: &'a T) -> &'a [u8]
{
	unsafe {
		std::slice::from_raw_parts(
			val as *const _ as *const u8,
			std::mem::size_of::<T>(),
		)
	}
}
