use bpf_comm::urb::UserRingBuffer;
use bpf_comm_api::dag_bpf::DagBpfMsg;
use dag_task::dag::DagTask;

// TODO: Allow specifying the weight
pub fn send_dag_task_to_bpf(urb: &mut UserRingBuffer, dag_task: &DagTask)
{
	let dag_task_id = dag_task.node_to_reactor[0];
	let weight = dag_task.node_to_weight[0] as u32;

	let msg = DagBpfMsg::new_task(dag_task_id, weight).as_bytes();
	urb.send_bytes(&msg).unwrap();

	for i in 1..dag_task.nr_nodes {
		let tid = dag_task.node_to_reactor[i];
		let weight = dag_task.node_to_weight[i] as u32;
		let msg = DagBpfMsg::add_node(dag_task_id, tid, weight).as_bytes();
		urb.send_bytes(&msg).unwrap();
	}

	for i in 0..dag_task.nr_nodes {
		for j in &dag_task.edges[i] {
			let from_tid = dag_task.node_to_reactor[i];
			let to_tid = dag_task.node_to_reactor[*j];
			let msg = DagBpfMsg::add_edge(dag_task_id, from_tid, to_tid).as_bytes();
			urb.send_bytes(&msg).unwrap();
		}
	}
}
