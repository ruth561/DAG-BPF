use dag_bpf::send_dag_task_to_bpf;
use dag_task::dag::TaskGraphBuilder;
use bpf_comm::urb::UserRingBuffer;

const USER_RING_BUFFER_NAME: &'static str = "urb";


fn main() {
	let mut urb = UserRingBuffer::new(USER_RING_BUFFER_NAME).unwrap();

	let mut builder = TaskGraphBuilder::new();

	builder.reg_reactor(0, vec!["topic2".to_string()], vec![]);
	builder.reg_reactor(1, vec!["topic0".to_string()], vec!["topic1".to_string()]);
	builder.reg_reactor(2, vec![], vec!["topic0".to_string()]);
	builder.reg_reactor(3, vec![], vec!["topic3".to_string()]);
	builder.reg_reactor(4, vec!["topic0".to_string(), "topic1".to_string()], vec![]);
	builder.reg_reactor(5, vec!["topic3".to_string()], vec!["topic2".to_string()]);

	let task_graph = builder.build();
	let dag_tasks = task_graph.to_dag_tasks().unwrap();
	assert_eq!(dag_tasks.len(), 2);
	let dag_task0 = &dag_tasks[0];
	assert_eq!(dag_task0.node_to_reactor, [3, 5, 0]);
	let dag_task1 = &dag_tasks[1];
	assert_eq!(dag_task1.node_to_reactor, [2, 1, 4]);

	send_dag_task_to_bpf(&mut urb, &dag_task0);
	send_dag_task_to_bpf(&mut urb, &dag_task1);
}
