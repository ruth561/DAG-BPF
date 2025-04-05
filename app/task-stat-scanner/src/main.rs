use bpf_comm::task_storage::TaskStorage;

use rustyline::error::ReadlineError;
use rustyline::Editor;


#[repr(C)]
struct EstCtx {
	estimated_exec_time: i64,
}

fn main() {
	let task_storage = TaskStorage::new("est_ctx").unwrap();

	let mut rl = Editor::<()>::new();
	if rl.load_history("history.txt").is_err() {
		println!("No previous history.");
	}

	loop {
		let readline = rl.readline("tid> ");
		match readline {
			Ok(line) => {
				rl.add_history_entry(line.as_str());

				if let Ok(tid) = i32::from_str_radix(&line, 10) {
					let mut ctx = EstCtx { estimated_exec_time: -1 };
					let result = task_storage.lookup_elem(tid, &mut ctx);
					match result {
						Ok(_) => println!("estimated_exec_time: {}", ctx.estimated_exec_time),
						Err(_) => println!("Failed to read estimated_exec_time.."),
					}
				}
			},
			Err(ReadlineError::Interrupted) => {
				println!("CTRL-C");
				break
			},
			Err(ReadlineError::Eof) => {
				println!("CTRL-D");
				break
			},
			Err(err) => {
				println!("Error: {:?}", err);
				break
			}
		}
	}
}
