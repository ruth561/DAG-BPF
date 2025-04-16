// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Takumi Jin
mod yaml_reader;
use yaml_reader::*;

use std::borrow::Cow;

use clap::Parser;


#[derive(Debug, Parser)]
struct Cli {
	/// Specify the YAML file created by RD-Gen, which represents a DAG structure.
	#[clap(short, long, verbatim_doc_comment)]
	dag_file: String,

	/// Specify the unit of work.
	#[clap(short, long, verbatim_doc_comment, default_value="40000")]
	busy_unit: usize,
}

fn main()
{
	let cli = Cli::parse();

	let graph_data = dag_task_from_yaml(Cow::Owned(cli.dag_file));
	let reactors = graph_data_to_reactor_info(graph_data);
	spawn_reactors(reactors, cli.busy_unit);
}
