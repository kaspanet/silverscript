use std::io::{BufReader, BufWriter};

use dap::prelude::Server;
use debugger_session::format_failure_report;
use serde_json::Value;

mod adapter;
mod launch_config;
mod refs;
mod runtime_builder;

use adapter::DapAdapter;
use launch_config::LaunchConfig;
use runtime_builder::build_launch;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        if arg == "--run-config-json" {
            let raw = args.next().ok_or("--run-config-json requires a JSON argument")?;
            return run_config_json(&raw);
        }
    }

    let input = BufReader::new(std::io::stdin());
    let output = BufWriter::new(std::io::stdout());
    let mut server = Server::new(input, output);
    let mut adapter = DapAdapter::new();

    loop {
        let req = match server.poll_request() {
            Ok(Some(req)) => req,
            Ok(None) => break,
            Err(err) => return Err(Box::new(err)),
        };

        let result = adapter.handle_request(req);
        if let Err(err) = server.respond(result.response) {
            return Err(Box::new(err));
        }

        for event in result.events {
            if let Err(err) = server.send_event(event) {
                return Err(Box::new(err));
            }
        }

        if result.should_exit {
            break;
        }
    }
    Ok(())
}

fn run_config_json(raw: &str) -> Result<(), Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_str(raw)?;
    let launch = LaunchConfig::from_value(value)?;
    let mut built = build_launch(launch.resolve(None)?)?;
    let session = built.runtime.session_mut();

    session.run_to_first_executed_statement()?;
    match session.continue_to_breakpoint() {
        Ok(Some(_)) | Ok(None) => {
            println!("Execution completed successfully.");
            Ok(())
        }
        Err(err) => {
            let report = session.build_failure_report(&err);
            let formatted = format_failure_report(&report, &|type_name, value| session.format_value(type_name, value));
            eprintln!("{formatted}");
            std::process::exit(1);
        }
    }
}
