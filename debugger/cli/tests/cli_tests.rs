use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn write_test_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_named_test_fixture("simple.sil", "simple.test.json")
}

fn write_fixture_files(
    script_name: &str,
    test_file_name: &str,
    script_source: &str,
    test_file_source: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_test_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join(script_name);
    let test_file_path = dir.join(test_file_name);

    std::fs::write(&script_path, script_source).expect("write fixture contract");
    std::fs::write(&test_file_path, test_file_source).expect("write fixture test file");

    (script_path, test_file_path)
}

fn write_logging_test_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        "logging.sil",
        "logging.test.json",
        r#"pragma silverscript ^0.1.0;

contract Logging(int seed) {
    entrypoint function check(int a) {
        console.log("seed", seed);
        console.log("sum", seed + a);
        require(seed + a > 0);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "log_case",
      "function": "check",
      "constructor_args": [5],
      "args": [4],
      "expect": "pass"
    }
  ]
}
"#,
    )
}

fn write_structured_console_fixture() -> std::path::PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_console_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join("structured_console.sil");
    std::fs::write(
        &script_path,
        r#"pragma silverscript ^0.1.0;

contract DebugSmallInline() {
    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;

    entrypoint function inspect(State[] next_states) {
        console.log("total sum of amounts: ", next_states[0].amount + next_states[1].amount);

        require(next_states[0].active == active);
        require(next_states[0].tag == tag);
        require(next_states[1].tag == 0xbb);
    }
}
"#,
    )
    .expect("write fixture contract");

    script_path
}

fn write_debug_state_fixture() -> std::path::PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_state_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join("debug_state.sil");
    std::fs::write(
        &script_path,
        r#"pragma silverscript ^0.1.0;

contract DebugState(int ctor_x) {
    int constant const_y = 5;

    int amount = 1;
    bool active = true;
    byte[1] tag = 0xaa;
    struct Pair {
        int amount;
        byte[2] code;
    }

    entrypoint function inspect_state(State next_state) {
        int bumped = next_state.amount + 1;
        byte[1] next_tag = next_state.tag;

        require(bumped > amount);
        require(next_state.active == active);
        require(next_tag == next_state.tag);
    }

    entrypoint function inspect_state_array(State[] next_states) {
        int first_amount = next_states[0].amount;
        byte[1] second_tag = next_states[1].tag;

        require(next_states.length == 2);
        require(first_amount < next_states[1].amount);
        require(next_states[0].active == true);
        require(second_tag == next_states[1].tag);
    }

    entrypoint function inspect_pair(Pair next_pair) {
        int pair_amount = next_pair.amount;
        byte[2] pair_tag = next_pair.code;

        require(pair_amount > 0);
        require(pair_tag == next_pair.code);
    }
}
"#,
    )
    .expect("write fixture contract");

    script_path
}

fn write_named_test_fixture(script_name: &str, test_file_name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        script_name,
        test_file_name,
        r#"pragma silverscript ^0.1.0;

contract Simple(int x) {
    entrypoint function check(int a) {
        require(a == x);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "pass_case",
      "function": "check",
      "constructor_args": [5],
      "args": [5],
      "expect": "pass"
    },
    {
      "name": "fail_case",
      "function": "check",
      "constructor_args": [5],
      "args": [4],
      "expect": "fail"
    }
  ]
}
"#,
    )
}

fn write_structured_args_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        "structured_args.sil",
        "structured_args.test.json",
        r#"pragma silverscript ^0.1.0;

contract StructuredArgs() {
    int amount = 1;
    byte[32] owner = 0x1111111111111111111111111111111111111111111111111111111111111111;

    entrypoint function inspect(State next) {
        int bumped = next.amount + 1;
        require(bumped > amount);
    }

    entrypoint function inspect_many(State[] next_states) {
        require(next_states.length == 2);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "object_arg_pass",
      "function": "inspect",
      "args": [
        {
          "amount": 7,
          "owner": "0x2222222222222222222222222222222222222222222222222222222222222222"
        }
      ],
      "expect": "pass"
    },
    {
      "name": "object_array_arg_pass",
      "function": "inspect_many",
      "args": [
        [
          {
            "amount": 7,
            "owner": "0x2222222222222222222222222222222222222222222222222222222222222222"
          },
          {
            "amount": 9,
            "owner": "0x3333333333333333333333333333333333333333333333333333333333333333"
          }
        ]
      ],
      "expect": "pass"
    }
  ]
}
"#,
    )
}

fn write_structured_ctor_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        "structured_ctor.sil",
        "structured_ctor.test.json",
        r#"pragma silverscript ^0.1.0;

contract StructuredCtor(Pair seed) {
    struct Pair {
        int amount;
        byte[2] code;
    }

    entrypoint function inspect() {
        require(true);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "struct_ctor_pass",
      "function": "inspect",
      "constructor_args": [
        {
          "amount": 7,
          "code": "0x1234"
        }
      ],
      "expect": "pass"
    }
  ]
}
"#,
    )
}

fn write_covenant_omitted_args_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        "cov_debug_demo.sil",
        "cov_debug_demo.test.json",
        r#"pragma silverscript ^0.1.0;

contract CovDebugDemo(int bump) {
    int value = 0;

    #[covenant(binding = cov, from = 2, to = 2, mode = verification)]
    function step(State[] prev_states, State[] new_states) {
        require(new_states[0].value == prev_states[0].value + bump);
        require(new_states[1].value == prev_states[1].value);
    }

    #[covenant(binding = cov, from = 2, to = 2, mode = verification)]
    function step_with_nonce(State[] prev_states, State[] new_states, int nonce) {
        require(nonce == bump);
        require(new_states[0].value == prev_states[0].value + bump);
        require(new_states[1].value == prev_states[1].value);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "source_leader_infers_args",
      "function": "step",
      "constructor_args": [2],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ],
        "outputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 9 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ]
      }
    },
    {
      "name": "source_leader_missing_nonce",
      "function": "step_with_nonce",
      "constructor_args": [2],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ],
        "outputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 9 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ]
      }
    },
    {
      "name": "source_leader_explicit_empty_args",
      "function": "step",
      "constructor_args": [2],
      "args": [],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ],
        "outputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 9 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ]
      }
    }
  ]
}
"#,
    )
}

fn write_covenant_local_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_fixture_files(
        "cov_debug_locals.sil",
        "cov_debug_locals.test.json",
        r#"pragma silverscript ^0.1.0;

contract CovDebugDemo(int bump) {
    int value = 0;

    #[covenant(binding = cov, from = 2, to = 2, mode = verification)]
    function step(State[] prev_states, State[] new_states) {
        int a = prev_states[0].value;
        int b = a + bump + value;
        require(new_states[0].value == prev_states[0].value + bump);
        require(new_states[1].value == prev_states[1].value);
        require(b == 16);
    }
}
"#,
        r#"{
  "tests": [
    {
      "name": "source_leader_local",
      "function": "step",
      "constructor_args": [2],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ],
        "outputs": [
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 9 }
          },
          {
            "amount": 1000,
            "covenant_id": 1,
            "state": { "value": 7 }
          }
        ]
      }
    }
  ]
}
"#,
    )
}

#[test]
fn cli_debugger_repl_all_commands_smoke() {
    let tmp = std::env::temp_dir().join("cli_test_if_statement.sil");
    std::fs::write(
        &tmp,
        r#"pragma silverscript ^0.1.0;

contract IfStatement(int x, int y) {
    entrypoint function hello(int a, int b) {
        int d = a + b;
        d = d - a;
        if (d == x - 2) {
            int c = d + b;
            d = a + c;
            require(c > d);
        } else {
            require(d == a);
        }
        d = d + a;
        require(d == y);
    }
}
"#,
    )
    .expect("write temp contract");
    let contract_path = &tmp;

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(contract_path)
        .arg("--function")
        .arg("hello")
        .arg("--ctor-arg")
        .arg("3")
        .arg("--ctor-arg")
        .arg("10")
        .arg("--arg")
        .arg("5")
        .arg("--arg")
        .arg("5")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"help\nl\nstack\nb 1\nb 7\nb\nn\nsi\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("Stepping through"), "missing startup output");
    assert!(stdout.contains("(sdb)"), "missing prompt output");
    assert!(stdout.contains("Commands:"), "missing help output");
    assert!(stdout.contains("Stack:"), "missing stack output");
    let saw_line1_feedback = stdout.contains("no statement at line 1") || stdout.contains("Breakpoint set at line 1");
    assert!(saw_line1_feedback, "missing breakpoint feedback for line 1");
    assert!(stdout.contains("Breakpoint set at line 7"), "missing line-7 breakpoint success");
    let listing_contains_7 = stdout.lines().any(|line| line.contains("Breakpoints:") && line.contains('7'));
    assert!(listing_contains_7, "missing breakpoint listing containing line 7");
}

#[test]
fn cli_debugger_eval_command_reports_results_and_errors() {
    let (script_path, _test_file_path) = write_test_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("check")
        .arg("--ctor-arg")
        .arg("5")
        .arg("--arg")
        .arg("5")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"eval 1 + 2\ne a + 1\ne missing + 1\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("1 + 2 = (int) 3"), "missing literal eval output: {stdout}");
    assert!(stdout.contains("a + 1 = (int) 6"), "missing scoped eval output: {stdout}");
    assert!(
        stdout.contains("ERROR: failed to compile debug expression: undefined identifier: missing"),
        "missing eval error output: {stdout}"
    );
}

#[test]
fn cli_debugger_interactive_prints_console_logs_automatically() {
    let (script_path, _test_file_path) = write_logging_test_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("check")
        .arg("--ctor-arg")
        .arg("5")
        .arg("--arg")
        .arg("4")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    child.stdin.as_mut().expect("stdin available").write_all(b"q\n").expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("seed 5"), "missing first console log: {stdout}");
}

#[test]
fn cli_debugger_interactive_does_not_duplicate_startup_console_logs_for_structured_arrays() {
    let script_path = write_structured_console_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("inspect")
        .arg("--arg")
        .arg(r#"[{"amount":5,"active":true,"tag":"0xaa"},{"amount":9,"active":true,"tag":"0xbb"}]"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    child.stdin.as_mut().expect("stdin available").write_all(b"q\n").expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let needle = "total sum of amounts:  14";

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert_eq!(stdout.matches(needle).count(), 1, "expected exactly one startup console log: {stdout}");
}

#[test]
fn cli_debugger_accepts_state_object_arg_and_renders_source_level_value() {
    let (script_path, _test_file_path) = write_structured_args_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("inspect")
        .arg("--arg")
        .arg(r#"{"amount":7,"owner":"0x2222222222222222222222222222222222222222222222222222222222222222"}"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"vars\np next\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rendered = "{amount: 7, owner: 0x2222222222222222222222222222222222222222222222222222222222222222}";

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("Contract State:"), "missing Contract State section: {stdout}");
    assert!(stdout.contains("Call Arguments:"), "missing Call Arguments section: {stdout}");
    assert!(stdout.contains(&format!("next (State) = {rendered}")), "missing rendered State value: {stdout}");
}

#[test]
fn cli_debugger_accepts_state_object_array_arg_and_renders_source_level_value() {
    let (script_path, _test_file_path) = write_structured_args_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("inspect_many")
        .arg("--arg")
        .arg(
            r#"[{"amount":7,"owner":"0x2222222222222222222222222222222222222222222222222222222222222222"},{"amount":9,"owner":"0x3333333333333333333333333333333333333333333333333333333333333333"}]"#,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"vars\np next_states\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let rendered = "[{amount: 7, owner: 0x2222222222222222222222222222222222222222222222222222222222222222}, {amount: 9, owner: 0x3333333333333333333333333333333333333333333333333333333333333333}]";

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains(&format!("next_states (State[]) = {rendered}")), "missing rendered State[] value: {stdout}");
}

#[test]
fn cli_debugger_accepts_struct_constructor_arg_and_renders_source_level_value() {
    let (script_path, _test_file_path) = write_structured_ctor_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("inspect")
        .arg("--ctor-arg")
        .arg(r#"{"amount":7,"code":"0x1234"}"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"vars\np seed\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("seed (Pair) = {amount: 7, code: 0x1234}"), "missing rendered constructor struct value: {stdout}");
}

#[test]
fn cli_debugger_evals_structured_state_expressions() {
    let script_path = write_debug_state_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("inspect_state")
        .arg("--ctor-arg")
        .arg("4")
        .arg("--arg")
        .arg(r#"{"amount":5,"active":true,"tag":"0xaa"}"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"eval next_state\neval next_state.amount\neval next_state.amount + amount\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("next_state = (State) {amount: 5, active: true, tag: 0xaa}"), "missing state eval output: {stdout}");
    assert!(stdout.contains("next_state.amount = (int) 5"), "missing state field eval output: {stdout}");
    assert!(stdout.contains("next_state.amount + amount = (int) 6"), "missing state arithmetic eval output: {stdout}");
}

#[test]
fn cli_debugger_run_test_file_pass_case() {
    let (_script_path, test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("pass_case")
        .output()
        .expect("run cli-debugger pass test");

    assert!(
        output.status.success(),
        "expected success, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "expected PASS in stdout, got: {stdout}");
}

#[test]
fn cli_debugger_run_test_file_expected_fail_case() {
    let (_script_path, test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("fail_case")
        .output()
        .expect("run cli-debugger expected-fail test");

    assert!(
        output.status.success(),
        "expected success for expected-fail test, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS (expected failure)"), "expected expected-failure PASS marker in stdout, got: {stdout}");
}

#[test]
fn cli_debugger_run_all_uses_test_file_suite() {
    let (_script_path, test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run-all")
        .arg("--test-file")
        .arg(&test_file_path)
        .output()
        .expect("run cli-debugger --run-all");

    assert!(
        output.status.success(),
        "expected success for run-all, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RUN   pass_case"), "missing pass_case header: {stdout}");
    assert!(stdout.contains("RUN   fail_case"), "missing fail_case header: {stdout}");
    assert!(stdout.contains("PASS  pass_case"), "missing pass_case status: {stdout}");
    assert!(stdout.contains("PASS  fail_case"), "missing fail_case status: {stdout}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_all_supports_structured_args_from_test_file() {
    let (_script_path, test_file_path) = write_structured_args_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run-all")
        .arg("--test-file")
        .arg(&test_file_path)
        .output()
        .expect("run cli-debugger --run-all for structured args");

    assert!(
        output.status.success(),
        "expected success for structured run-all, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS  object_arg_pass"), "missing object_arg_pass line: {stdout}");
    assert!(stdout.contains("PASS  object_array_arg_pass"), "missing object_array_arg_pass line: {stdout}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_all_supports_structured_constructor_args_from_test_file() {
    let (_script_path, test_file_path) = write_structured_ctor_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run-all")
        .arg("--test-file")
        .arg(&test_file_path)
        .output()
        .expect("run cli-debugger --run-all for structured ctor args");

    assert!(
        output.status.success(),
        "expected success for structured ctor run-all, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS  struct_ctor_pass"), "missing struct_ctor_pass line: {stdout}");
    assert!(stdout.contains("1 tests: 1 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_test_file_infers_covenant_state_args_when_args_omitted() {
    let (_script_path, test_file_path) = write_covenant_omitted_args_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("source_leader_infers_args")
        .output()
        .expect("run cli-debugger covenant inference test");

    assert!(
        output.status.success(),
        "expected success, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "expected PASS in stdout, got: {stdout}");
}

#[test]
fn cli_debugger_run_test_file_reports_missing_non_state_covenant_args_when_args_omitted() {
    let (_script_path, test_file_path) = write_covenant_omitted_args_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("source_leader_missing_nonce")
        .output()
        .expect("run cli-debugger covenant nonce inference test");

    assert!(!output.status.success(), "expected missing nonce inference to fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot infer omitted args for covenant 'step_with_nonce'; provide explicit args for nonce (int)"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cli_debugger_run_test_file_preserves_explicit_empty_args_for_covenant_calls() {
    let (_script_path, test_file_path) = write_covenant_omitted_args_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("source_leader_explicit_empty_args")
        .output()
        .expect("run cli-debugger explicit empty covenant args test");

    assert!(!output.status.success(), "expected explicit empty args to remain strict");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("function expects 1 arguments, got 0"), "unexpected stderr: {stderr}");
}

#[test]
fn cli_debugger_covenant_vars_render_source_level_args_and_active_state() {
    let (script_path, test_file_path) = write_covenant_omitted_args_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("step")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("source_leader_infers_args")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"vars\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("Contract State:\n  value (int) = 7"), "missing active contract state: {stdout}");
    assert!(stdout.contains("prev_states (State[]) = [{value: 7}, {value: 7}]"), "missing prev_states call arg: {stdout}");
    assert!(stdout.contains("new_states (State[]) = [{value: 9}, {value: 7}]"), "missing new_states call arg: {stdout}");

    let call_args_index = stdout.find("Call Arguments:").expect("missing Call Arguments section");
    let new_states_index = stdout.find("new_states (State[]) = [{value: 9}, {value: 7}]").expect("missing new_states render");
    let locals_index = stdout.find("Locals:");
    assert!(call_args_index < new_states_index, "new_states should appear under Call Arguments: {stdout}");
    assert!(locals_index.is_none_or(|index| new_states_index < index), "new_states should not render as a local: {stdout}");
}

#[test]
fn cli_debugger_resolves_covenant_local_from_prev_states_array() {
    let (script_path, test_file_path) = write_covenant_local_fixture();

    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--function")
        .arg("step")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("source_leader_local")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn cli-debugger");

    let input = b"n\nvars\ne a\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for cli-debugger");
    assert!(output.status.success(), "cli-debugger exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("a (int) = 7"), "missing resolved local a: {stdout}");
    assert!(stdout.contains("a = (int) 7"), "missing resolved eval for a: {stdout}");
    assert!(!stdout.contains("a (int) = <unavailable"), "local a should not be unavailable: {stdout}");
    assert!(!stdout.contains("ERROR: failed to compile debug expression"), "local a should not hit debug compile failure: {stdout}");
}

#[test]
fn cli_debugger_run_all_infers_test_file_from_script_path() {
    let (script_path, _test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--run-all")
        .output()
        .expect("run cli-debugger --run-all with inferred sidecar");

    assert!(
        output.status.success(),
        "expected success for inferred run-all, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RUN   pass_case"), "missing pass_case header: {stdout}");
    assert!(stdout.contains("RUN   fail_case"), "missing fail_case header: {stdout}");
    assert!(stdout.contains("PASS  pass_case"), "missing pass_case status: {stdout}");
    assert!(stdout.contains("PASS  fail_case"), "missing fail_case status: {stdout}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_all_uses_script_override_for_mismatched_sidecar_name() {
    let (script_path, test_file_path) = write_named_test_fixture("actual_contract.sil", "suite.test.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--run-all")
        .arg("--test-file")
        .arg(&test_file_path)
        .output()
        .expect("run cli-debugger --run-all with script override");

    assert!(
        output.status.success(),
        "expected success for run-all with script override, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RUN   pass_case"), "missing pass_case header: {stdout}");
    assert!(stdout.contains("RUN   fail_case"), "missing fail_case header: {stdout}");
    assert!(stdout.contains("PASS  pass_case"), "missing pass_case status: {stdout}");
    assert!(stdout.contains("PASS  fail_case"), "missing fail_case status: {stdout}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_test_name_infers_test_file_from_script_path() {
    let (script_path, _test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--run")
        .arg("--test-name")
        .arg("pass_case")
        .output()
        .expect("run cli-debugger with inferred sidecar");

    assert!(
        output.status.success(),
        "expected success for inferred run test, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "expected PASS in stdout, got: {stdout}");
}

#[test]
fn cli_debugger_run_prints_console_logs_before_pass() {
    let (_script_path, test_file_path) = write_logging_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .arg("--test-name")
        .arg("log_case")
        .output()
        .expect("run cli-debugger logging test");

    assert!(
        output.status.success(),
        "expected success, status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let seed_index = stdout.find("seed 5").expect("missing seed log");
    let sum_index = stdout.find("sum 9").expect("missing sum log");
    let pass_index = stdout.find("PASS").expect("missing PASS output");
    assert!(seed_index < sum_index && sum_index < pass_index, "unexpected stdout order: {stdout}");
}

#[test]
fn cli_debugger_run_test_name_requires_matching_sidecar_or_explicit_test_file() {
    let (script_path, _test_file_path) = write_named_test_fixture("actual_contract.sil", "suite.test.json");

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg(&script_path)
        .arg("--run")
        .arg("--test-name")
        .arg("pass_case")
        .output()
        .expect("run cli-debugger without matching inferred script");

    assert!(!output.status.success(), "expected failure when inferred sidecar script is missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to canonicalize test file") && stderr.contains("actual_contract.test.json"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn cli_debugger_run_all_requires_test_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run-all")
        .output()
        .expect("run cli-debugger --run-all without test file");

    assert!(!output.status.success(), "expected failure when both script path and --test-file are missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--run-all requires SCRIPT_PATH or --test-file"), "unexpected stderr: {stderr}");
}

#[test]
fn cli_debugger_test_file_requires_test_name_in_run_mode() {
    let (_script_path, test_file_path) = write_test_fixture();

    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-file")
        .arg(&test_file_path)
        .output()
        .expect("run cli-debugger --run --test-file without test-name");

    assert!(!output.status.success(), "expected failure when --test-name is missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--test-file requires --test-name"), "unexpected stderr: {stderr}");
}

#[test]
fn cli_debugger_test_name_requires_script_path_or_test_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run")
        .arg("--test-name")
        .arg("pass_case")
        .output()
        .expect("run cli-debugger --run --test-name without script path or test file");

    assert!(!output.status.success(), "expected failure when neither script path nor test file is provided");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--test-name requires --test-file or SCRIPT_PATH"), "unexpected stderr: {stderr}");
}
