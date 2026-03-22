use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn write_test_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    write_named_test_fixture("simple.sil", "simple.test.json")
}

fn write_logging_test_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_logging_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join("logging.sil");
    let test_file_path = dir.join("logging.test.json");

    std::fs::write(
        &script_path,
        r#"pragma silverscript ^0.1.0;

contract Logging(int seed) {
    entrypoint function check(int a) {
        console.log("seed", seed);
        console.log("sum", seed + a);
        require(seed + a > 0);
    }
}
"#,
    )
    .expect("write logging fixture contract");

    std::fs::write(
        &test_file_path,
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
    .expect("write logging fixture test file");

    (script_path, test_file_path)
}

fn write_named_test_fixture(script_name: &str, test_file_name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_test_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join(script_name);
    let test_file_path = dir.join(test_file_name);

    std::fs::write(
        &script_path,
        r#"pragma silverscript ^0.1.0;

contract Simple(int x) {
    entrypoint function check(int a) {
        require(a == x);
    }
}
"#,
    )
    .expect("write fixture contract");

    std::fs::write(
        &test_file_path,
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
    .expect("write fixture test file");

    (script_path, test_file_path)
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
