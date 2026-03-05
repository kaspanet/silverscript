use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn write_test_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("cli_debugger_test_fixture_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&dir).expect("create temp fixture dir");

    let script_path = dir.join("simple.sil");
    let test_file_path = dir.join("simple.test.json");

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
    assert!(stdout.contains("PASS  pass_case"), "missing pass_case line: {stdout}");
    assert!(stdout.contains("PASS  fail_case"), "missing fail_case line (expected-fail test should still pass): {stdout}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "missing summary line: {stdout}");
}

#[test]
fn cli_debugger_run_all_requires_test_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_cli-debugger"))
        .arg("--run-all")
        .output()
        .expect("run cli-debugger --run-all without test file");

    assert!(!output.status.success(), "expected failure when --test-file is missing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--run-all requires --test-file"), "unexpected stderr: {stderr}");
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
