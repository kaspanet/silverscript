use std::io::Write;
use std::process::{Command, Stdio};

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
    assert!(stdout.contains("no statement at line 1"), "missing invalid breakpoint warning");
    assert!(stdout.contains("Breakpoint set at line 7"), "missing line-7 breakpoint success");
    assert!(stdout.contains("Breakpoints: 7"), "missing breakpoint listing");
}
