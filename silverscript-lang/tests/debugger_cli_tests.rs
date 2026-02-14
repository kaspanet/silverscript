use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn example_contract_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/examples/if_statement.sil")
}

#[test]
fn sil_debug_repl_all_commands_smoke() {
    let contract_path = example_contract_path();
    assert!(contract_path.exists(), "example contract not found: {}", contract_path.display());

    let mut child = Command::new(env!("CARGO_BIN_EXE_sil-debug"))
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
        .expect("failed to spawn sil-debug");

    let input = b"help\nl\nstack\nb 1\nb 7\nb\nn\nsi\nq\n";
    child.stdin.as_mut().expect("stdin available").write_all(input).expect("write stdin");

    let output = child.wait_with_output().expect("wait for sil-debug");
    assert!(output.status.success(), "sil-debug exited with status {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    assert!(stdout.contains("Stepping through"), "missing startup output");
    assert!(stdout.contains("(sdb)"), "missing prompt output");
    assert!(stdout.contains("Commands:"), "missing help output");
    assert!(stdout.contains("Stack:"), "missing stack output");
    assert!(stdout.contains("no statement at line 1"), "missing invalid breakpoint warning");
    assert!(stdout.contains("Breakpoint set at line 7"), "missing breakpoint confirmation");
    assert!(stdout.contains("Breakpoints: 7"), "missing breakpoint listing");
}
