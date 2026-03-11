mod harness;

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use harness::TestClient;
use serde_json::json;

const SIMPLE_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract Simple() {
    entrypoint function main() {
        int a = 1;
        int b = 2;
        require(a + b == 3);
    }
}
"#;

const MULTIFUNCTION_IF_STATEMENTS_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract MultiFunctionIfStatements(int x, int y) {
    entrypoint function transfer(int a, int b) {
        int d = a + b;
        d = d - a;
        if (d == x) {
            int c = d + b;
            d = a + c;
            require(c > d);
        } else {
            d = a;
        }
        d = d + a;
        require(d == y);
    }

    entrypoint function timeout(int b) {
        int d = b;
        d = d + 2;
        if (d == x) {
            int c = d + b;
            d = c + d;
            require(c > d);
        }
        d = b;
        require(d == y);
    }
}
"#;

const INLINE_CALL_BOUNCE_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract InlineBounce() {
    function check_pair(int leftInput, int rightInput) {
        int left = leftInput + rightInput;
        int right = left * 2;
        require(right >= left);
    }

    entrypoint function main(int a, int b) {
        check_pair(a, b);
        require(a >= 0);
    }
}
"#;

const STACK_RENDER_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract StackRender() {
    entrypoint function main(bool flag) {
        require(!flag);
    }
}
"#;

const CHECKSIG_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract CheckSig(pubkey pk) {
    entrypoint function main(sig s) {
        require(checkSig(s, pk));
    }
}
"#;

const P2PKH_SCRIPT: &str = r#"pragma silverscript ^0.1.0;

contract P2PKH(byte[32] pkh) {
    entrypoint function spend(pubkey pk, sig s) {
        require(blake2b(pk) == pkh);
        require(checkSig(s, pk));
    }
}
"#;

struct TempScript {
    path: PathBuf,
}

impl TempScript {
    fn new(source: &str) -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or_default();
        let file_name = format!("silverscript-dap-test-{}-{}.sil", std::process::id(), unique);
        let path = std::env::temp_dir().join(file_name);
        fs::write(&path, source).expect("failed to write temp script");
        Self { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn equivalent_path_variant(path: &str) -> String {
    let path_buf = PathBuf::from(path);
    let Some(parent) = path_buf.parent() else {
        return path.to_string();
    };
    let Some(parent_name) = parent.file_name() else {
        return path.to_string();
    };
    let Some(file_name) = path_buf.file_name() else {
        return path.to_string();
    };
    parent.join("..").join(parent_name).join(file_name).to_string_lossy().to_string()
}

#[test]
fn launch_stops_on_entry_and_disconnects() {
    let script = TempScript::new(SIMPLE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    let stopped = client.full_launch_sequence(&script_path);

    let reason = stopped.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(reason, "entry");

    client.send_request("threads", serde_json::Value::Null);
    let threads = client.expect_response_success("threads");
    let size = threads.get("body").and_then(|v| v.get("threads")).and_then(|v| v.as_array()).map(|arr| arr.len()).unwrap_or(0);
    assert!(size >= 1);

    client.send_request("disconnect", serde_json::json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn breakpoint_snaps_and_continue_stops() {
    let script = TempScript::new(SIMPLE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 2}, {"line": 6}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 2, "expected two breakpoint responses: {set_bp:#}");

    let first_verified = breakpoints.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(first_verified, "first breakpoint should be verified: {set_bp:#}");

    let first_resolved = breakpoints.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert!(first_resolved >= 4, "expected first breakpoint to snap to executable line >= 4, got {first_resolved}");

    let second_resolved = breakpoints.get(1).and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert_eq!(second_resolved, 6, "expected second breakpoint to stay on line 6: {set_bp:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut terminated_seen = false;
    for _ in 0..12 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.as_deref() == Some("breakpoint"),
        "expected breakpoint stop after continue; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn launch_auto_signs_sig_argument_from_secret_key() {
    let script = TempScript::new(CHECKSIG_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "main",
            "constructorArgs": ["keypair1.pubkey"],
            "args": ["keypair1.secret"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");
    client.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
    client.expect_response_success("setBreakpoints");
    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");
    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut terminated = false;
    for _ in 0..8 {
        let msg = client.read_message();
        if msg.get("type") != Some(&serde_json::Value::String("event".to_string())) {
            continue;
        }
        if msg.get("event").and_then(|v| v.as_str()) == Some("terminated") {
            terminated = true;
            break;
        }
        if msg.get("event").and_then(|v| v.as_str()) == Some("stopped") {
            panic!("expected successful termination, got stop event: {msg:#}");
        }
    }

    assert!(terminated, "expected debug session to terminate successfully after auto-sign");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn launch_resolves_symbolic_pkh_tokens() {
    let script = TempScript::new(P2PKH_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "spend",
            "constructorArgs": ["keypair1.pkh"],
            "args": ["keypair1.pubkey", "keypair1.secret"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");
    client.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
    client.expect_response_success("setBreakpoints");
    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");
    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut terminated = false;
    for _ in 0..8 {
        let msg = client.read_message();
        if msg.get("type") != Some(&serde_json::Value::String("event".to_string())) {
            continue;
        }
        if msg.get("event").and_then(|v| v.as_str()) == Some("terminated") {
            terminated = true;
            break;
        }
        if msg.get("event").and_then(|v| v.as_str()) == Some("stopped") {
            panic!("expected successful termination, got stop event: {msg:#}");
        }
    }

    assert!(terminated, "expected debug session to terminate successfully after resolving keypair<N>.pkh");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_hits_breakpoint_in_second_entrypoint() {
    let script = TempScript::new(MULTIFUNCTION_IF_STATEMENTS_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "timeout",
            "constructorArgs": ["100", "9"],
            "args": ["9"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 26}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 1, "expected one breakpoint response: {set_bp:#}");
    let verified = breakpoints.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(verified, "breakpoint should be verified: {set_bp:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut stopped_line: Option<i64> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());

                client.send_request("stackTrace", json!({"threadId": 1}));
                let stack = client.expect_response_success("stackTrace");
                stopped_line = stack
                    .get("body")
                    .and_then(|v| v.get("stackFrames"))
                    .and_then(|v| v.as_array())
                    .and_then(|frames| frames.first())
                    .and_then(|frame| frame.get("line"))
                    .and_then(|v| v.as_i64());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.as_deref() == Some("breakpoint"),
        "expected breakpoint stop after continue; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );
    assert!(stopped_line.is_some(), "expected stack frame line to be present when stopped");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn run_config_json_resolves_symbolic_identities() {
    let script = TempScript::new(P2PKH_SCRIPT);
    let config = json!({
        "scriptPath": script.path_str(),
        "function": "spend",
        "constructorArgs": ["keypair1.pkh"],
        "args": ["keypair1.pubkey", "keypair1.secret"]
    });

    let output = std::process::Command::new(harness::resolve_debugger_dap_binary())
        .arg("--run-config-json")
        .arg(config.to_string())
        .output()
        .expect("failed to run debugger-dap --run-config-json");

    assert!(
        output.status.success(),
        "run-config-json failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Execution completed successfully."),
        "unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn run_config_json_accepts_identity_tokens() {
    let script = TempScript::new(P2PKH_SCRIPT);
    let config = json!({
        "scriptPath": script.path_str(),
        "function": "spend",
        "constructorArgs": ["identity1.pkh"],
        "args": ["identity1.pubkey", "identity1.secret"]
    });

    let output = std::process::Command::new(harness::resolve_debugger_dap_binary())
        .arg("--run-config-json")
        .arg(config.to_string())
        .output()
        .expect("failed to run debugger-dap --run-config-json");

    assert!(
        output.status.success(),
        "identity token run-config-json failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_config_json_rejects_invalid_identity_tokens() {
    let script = TempScript::new(CHECKSIG_SCRIPT);
    let config = json!({
        "scriptPath": script.path_str(),
        "function": "main",
        "constructorArgs": ["keypair1.pubkey"],
        "args": ["keypair1.invalid"]
    });

    let output = std::process::Command::new(harness::resolve_debugger_dap_binary())
        .arg("--run-config-json")
        .arg(config.to_string())
        .output()
        .expect("failed to run debugger-dap --run-config-json");

    assert!(
        !output.status.success(),
        "expected invalid identity token failure: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid identity token"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn named_launch_arguments_select_breakpoint() {
    let script = TempScript::new(MULTIFUNCTION_IF_STATEMENTS_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "timeout",
            "constructorArgs": {
                "x": 100,
                "y": 9
            },
            "args": {
                "b": 9
            },
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 24}]
        }),
    );
    client.expect_response_success("setBreakpoints");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_line: Option<i64> = None;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string()))
            && msg.get("event").and_then(|v| v.as_str()) == Some("stopped")
        {
            client.send_request("stackTrace", json!({"threadId": 1}));
            let stack = client.expect_response_success("stackTrace");
            stopped_line = stack
                .get("body")
                .and_then(|v| v.get("stackFrames"))
                .and_then(|v| v.as_array())
                .and_then(|frames| frames.first())
                .and_then(|frame| frame.get("line"))
                .and_then(|v| v.as_i64());
            break;
        }
    }

    let stopped_line = stopped_line.expect("expected named launch-config breakpoint stop");
    assert!((18..=27).contains(&stopped_line), "expected breakpoint inside timeout entrypoint, got line {stopped_line}",);

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn scopes_expose_variables_and_stacks() {
    let script = TempScript::new(
        r#"pragma silverscript ^0.1.0;

contract ScopeTest(int threshold) {
    entrypoint function main(int a, int b) {
        int local = a + b;
        require(local > threshold);
    }
}
"#,
    );
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "main",
            "constructorArgs": ["3"],
            "args": ["5", "4"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
    client.expect_response_success("setBreakpoints");
    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");
    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("next", json!({"threadId": 1}));
    client.expect_response_success("next");
    let step_stop = client.expect_event("stopped");
    let step_reason = step_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(step_reason, "step");

    client.send_request("stackTrace", json!({"threadId": 1}));
    let stack = client.expect_response_success("stackTrace");
    let frame_id = stack
        .get("body")
        .and_then(|v| v.get("stackFrames"))
        .and_then(|v| v.as_array())
        .and_then(|frames| frames.first())
        .and_then(|frame| frame.get("id"))
        .and_then(|v| v.as_i64())
        .expect("expected stack frame id");

    client.send_request("scopes", json!({"frameId": frame_id}));
    let scopes = client.expect_response_success("scopes");
    let scope_entries = scopes.get("body").and_then(|v| v.get("scopes")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let scope_names = scope_entries.iter().filter_map(|scope| scope.get("name").and_then(|value| value.as_str())).collect::<Vec<_>>();
    assert!(scope_names.contains(&"Variables"));
    assert!(scope_names.contains(&"Data Stack"));
    assert!(scope_names.contains(&"Alt Stack"));

    let variables_ref = scope_entries
        .iter()
        .find(|scope| scope.get("name").and_then(|value| value.as_str()) == Some("Variables"))
        .and_then(|scope| scope.get("variablesReference"))
        .and_then(|value| value.as_i64())
        .expect("expected variables scope");
    let dstack_ref = scope_entries
        .iter()
        .find(|scope| scope.get("name").and_then(|value| value.as_str()) == Some("Data Stack"))
        .and_then(|scope| scope.get("variablesReference"))
        .and_then(|value| value.as_i64())
        .expect("expected data stack scope");
    let astack_ref = scope_entries
        .iter()
        .find(|scope| scope.get("name").and_then(|value| value.as_str()) == Some("Alt Stack"))
        .and_then(|scope| scope.get("variablesReference"))
        .and_then(|value| value.as_i64())
        .expect("expected alt stack scope");

    client.send_request("variables", json!({"variablesReference": variables_ref}));
    let variables = client.expect_response_success("variables");
    let variable_names = variables
        .get("body")
        .and_then(|v| v.get("variables"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.get("name").and_then(|value| value.as_str()).map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(variable_names, vec!["a".to_string(), "b".to_string(), "local".to_string(), "threshold (const)".to_string()]);

    client.send_request("variables", json!({"variablesReference": dstack_ref}));
    let dstack = client.expect_response_success("variables");
    let dstack_count =
        dstack.get("body").and_then(|v| v.get("variables")).and_then(|v| v.as_array()).map(|items| items.len()).unwrap_or_default();
    assert!(dstack_count >= 2, "expected parameters to be visible on the data stack");

    client.send_request("variables", json!({"variablesReference": astack_ref}));
    let astack = client.expect_response_success("variables");
    let astack_entries = astack.get("body").and_then(|v| v.get("variables")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(astack_entries.len(), 1, "expected empty alt stack placeholder");
    assert_eq!(astack_entries.first().and_then(|entry| entry.get("name")).and_then(|value| value.as_str()), Some("(empty)"));
    assert_eq!(astack_entries.first().and_then(|entry| entry.get("value")).and_then(|value| value.as_str()), Some("<empty>"));

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn data_stack_renders_empty_bytes_without_bare_hex_prefix() {
    let script = TempScript::new(STACK_RENDER_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();
    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "function": "main",
            "constructorArgs": {},
            "args": {
              "flag": false
            },
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    client.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
    client.expect_response_success("setBreakpoints");
    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");
    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    client.expect_event("stopped");

    client.send_request("stackTrace", json!({"threadId": 1}));
    let stack = client.expect_response_success("stackTrace");
    let frame_id = stack
        .get("body")
        .and_then(|v| v.get("stackFrames"))
        .and_then(|v| v.as_array())
        .and_then(|frames| frames.first())
        .and_then(|frame| frame.get("id"))
        .and_then(|v| v.as_i64())
        .expect("expected stack frame id");

    client.send_request("scopes", json!({"frameId": frame_id}));
    let scopes = client.expect_response_success("scopes");
    let dstack_ref = scopes
        .get("body")
        .and_then(|v| v.get("scopes"))
        .and_then(|v| v.as_array())
        .and_then(|entries| entries.iter().find(|scope| scope.get("name").and_then(|value| value.as_str()) == Some("Data Stack")))
        .and_then(|scope| scope.get("variablesReference"))
        .and_then(|value| value.as_i64())
        .expect("expected data stack scope");

    client.send_request("variables", json!({"variablesReference": dstack_ref}));
    let dstack = client.expect_response_success("variables");
    let values = dstack
        .get("body")
        .and_then(|v| v.get("variables"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| item.get("value").and_then(|value| value.as_str()).map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert!(
        values.iter().any(|value| value.starts_with("<empty bytes>")),
        "expected empty bool stack item to describe empty bytes, got {values:?}",
    );
    assert!(values.iter().all(|value| value != "0x"), "unexpected bare hex prefix in stack values: {values:?}",);

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_with_inline_call_and_callee_breakpoints_does_not_bounce_back_to_call_site() {
    let script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let script_path = script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // Request one call-site breakpoint and one callee-body breakpoint.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 11}, {"line": 5}]
        }),
    );
    let set_bp = client.expect_response_success("setBreakpoints");
    let breakpoints = set_bp.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(breakpoints.len(), 2, "expected two breakpoints: {set_bp:#}");
    let call_site_line = breakpoints.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    let callee_line = breakpoints.get(1).and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    let continue_and_capture_line = |client: &mut TestClient| -> Option<i64> {
        client.send_request("continue", json!({"threadId": 1}));
        client.expect_response_success("continue");

        for _ in 0..12 {
            let msg = client.read_message();
            if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
                let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
                if event == "terminated" {
                    return None;
                }
                if event == "stopped" {
                    client.send_request("stackTrace", json!({"threadId": 1}));
                    let stack = client.expect_response_success("stackTrace");
                    return stack
                        .get("body")
                        .and_then(|v| v.get("stackFrames"))
                        .and_then(|v| v.as_array())
                        .and_then(|frames| frames.first())
                        .and_then(|frame| frame.get("line"))
                        .and_then(|v| v.as_i64());
                }
            }
        }
        None
    };

    let first = continue_and_capture_line(&mut client);
    let second = continue_and_capture_line(&mut client);
    let third = continue_and_capture_line(&mut client);

    // Regression check for the user-reported bounce pattern:
    // call-site -> callee -> same call-site.
    let bounced = first == Some(call_site_line) && second == Some(callee_line) && third == Some(call_site_line);
    assert!(
        !bounced,
        "inline breakpoint bounce reproduced: first={first:?}, second={second:?}, third={third:?}, call_site_line={call_site_line}, callee_line={callee_line}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn continue_after_clearing_breakpoints_with_path_variant_does_not_stop() {
    let script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let script_path = script.path_str();
    let variant_path = equivalent_path_variant(&script_path);

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": script_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // First set breakpoints on canonical path.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": script_path},
            "breakpoints": [{"line": 11}, {"line": 5}]
        }),
    );
    let initial_set = client.expect_response_success("setBreakpoints");
    let initial_breakpoints =
        initial_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(initial_breakpoints.len(), 2, "expected two breakpoint responses: {initial_set:#}");

    // Then clear using an equivalent but differently formatted path.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": variant_path},
            "breakpoints": []
        }),
    );
    client.expect_response_success("setBreakpoints");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_reason: Option<String> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                stopped_reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).map(|v| v.to_string());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(
        stopped_reason.is_none() && terminated_seen,
        "expected termination after clearing breakpoints; stopped_reason={stopped_reason:?}, terminated_seen={terminated_seen}"
    );

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}

#[test]
fn breakpoints_for_launch_source_survive_other_source_updates() {
    let launch_script = TempScript::new(INLINE_CALL_BOUNCE_SCRIPT);
    let launch_path = launch_script.path_str();
    let other_script = TempScript::new(SIMPLE_SCRIPT);
    let other_path = other_script.path_str();

    let mut client = TestClient::spawn();

    client.send_request(
        "initialize",
        json!({
            "adapterID": "silverscript",
            "pathFormat": "path",
            "linesStartAt1": true,
            "columnsStartAt1": true,
            "supportsVariableType": true,
            "supportsVariablePaging": false,
            "supportsRunInTerminalRequest": false
        }),
    );
    client.expect_response_success("initialize");
    client.expect_event("initialized");

    client.send_request(
        "launch",
        json!({
            "scriptPath": launch_path,
            "constructorArgs": [],
            "function": "main",
            "args": ["1", "2"],
            "stopOnEntry": true
        }),
    );
    client.expect_response_success("launch");

    // Set one breakpoint in the launched source (call-site line).
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": launch_path},
            "breakpoints": [{"line": 5}]
        }),
    );
    let launch_set = client.expect_response_success("setBreakpoints");
    let launch_bp = launch_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(launch_bp.len(), 1, "expected one launch-source breakpoint response: {launch_set:#}");
    let launch_line = launch_bp.first().and_then(|v| v.get("line")).and_then(|v| v.as_i64()).unwrap_or_default();
    assert!(launch_line > 0, "launch breakpoint should resolve to executable line: {launch_set:#}");

    // Simulate a client sending setBreakpoints for a different source.
    // It should not clear or override launch-source breakpoints.
    client.send_request(
        "setBreakpoints",
        json!({
            "source": {"path": other_path},
            "breakpoints": [{"line": 5}]
        }),
    );
    let other_set = client.expect_response_success("setBreakpoints");
    let other_bp = other_set.get("body").and_then(|v| v.get("breakpoints")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(other_bp.len(), 1, "expected one foreign-source breakpoint response: {other_set:#}");
    let other_verified = other_bp.first().and_then(|v| v.get("verified")).and_then(|v| v.as_bool()).unwrap_or(true);
    assert!(!other_verified, "foreign-source breakpoint should be unverified: {other_set:#}");

    client.send_request("setExceptionBreakpoints", json!({"filters": []}));
    client.expect_response_success("setExceptionBreakpoints");

    client.send_request("configurationDone", serde_json::Value::Null);
    client.expect_response_success("configurationDone");
    let entry_stop = client.expect_event("stopped");
    let entry_reason = entry_stop.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(entry_reason, "entry");

    client.send_request("continue", json!({"threadId": 1}));
    client.expect_response_success("continue");

    let mut stopped_line: Option<i64> = None;
    let mut terminated_seen = false;
    for _ in 0..16 {
        let msg = client.read_message();
        if msg.get("type") == Some(&serde_json::Value::String("event".to_string())) {
            let event = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
            if event == "stopped" {
                let reason = msg.get("body").and_then(|v| v.get("reason")).and_then(|v| v.as_str()).unwrap_or_default();
                assert_eq!(reason, "breakpoint", "expected breakpoint stop event: {msg:#}");

                client.send_request("stackTrace", json!({"threadId": 1}));
                let stack = client.expect_response_success("stackTrace");
                stopped_line = stack
                    .get("body")
                    .and_then(|v| v.get("stackFrames"))
                    .and_then(|v| v.as_array())
                    .and_then(|frames| frames.first())
                    .and_then(|frame| frame.get("line"))
                    .and_then(|v| v.as_i64());
                break;
            }
            if event == "terminated" {
                terminated_seen = true;
                break;
            }
        }
    }

    assert!(!terminated_seen, "launch-source breakpoint should still be active after foreign-source update");
    assert_eq!(stopped_line, Some(launch_line), "expected stop on launch-source breakpoint line after foreign-source update");

    client.send_request("disconnect", json!({}));
    client.expect_response_success("disconnect");
}
