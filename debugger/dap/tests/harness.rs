use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TestClient {
    child: Child,
    stdin: ChildStdin,
    messages: mpsc::Receiver<Value>,
    stderr_log: Arc<Mutex<String>>,
    seq: i64,
}

impl TestClient {
    pub fn spawn() -> Self {
        let binary = resolve_debugger_dap_binary();
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn debugger-dap binary at {:?}: {err}", binary));

        let stdin = child.stdin.take().expect("missing child stdin");
        let stdout = child.stdout.take().expect("missing child stdout");
        let stderr = child.stderr.take().expect("missing child stderr");
        let stderr_log = Arc::new(Mutex::new(String::new()));
        let stderr_sink = Arc::clone(&stderr_log);
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || read_stdout_messages(stdout, tx));
        thread::spawn(move || capture_stderr(stderr, stderr_sink));

        Self { child, stdin, messages: rx, stderr_log, seq: 1 }
    }

    pub fn send_request(&mut self, command: &str, arguments: Value) {
        let message = json!({
            "seq": self.seq,
            "type": "request",
            "command": command,
            "arguments": arguments,
        });
        self.seq += 1;
        self.write_message(&message);
    }

    pub fn read_message(&mut self) -> Value {
        match self.messages.recv_timeout(MESSAGE_TIMEOUT) {
            Ok(message) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let stderr = self.stderr_snapshot();
                panic!("timed out waiting for DAP message after {:?}; stderr: {}", MESSAGE_TIMEOUT, stderr);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let stderr = self.stderr_snapshot();
                panic!("adapter closed message channel unexpectedly; stderr: {}", stderr);
            }
        }
    }

    pub fn expect_response_success(&mut self, command: &str) -> Value {
        loop {
            let msg = self.read_message();
            if msg.get("type") == Some(&Value::String("response".to_string())) {
                let actual = msg.get("command").and_then(|v| v.as_str()).unwrap_or_default();
                if actual == command {
                    let success = msg.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    assert!(success, "expected successful response for {command}, got {msg:#}");
                    return msg;
                }
            }
        }
    }

    pub fn expect_event(&mut self, event: &str) -> Value {
        loop {
            let msg = self.read_message();
            if msg.get("type") == Some(&Value::String("event".to_string())) {
                let actual = msg.get("event").and_then(|v| v.as_str()).unwrap_or_default();
                if actual == event {
                    return msg;
                }
            }
        }
    }

    pub fn full_launch_sequence(&mut self, script_path: &str) -> Value {
        self.send_request(
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
        self.expect_response_success("initialize");
        self.expect_event("initialized");

        self.send_request(
            "launch",
            json!({
                "scriptPath": script_path,
                "stopOnEntry": true
            }),
        );
        self.expect_response_success("launch");

        self.send_request("setBreakpoints", json!({"source": {"path": script_path}, "breakpoints": []}));
        self.expect_response_success("setBreakpoints");

        self.send_request("setExceptionBreakpoints", json!({"filters": []}));
        self.expect_response_success("setExceptionBreakpoints");

        self.send_request("configurationDone", Value::Null);
        self.expect_response_success("configurationDone");
        self.expect_event("stopped")
    }

    fn write_message(&mut self, payload: &Value) {
        let encoded = serde_json::to_vec(payload).expect("failed to serialize request");
        let header = format!("Content-Length: {}\r\n\r\n", encoded.len());
        self.stdin.write_all(header.as_bytes()).expect("failed to write header");
        self.stdin.write_all(&encoded).expect("failed to write body");
        self.stdin.flush().expect("failed to flush request");
    }

    fn stderr_snapshot(&self) -> String {
        self.stderr_log.lock().map(|value| value.trim().to_string()).unwrap_or_else(|_| "<stderr unavailable>".to_string())
    }
}

fn read_stdout_messages(stdout: impl Read, tx: mpsc::Sender<Value>) {
    let mut stdout = BufReader::new(stdout);
    loop {
        let mut content_length: usize = 0;
        let mut raw_headers: Vec<String> = Vec::new();
        loop {
            let mut line = String::new();
            let bytes = match stdout.read_line(&mut line) {
                Ok(bytes) => bytes,
                Err(_) => return,
            };
            if bytes == 0 {
                return;
            }
            raw_headers.push(line.clone());
            if line.trim().is_empty() {
                if content_length == 0 {
                    continue;
                }
                break;
            }
            if let Some(rest) = line.trim().strip_prefix("Content-Length: ") {
                content_length = rest.trim().parse::<usize>().expect("invalid Content-Length header");
            }
        }

        assert!(content_length > 0, "received DAP message with zero Content-Length; headers: {:?}", raw_headers);

        let mut body = vec![0u8; content_length];
        if stdout.read_exact(&mut body).is_err() {
            return;
        }

        let payload = serde_json::from_slice::<Value>(&body).expect("invalid JSON payload");
        if tx.send(payload).is_err() {
            return;
        }
    }
}

fn capture_stderr(stderr: impl Read, sink: Arc<Mutex<String>>) {
    let mut stderr = BufReader::new(stderr);
    let mut buffer = String::new();
    let _ = stderr.read_to_string(&mut buffer);
    if let Ok(mut stored) = sink.lock() {
        *stored = buffer;
    }
}

pub fn resolve_debugger_dap_binary() -> PathBuf {
    let env_candidates =
        ["CARGO_BIN_EXE_debugger-dap", "CARGO_BIN_EXE_debugger_dap"].iter().filter_map(|key| std::env::var_os(key).map(PathBuf::from));
    for candidate in env_candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let exe = format!("debugger-dap{}", std::env::consts::EXE_SUFFIX);
    let profiles = if cfg!(debug_assertions) { ["debug", "release"] } else { ["release", "debug"] };

    for profile in profiles {
        let candidate = target_dir.join(profile).join(&exe);
        if candidate.exists() {
            return candidate;
        }
    }

    panic!(
        "could not locate debugger-dap binary via env vars or target dir {}; looked for {} in debug/release",
        target_dir.display(),
        exe
    );
}

impl Drop for TestClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
