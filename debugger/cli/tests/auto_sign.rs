use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn cli_debugger_auto_signs_sig_args_from_secret_keys() {
    let cli = env!("CARGO_BIN_EXE_cli-debugger");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("silverscript-auto-sign-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("auto-sign.sil");
    let tests = dir.join("auto-sign.test.json");

    fs::write(
        &source,
        r#"pragma silverscript ^0.1.0;

contract AutoSigArg(pubkey owner) {
    entrypoint function spend(sig s) {
        require(checkSig(s, owner));
    }
}
"#,
    )
    .unwrap();

    fs::write(
        &tests,
        r#"{
  "tests": [
    {
      "name": "secret_key_arg_materializes_valid_schnorr_signature",
      "function": "spend",
      "constructor_args": ["0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
      "args": ["0x0000000000000000000000000000000000000000000000000000000000000001"],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [{ "utxo_value": 100000 }],
        "outputs": [{ "value": 99000, "p2pk_pubkey": "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" }]
      }
    },
    {
      "name": "wrong_secret_key_fails_checksig",
      "function": "spend",
      "constructor_args": ["0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
      "args": ["0x0000000000000000000000000000000000000000000000000000000000000002"],
      "expect": "fail",
      "tx": {
        "active_input_index": 0,
        "inputs": [{ "utxo_value": 100000 }],
        "outputs": [{ "value": 99000, "p2pk_pubkey": "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" }]
      }
    }
  ]
}
"#,
    )
    .unwrap();

    let output = Command::new(cli)
        .arg(&source)
        .arg("--run-all")
        .arg("--test-file")
        .arg(&tests)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("2 tests: 2 passed, 0 failed"), "stdout:\n{stdout}\nstderr:\n{stderr}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_debugger_auto_signs_sig_args_after_covenant_prefix_args() {
    let cli = env!("CARGO_BIN_EXE_cli-debugger");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("silverscript-auto-sign-covenant-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("auto-sign-covenant.sil");
    let tests = dir.join("auto-sign-covenant.test.json");

    fs::write(
        &source,
        r#"pragma silverscript ^0.1.0;

contract AutoSigCovenant(pubkey owner) {
    int status = 0;

    #[covenant.singleton(mode = transition)]
    function step(State prev_state, sig s) : (State) {
        require(prev_state.status == 0);
        require(checkSig(s, owner));
        return(prev_state);
    }
}
"#,
    )
    .unwrap();

    fs::write(
        &tests,
        r#"{
  "tests": [
    {
      "name": "covenant_sig_secret_key_arg_is_offset_past_synthesized_state",
      "function": "step",
      "constructor_args": ["0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
      "args": ["0x0000000000000000000000000000000000000000000000000000000000000001"],
      "expect": "pass",
      "tx": {
        "active_input_index": 0,
        "inputs": [
          {
            "utxo_value": 100000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "status": 0 }
          }
        ],
        "outputs": [
          {
            "value": 99000,
            "covenant_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "state": { "status": 0 }
          }
        ]
      }
    }
  ]
}
"#,
    )
    .unwrap();

    let output = Command::new(cli)
        .arg(&source)
        .arg("--run-all")
        .arg("--test-file")
        .arg(&tests)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("1 tests: 1 passed, 0 failed"), "stdout:\n{stdout}\nstderr:\n{stderr}");

    let _ = fs::remove_dir_all(&dir);
}
