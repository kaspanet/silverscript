use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[test]
fn tutorial_rust_programmatic_compilation_example() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract MyContract(int x) {
            entrypoint function spend(int y) {
                require(y > x);
            }
        }
    "#;

    let constructor_args = vec![Expr::Int(100)];
    let compiled = compile_contract(source, &constructor_args, CompileOptions::default())
        .expect("programmatic compilation example should compile");

    assert_eq!(compiled.contract_name, "MyContract");
    assert!(!compiled.script.is_empty());
    assert_eq!(compiled.abi.len(), 1);
    assert_eq!(compiled.abi[0].name, "spend");
}

#[test]
fn tutorial_rust_build_sigscript_multiple_entrypoints_example() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract TransferWithTimeout(pubkey sender, pubkey recipient, int timeout) {
            entrypoint function transfer(sig recipientSig) {
                require(checkSig(recipientSig, recipient));
            }

            entrypoint function reclaim(sig senderSig) {
                require(checkSig(senderSig, sender));
                require(tx.time >= timeout);
            }
        }
    "#;

    let sender_pk = vec![3u8; 32];
    let recipient_pk = vec![4u8; 32];
    let timeout = 1_640_000_000i64;
    let compiled = compile_contract(source, &[sender_pk.into(), recipient_pk.into(), timeout.into()], CompileOptions::default())
        .expect("multi-entrypoint example should compile");

    assert!(!compiled.without_selector, "multiple entrypoints should require a selector");

    let sig = vec![5u8; 64];
    let transfer_sigscript = compiled.build_sig_script("transfer", vec![sig.clone().into()]).expect("transfer sigscript should build");
    let reclaim_sigscript = compiled.build_sig_script("reclaim", vec![sig.into()]).expect("reclaim sigscript should build");

    assert!(!transfer_sigscript.is_empty());
    assert!(!reclaim_sigscript.is_empty());
    assert_ne!(transfer_sigscript, reclaim_sigscript, "selectors should differ per entrypoint");
}
