mod common;

use silverscript_lang::compiler::compile_to_sil_abi_artifact;

use common::encode_entry_sig_script;

#[test]
fn tutorial_rust_programmatic_compilation_example() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract MyContract(int x) {
            entry spend(int y) {
                require(y > x);
            }
        }
    "#;

    let artifact = compile_to_sil_abi_artifact(source, &[100.into()]).expect("programmatic compilation example should compile");
    let contract = artifact.contract("MyContract").expect("contract exists");

    assert!(!contract.compiled.bytecode.is_empty());
    assert_eq!(contract.entries.len(), 1);
    assert_eq!(contract.entries[0].name, "spend");
}

#[test]
fn tutorial_rust_build_sigscript_multiple_entrypoints_example() {
    let source = r#"
        pragma silverscript ^0.1.0;

        contract TransferWithTimeout(pubkey sender, pubkey recipient, temporal timeout) {
            entry transfer(sig recipientSig) {
                require(checkSig(recipientSig, recipient));
            }

            entry reclaim(sig senderSig) {
                require(checkSig(senderSig, sender));
                require(tx.time >= timeout);
            }
        }
    "#;

    let sender_pk = vec![3u8; 32];
    let recipient_pk = vec![4u8; 32];
    let timeout = 1_640_000_000_000i64;
    let artifact = compile_to_sil_abi_artifact(source, &[sender_pk.into(), recipient_pk.into(), timeout.into()])
        .expect("multi-entrypoint example should compile");

    let sig = vec![5u8; 65];
    let transfer_sigscript =
        encode_entry_sig_script(&artifact, "transfer", &[sig.clone().into()]).expect("transfer sigscript should build");
    let reclaim_sigscript = encode_entry_sig_script(&artifact, "reclaim", &[sig.into()]).expect("reclaim sigscript should build");

    assert!(!transfer_sigscript.is_empty());
    assert!(!reclaim_sigscript.is_empty());
    assert_ne!(transfer_sigscript, reclaim_sigscript, "dispatch tags should differ per entrypoint");
}
