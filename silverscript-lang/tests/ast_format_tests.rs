use silverscript_lang::ast::{format_contract_ast, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};

fn assert_compiled_formatted_contract_preserves_ast(source: &str, options: CompileOptions) {
    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let compiled = compile_contract(&formatted, &[], options).expect("formatted contract compiles");

    assert_eq!(
        serde_json::to_value(&compiled.ast).expect("serialize compiled ast"),
        serde_json::to_value(&ast).expect("serialize original ast")
    );
}

#[test]
fn formats_contract_ast_into_canonical_silverscript() {
    let source = r#"
contract Pretty(sig s, pubkey pk){
int constant LIMIT=3;
byte[2] seed=0x1234;
entrypoint function main(int x):(int, int){
int total=(x+LIMIT)*2;
int[] values=[1,2,3];
values.push(total);
if(x>0&&x<LIMIT){
require(checkSig(s,pk), "ok");
}else{
require(tx.outputs[0].value>=total);
}
return(total, values[0]);
}
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);

    let expected = r#"contract Pretty(sig s, pubkey pk) {
    int constant LIMIT = 3;

    byte[2] seed = 0x1234;

    entrypoint function main(int x): (int, int) {
        int total = (x + LIMIT) * 2;
        int[] values = [1, 2, 3];
        values.push(total);
        if (x > 0 && x < LIMIT) {
            require(checkSig(s, pk), "ok");
        } else {
            require(tx.outputs[0].value >= total);
        }
        return(total, values[0]);
    }
}
"#;

    assert_eq!(formatted, expected);
}

#[test]
fn formatted_contracts_parse_back_to_same_canonical_source() {
    let source = r#"
contract Advanced(int limit, pubkey owner) {
    int balance = 10;

    function compute(int x): (int, int) {
        int left = x + balance;
        int right = left * 2;
        return(left, right);
    }

    entrypoint function main() {
        (int left, int right) = compute(1 + 2 * 3);
        {balance: int current} = readState();
        int[] values = [1, 2];
        values.push(current);
        byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);
        validateOutputState(0, {balance: current});
        for (i, 0, limit, limit) {
            console.log("loop", i);
        }
        balance = current;
        require(this.age >= 10, "age");
        return(tail.split(1)[1]);
    }
}
"#;

    let ast = parse_contract_ast(source).expect("parse succeeds");
    let formatted = format_contract_ast(&ast);
    let reparsed = parse_contract_ast(&formatted).expect("formatted output parses");
    let reformatted = format_contract_ast(&reparsed);

    assert_eq!(reformatted, formatted);
    assert!(formatted.contains("{balance: int current} = readState();"));
    assert!(formatted.contains("byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);"));
    assert!(formatted.contains("return(tail.split(1)[1]);"));
}

#[test]
fn compiled_formatted_contract_preserves_exact_ast_for_basic_contract() {
    let source = r#"contract ExactBasic() {
    int constant LIMIT = 3;

    int balance = 10;

    function compute(int x): (int, int) {
        int left = x + balance;
        int right = left * LIMIT;
        return(left, right);
    }

    entrypoint function main() {
        int input = 1 + 2;
        (int left, int right) = compute(input);
        require(left < right, "ordered");
        console.log("pair", LIMIT);
    }
}
"#;

    assert_compiled_formatted_contract_preserves_ast(source, CompileOptions::default());
}

#[test]
fn compiled_formatted_contract_preserves_exact_ast_with_state_and_return() {
    let source = r#"contract ExactState() {
    int amount = 7;

    entrypoint function main(): (byte[]) {
        {amount: int current} = readInputState(this.activeInputIndex);
        byte[] tail = this.activeScriptPubKey.slice(1, this.activeScriptPubKey.length);
        validateOutputState(0, {amount: current});
        require(this.age >= 10, "age");
        return(tail.split(1)[1]);
    }
}
"#;

    assert_compiled_formatted_contract_preserves_ast(source, CompileOptions { allow_entrypoint_return: true, ..CompileOptions::default() });
}
