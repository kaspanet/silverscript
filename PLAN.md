# Rebase Conflict Resolution Plan (Span-first AST + Upstream State/Fields)

No implementation changes are made in this step. This file is the proposed resolution strategy.

## Goal
Keep the architecture introduced in `d85a801` as canonical (`Expr<'i> { kind: ExprKind<'i>, span: Span<'i> }`, lifetime-aware AST, span-aware errors), while integrating upstream language/compiler features (contract fields, state bindings/object, richer array typing behavior, state validation/read helpers).

## Canonical decisions
- Keep `Expr<'i>` + `ExprKind<'i>` + `Span<'i>` as the core expression model.
- Keep span-aware diagnostics (`CompilerError::with_span`) as the standard error path.
- Reintroduce upstream-only features into that architecture, not by downgrading AST back to direct enum expressions.
- Resolve semantically from full file context (`:2` vs `:3`), not conflict-hunk-by-conflict-hunk.

## Architectural delta

### Upstream (`:2`) behavior to preserve
- Contract-level fields and compilation prolog (`ContractFieldAst`, `contract.fields`, `compile_contract_fields`).
- State binding/object flow.
- `Statement::StateFunctionCallAssign`.
- `readInputState(...)` and `validateOutputState(...)` compile paths.
- Structured array typing helpers (`TypeRef`/`TypeBase`/`ArrayDim` and related size/inference helpers), especially for fixed/dynamic/constant-sized arrays.

### Span branch (`:3`) behavior to preserve
- Lifetime-bearing AST (`ContractAst<'i>`, `FunctionAst<'i>`, `Expr<'i>`, `Statement<'i>`).
- Span fields on AST nodes and subcomponents (`name_span`, `type_span`, `body_span`, etc.).
- Span-aware error propagation and contextual wrapping.
- `ExprKind`-based compiler pipeline and helper constructors (`Expr::int`, `Expr::bytes`, ...).

### Cross-file drift that must be reconciled
- Grammar currently uses `this.activeScriptPubKey`, while span parser maps `this.activeBytecode`.
- Span parser references `Rule::Bytes`, but grammar does not define it.
- Upstream logic still assumes direct `Expr` variants (`Expr::Int`, `Expr::Byte`, etc.), while canonical model is `ExprKind`.

## Proposed merge order

### Phase 1: AST shape (`silverscript-lang/src/ast.rs`)
- Start from `:3` AST architecture as baseline.
- Reintroduce missing upstream nodes with spans/lifetimes:
- `ContractAst<'i>.fields`.
- `ContractFieldAst<'i>`.
- `StateBindingAst<'i>`.
- `Statement::StateFunctionCallAssign { ... span fields ... }`.
- `ExprKind::StateObject(...)` plus a state-entry struct carrying field/value spans.
- Keep `TypeRef`/`TypeBase`/`ArrayDim` helpers (or equivalent parsing helper surface) for array-dimension semantics.
- Update `rewrite_expr_kind_tags` so new expression kinds serialize consistently in AST JSON snapshots.

Checkpoint A
- `ast.rs` compiles standalone.
- No conflict markers remain.
- No duplicate/competing AST model remains.

### Phase 2: Parser integration (`silverscript-lang/src/ast.rs` parser section)
- Re-enable parsing of upstream constructs using span-aware builders:
- `contract_field_definition` in `parse_contract_definition`.
- `state_function_call_assignment` and `state_typed_binding` in `parse_statement`.
- `state_object` and `state_entry` in `parse_primary`/helper parser.
- Ensure all new nodes get full span coverage (`span`, `type_span`, `name_span`, field spans, message spans).
- Reconcile nullary token mapping with grammar (`activeScriptPubKey` at minimum; optional alias for backward compatibility).
- Remove stale parser branches depending on non-existent grammar rules (`Rule::Bytes`).

Checkpoint B
- Parsing supports upstream syntax and still populates spans end-to-end.

### Phase 3: Compiler behavior merge (`silverscript-lang/src/compiler.rs`)
- Use `:3` compiler architecture as base (span-aware `ExprKind` pipeline, lifetimes, error spans).
- Reintroduce upstream behavior modules and adapt them to `ExprKind`:
- `compile_contract_fields` and contract-field prolog injection.
- `compile_read_input_state_statement`.
- `compile_validate_output_state_statement`.
- Statement dispatch branch for `StateFunctionCallAssign`.
- Port/restore typed array helpers required by those features (size inference, assignability, constant array dims).
- Translate all old direct-`Expr` matches to `ExprKind` (`Expr::Byte` -> `ExprKind::Bytes(len=1)` semantics).
- Keep span-aware error attachment in all new branches (`stmt.span()`, sub-spans where available).
- Keep stage3 expression capabilities intact (cast/slice/unary suffix/introspection shape).

Checkpoint C
- Compiler contains both upstream state/field functionality and span-aware diagnostics.

### Phase 4: Tests merge (`silverscript-lang/tests/compiler_tests.rs` + span tests)
- Resolve test conflicts by preserving both intent sets.
- Keep span-architecture constructor style (`Expr::int`, `Expr::bytes`, etc.) where applicable.
- Reintroduce upstream state/field behavior tests (`readInputState`, `validateOutputState`, field-prolog/script-size interactions).
- Add/adjust span coverage tests for newly restored AST nodes (contract fields/state bindings/state object).
- Update AST JSON fixtures if expression-kind tag rewriting changes serialized shape.

Checkpoint D
- Test suite covers both span model and upstream state/array features.

### Phase 5: Validation and rebase completion
- Verify no conflict markers remain.
- Run formatting and build/tests for `silverscript-lang`.
- Run targeted tests first (compiler/state/span), then full package tests.
- Continue rebase only after green checks.

## Validation matrix
- Parse-only: contract with fields + state object + state assignment parses.
- Span coverage: new nodes carry correct spans.
- Compile behavior: `readInputState` and `validateOutputState` compile and execute expected script semantics.
- Type behavior: constructor arg checks and array-dimension rules still hold under `ExprKind` model.
- Script-size behavior: stabilization still converges when field prolog is active.
- Regression: existing span tests and non-state compiler tests remain green.

## Practical implementation strategy
- For each conflicted file, reconstruct from canonical baseline (`:3`) then port upstream features intentionally.
- Do not accept full `HEAD`/`THEIRS` blocks blindly; port semantics, not syntax.
- Compile after each phase to catch structural drift early.
