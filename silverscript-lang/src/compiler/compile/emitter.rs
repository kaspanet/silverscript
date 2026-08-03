use super::*;

/// Emits bytecode while tracking the number of temporary stack values.
///
/// Named values are tracked separately by `StackBindings`; this type only
/// accounts for values produced and consumed while compiling an expression or
/// another self-contained bytecode fragment.
pub(super) struct ScriptEmitter<'a> {
    builder: &'a mut ScriptBuilder,
    stack_depth: i64,
}

impl<'a> ScriptEmitter<'a> {
    pub(super) fn new(builder: &'a mut ScriptBuilder, stack_depth: i64) -> Self {
        Self { builder, stack_depth }
    }

    pub(super) fn stack_depth(&self) -> i64 {
        self.stack_depth
    }

    pub(super) fn set_stack_depth(&mut self, stack_depth: i64) {
        self.stack_depth = stack_depth;
    }

    pub(super) fn push_int(&mut self, value: i64) -> Result<(), CompilerError> {
        self.builder.add_i64(value)?;
        self.stack_depth += 1;
        Ok(())
    }

    pub(super) fn push_data(&mut self, value: &[u8]) -> Result<(), CompilerError> {
        self.builder.add_data_with_push_opcode(value)?;
        self.stack_depth += 1;
        Ok(())
    }

    pub(super) fn emit_op(&mut self, opcode: u8, stack_delta: i64) -> Result<(), CompilerError> {
        self.builder.add_op(opcode)?;
        self.stack_depth += stack_delta;
        Ok(())
    }

    pub(super) fn parts(&mut self) -> (&mut ScriptBuilder, &mut i64) {
        (self.builder, &mut self.stack_depth)
    }
}
