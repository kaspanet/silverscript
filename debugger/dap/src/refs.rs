use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ScopeKind {
    Variables,
    DataStack,
    AltStack,
}

#[derive(Debug, Clone)]
pub enum RefTarget {
    Scope { kind: ScopeKind, sequence: u32, frame_token: u32 },
}

#[derive(Debug, Default)]
pub struct RefAllocator {
    next_id: i64,
    refs: HashMap<i64, RefTarget>,
}

impl RefAllocator {
    pub fn new() -> Self {
        Self { next_id: 1, refs: HashMap::new() }
    }

    pub fn reset(&mut self) {
        self.next_id = 1;
        self.refs.clear();
    }

    pub fn alloc(&mut self, target: RefTarget) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        self.refs.insert(id, target);
        id
    }

    pub fn get(&self, id: i64) -> Option<&RefTarget> {
        self.refs.get(&id)
    }
}
