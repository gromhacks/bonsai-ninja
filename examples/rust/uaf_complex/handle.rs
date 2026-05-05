pub struct Handle {
    pub id: usize,
    pub label: String,
}

impl Handle {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            label: String::new(),
        }
    }

    pub fn read(&self) -> usize {
        self.id
    }
}
