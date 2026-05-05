mod transformer;

pub fn run_pipeline(payload: &str) {
    let wrapped = format!("[{}]", payload);
    transformer::transform_and_forward(&wrapped);
}
