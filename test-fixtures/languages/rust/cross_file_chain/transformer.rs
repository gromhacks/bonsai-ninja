mod executor;

pub fn transform_and_forward(value: &str) {
    let upper = value.to_uppercase();
    executor::execute(&upper);
}
