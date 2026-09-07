use axum::body::Bytes;
pub async fn parse(input: Bytes) {
    let _value: serde_pickle::Value = serde_pickle::from_slice(&input, Default::default()).unwrap();
}
