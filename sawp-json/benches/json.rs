use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sawp::parser::Parse;
use sawp_json::{Json, Message};
use serde_json::json;

const SAMPLE_JSON: &[u8] = br#"{
    "object": {
        "nested": [1, 2, 3]
    },
    "bool_true": true,
    "bool_false": false,
    "null": null,
    "string": "test",
    "number": 123,
    "list": ["1"]
}"#;

fn parse_json<'a>(json: &'a Json, input: &'a [u8]) -> (&'a [u8], Option<Message>) {
    json.parse(input).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let expected = json!({
        "object": {
            "nested": [1, 2, 3]
        },
        "bool_true": true,
        "bool_false": false,
        "null": null,
        "string": "test",
        "number": 123,
        "list": ["1"]
    });

    // Assert output is what we expect before benchmarking
    assert_eq!(
        ([].as_ref(), Some(Message::new(expected))),
        parse_json(&Json {}, SAMPLE_JSON)
    );

    c.bench_function("json", |b| {
        b.iter(|| parse_json(&Json {}, black_box(SAMPLE_JSON)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
