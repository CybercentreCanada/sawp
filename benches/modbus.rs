use criterion::{black_box, criterion_group, criterion_main, Criterion};

// TODO: benchmark modbus protocol parsing
fn modbus(n: u64) -> bool {
    n == 20
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("modbus", |b| b.iter(|| modbus(black_box(20))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
