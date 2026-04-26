use optimized_vdf::{Proof, Wesolowski};
use std::time::Instant;

fn main() {
    let difficulties = parse_difficulties();
    let payload = b"benchmark-payload";
    let vdf = benchmark_vdf();

    println!("Rust Wesolowski VDF benchmark");
    println!("BenchmarkProve");
    let mut proofs = Vec::with_capacity(difficulties.len());
    for difficulty in &difficulties {
        let start = Instant::now();
        let proof = vdf
            .prove(payload, *difficulty)
            .unwrap_or_else(|err| panic!("prove difficulty={difficulty}: {err:?}"));
        let elapsed = start.elapsed();
        println!(
            "  difficulty={} iterations=1 total_ms={:.3} avg_ms={:.3}",
            difficulty,
            elapsed.as_secs_f64() * 1000.0,
            elapsed.as_secs_f64() * 1000.0
        );

        verify_once(&vdf, payload, *difficulty, &proof);
        proofs.push(proof);
    }

    println!();
    println!("BenchmarkVerify");
    for (difficulty, proof) in difficulties.iter().zip(proofs.iter()) {
        let start = Instant::now();
        verify_once(&vdf, payload, *difficulty, proof);
        let elapsed = start.elapsed();
        println!(
            "  difficulty={} iterations=1 total_ms={:.3} avg_ms={:.3}",
            difficulty,
            elapsed.as_secs_f64() * 1000.0,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

fn parse_difficulties() -> Vec<i64> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return vec![500, 1000, 10_000, 1_000_000];
    }

    args.iter()
        .map(|arg| {
            let value = arg
                .parse::<i64>()
                .unwrap_or_else(|err| panic!("invalid difficulty {arg:?}: {err}"));
            if value < 0 {
                panic!("difficulty must be non-negative, got {value}");
            }
            value
        })
        .collect()
}

fn benchmark_vdf() -> Wesolowski {
    Wesolowski::with_modulus(benchmark_modulus(), 128).expect("benchmark modulus")
}

fn benchmark_modulus() -> num_bigint::BigUint {
    let p = (num_bigint::BigUint::from(1u8) << 521usize) - num_bigint::BigUint::from(1u8);
    let q = (num_bigint::BigUint::from(1u8) << 607usize) - num_bigint::BigUint::from(1u8);
    p * q
}

fn verify_once(vdf: &Wesolowski, payload: &[u8], difficulty: i64, proof: &Proof) {
    let ok = vdf
        .verify(payload, difficulty, proof)
        .unwrap_or_else(|err| panic!("verify difficulty={difficulty}: {err:?}"));
    if !ok {
        panic!("verification failed at difficulty={difficulty}");
    }
}
