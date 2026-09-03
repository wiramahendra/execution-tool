use marshall::{destination::host_of, validate_destination};

fn main() {
    // libFuzzer entry: cargo fuzz run fuzz_destination
    // For `cargo run --bin fuzz_destination` we run a simple corpus.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let input = args[1].as_str();
        let _ = host_of(input);
        let _ = validate_destination(input);
        return;
    }
    // Simple inline corpus smoke
    let corpus = [
        "https://example.com/",
        "https://169.254.169.254/",
        "https://[::ffff:169.254.169.254]/",
        "https://example.com@169.254.169.254/",
        "https://example.com/\r\nHost: evil",
        "https://example.com:22/",
        "file:///etc/passwd",
        "http://127.0.0.1:8080/",
        "https://[2002:a9fe:a9fe::1]/",
        "https://[fd00::1]/",
    ];
    for url in corpus {
        let _ = host_of(url);
        let _ = validate_destination(url);
    }
    println!("fuzz corpus ok: {}", corpus.len());
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corpus_does_not_panic() {
        main();
    }
}
