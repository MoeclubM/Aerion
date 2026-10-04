mod protocol_performance {
    use super::*;
    use std::hint::black_box;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/performance/support.rs"
        ));
    }

    #[test]
    #[ignore = "release benchmark run by protocol-performance workflow"]
    fn sudoku_appearance() -> Result<()> {
        let table = Table::new("performance-user", "prefer_ascii", "")?;
        for packed in [false, true] {
            for padding in [0, 50] {
                for size in [64, 1024, 16384] {
                    let plain = (0..size).map(|index| index as u8).collect::<Vec<_>>();
                    support::measure(
                        &format!("sudoku-encode-{packed}-{padding}-{size}"),
                        size,
                        || {
                            black_box(
                                table::encode(&table, true, packed, black_box(&plain), padding)
                                    .unwrap(),
                            );
                        },
                    );
                    let wire = table::encode(&table, true, packed, &plain, padding)?;
                    let mut decoder = table::Decoder::new(table.clone(), true, packed);
                    assert_eq!(decoder.feed(&wire)?, plain);
                    support::measure(
                        &format!("sudoku-decode-{packed}-{padding}-{size}"),
                        size,
                        || {
                            assert_eq!(
                                black_box(decoder.feed(black_box(&wire)).unwrap()).len(),
                                size
                            );
                        },
                    );
                }
            }
        }
        Ok(())
    }
}
