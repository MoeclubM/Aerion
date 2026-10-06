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
    fn mieru_cipher() {
        for implicit in [false, true] {
            for size in [64, 1024, 16384] {
                let plain = vec![0x42; size];
                let mut cipher = MieruCipher::new([0x11; KEY_LEN], implicit, "alice".into(), None);
                support::measure(&format!("mieru-encrypt-{implicit}-{size}"), size, || {
                    black_box(cipher.encrypt(black_box(&plain)).unwrap());
                });
                let nonce = [0x22; NONCE_LEN];
                let encrypted = cipher.encrypt_with_nonce(&plain, &nonce).unwrap();
                support::measure(&format!("mieru-decrypt-{implicit}-{size}"), size, || {
                    black_box(
                        cipher
                            .decrypt_with_nonce(black_box(&encrypted), black_box(&nonce))
                            .unwrap(),
                    );
                });
            }
        }
    }
}
