use super::*;

#[test]
fn encrypts_and_decrypts_tls13_application_record() -> Result<()> {
    let suite = CipherSuite::from_id(0x1301)?;
    let secret = vec![0x11; 32];
    let mut writer = RecordCipher::new(suite, &secret)?;
    let mut reader = RecordCipher::new(suite, &secret)?;
    let record = writer.encrypt_record(TLS_CONTENT_TYPE_APPLICATION_DATA, b"hello")?;
    let mut payload = record[TLS_RECORD_HEADER_LEN..].to_vec();
    let content_type = reader.decrypt_record_in_place(record[0], &mut payload)?;
    assert_eq!(content_type, TLS_CONTENT_TYPE_APPLICATION_DATA);
    assert_eq!(payload, b"hello");
    Ok(())
}

#[test]
fn tls13_key_schedule_uses_hash_len_zero_secret_for_empty_input() {
    let schedule = Tls13KeySchedule::new(HashKind::Sha256);
    assert_eq!(
        schedule.current_secret,
        HashKind::Sha256.hkdf_extract(None, &vec![0u8; HashKind::Sha256.output_len()])
    );
    assert_ne!(
        schedule.current_secret,
        HashKind::Sha256.hkdf_extract(None, &[])
    );
}
