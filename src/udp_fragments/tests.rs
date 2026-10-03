use super::*;

#[test]
fn reordered_fragments_preserve_payload() -> Result<()> {
    let mut fragments = FragmentPayload::new(3);
    assert!(fragments.insert(2, b"three".to_vec())?.is_none());
    assert!(fragments.insert(0, b"one".to_vec())?.is_none());
    assert_eq!(
        fragments.insert(1, b"two".to_vec())?,
        Some(b"onetwothree".to_vec())
    );
    Ok(())
}

#[test]
fn rejects_duplicates_invalid_indices_and_oversized_packets() -> Result<()> {
    let mut fragments = FragmentPayload::new(2);
    assert!(fragments.insert(2, vec![1]).is_err());
    assert!(fragments.insert(0, vec![0; MAX_UDP_PAYLOAD])?.is_none());
    assert!(fragments.insert(0, vec![1]).is_err());
    assert!(fragments.insert(1, vec![1]).is_err());
    assert_eq!(fragments.insert(1, vec![])?.unwrap().len(), MAX_UDP_PAYLOAD);
    Ok(())
}
