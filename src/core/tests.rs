use super::*;

#[tokio::test]
async fn records_per_user_traffic() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("u1", "secret")])?;
    let session = core.authenticate("secret").await?;
    session.record_upload(10).await?;
    session.record_download(20).await?;
    let stats = core.snapshot().await;
    assert_eq!(stats[0].upload_bytes, 10);
    assert_eq!(stats[0].download_bytes, 20);
    assert_eq!(stats[0].online_sessions, 1);
    assert_eq!(stats[0].online_ips, 0);
    drop(session);
    assert_eq!(core.snapshot().await[0].online_sessions, 0);
    Ok(())
}

#[tokio::test]
async fn emits_session_and_traffic_events() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("u1", "secret")])?;
    let mut events = core.subscribe_events();
    let session = core
        .authenticate_from("secret", "1.2.3.4:1234".parse()?)
        .await?;
    let session_id = session.session_id();
    assert_eq!(
        events.recv().await,
        Some(CoreEvent::SessionOpened {
            user_id: "u1".to_string(),
            session_id,
            source_ip: Some("1.2.3.4".to_string()),
        })
    );

    session.record_upload(7).await?;
    assert_eq!(
        events.recv().await,
        Some(CoreEvent::TrafficRecorded {
            user_id: "u1".to_string(),
            session_id,
            direction: TrafficDirection::Upload,
            bytes: 7,
            upload_bytes: 7,
            download_bytes: 0,
        })
    );

    drop(session);
    assert_eq!(
        events.recv().await,
        Some(CoreEvent::SessionClosed {
            user_id: "u1".to_string(),
            session_id,
            source_ip: Some("1.2.3.4".to_string()),
        })
    );
    Ok(())
}

#[tokio::test]
async fn quota_rejects_over_limit() -> Result<()> {
    let mut user = CoreUser::password("u1", "secret");
    user.quota_bytes = Some(4);
    let core = ProxyCore::new(vec![user])?;
    let session = core.authenticate("secret").await?;
    session.record_upload(4).await?;
    assert!(session.record_download(1).await.is_err());
    Ok(())
}

#[tokio::test]
async fn online_limit_rejects_extra_sessions() -> Result<()> {
    let mut user = CoreUser::password("u1", "secret");
    user.max_online_sessions = Some(1);
    let core = ProxyCore::new(vec![user])?;
    let session = core.authenticate("secret").await?;
    assert!(core.authenticate("secret").await.is_err());
    drop(session);
    let session = core.authenticate("secret").await?;
    assert_eq!(session.user_id(), "u1");
    Ok(())
}

#[tokio::test]
async fn online_ip_limit_counts_unique_sources() -> Result<()> {
    let mut user = CoreUser::password("u1", "secret");
    user.max_online_ips = Some(1);
    let core = ProxyCore::new(vec![user])?;
    let first = core
        .authenticate_from("secret", "1.1.1.1:1000".parse()?)
        .await?;
    let second = core
        .authenticate_from("secret", "1.1.1.1:2000".parse()?)
        .await?;
    assert!(
        core.authenticate_from("secret", "2.2.2.2:1000".parse()?)
            .await
            .is_err()
    );
    let stats = core.snapshot().await;
    assert_eq!(stats[0].online_sessions, 2);
    assert_eq!(stats[0].online_ips, 1);
    drop(first);
    drop(second);
    let third = core
        .authenticate_from("secret", "2.2.2.2:1000".parse()?)
        .await?;
    assert_eq!(third.user_id(), "u1");
    Ok(())
}

#[tokio::test]
async fn replace_users_preserves_traffic_and_cancels_rotated_sessions() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("u1", "old-secret")])?;
    let session = core.authenticate("old-secret").await?;
    session.record_upload(10).await?;
    core.replace_users(vec![CoreUser::password("u1", "new-secret")])?;
    assert!(session.is_cancelled());
    assert!(session.record_upload(1).await.is_err());
    assert!(core.authenticate("old-secret").await.is_err());
    let new_session = core.authenticate("new-secret").await?;
    assert_eq!(new_session.user_id(), "u1");
    let stats = core.snapshot().await;
    assert_eq!(stats[0].upload_bytes, 10);
    Ok(())
}

#[tokio::test]
async fn supports_multiple_credentials_for_one_user() -> Result<()> {
    let core = ProxyCore::new(vec![
        CoreUser::password("u1", "secret-a"),
        CoreUser::password("u1", "secret-b"),
    ])?;
    assert_eq!(core.authenticate("secret-a").await?.user_id(), "u1");
    assert_eq!(core.authenticate("secret-b").await?.user_id(), "u1");
    Ok(())
}

#[tokio::test]
async fn replace_users_preserves_sessions_for_unchanged_multiple_credentials() -> Result<()> {
    let core = ProxyCore::new(vec![
        CoreUser::password("u1", "secret-a"),
        CoreUser::password("u1", "secret-b"),
    ])?;
    let session = core.authenticate("secret-a").await?;
    session.record_upload(10).await?;
    core.replace_users(vec![
        CoreUser::password("u1", "secret-a"),
        CoreUser::password("u1", "secret-b"),
    ])?;
    assert!(!session.is_cancelled());
    session.record_upload(1).await?;
    assert_eq!(core.authenticate("secret-b").await?.user_id(), "u1");
    assert_eq!(core.snapshot().await[0].upload_bytes, 11);
    Ok(())
}
