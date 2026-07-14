use super::*;

#[test]
fn token_bucket_initial_full() {
    let mut b = TokenBucket::new(3);
    assert!(b.try_consume());
    assert!(b.try_consume());
    assert!(b.try_consume());
    assert!(!b.try_consume());
}

#[test]
fn token_bucket_refills() {
    let mut b = TokenBucket::new(2);
    b.tokens = 0;
    b.last_refill = Instant::now() - Duration::from_secs(2);
    assert!(b.try_consume());
}

#[test]
fn token_bucket_respects_capacity() {
    let mut b = TokenBucket::new(1);
    b.tokens = 1;
    b.last_refill = Instant::now() - Duration::from_secs(100);
    b.refill();
    assert_eq!(b.tokens, 1);
}

#[test]
fn token_bucket_zero_rate_uses_min_one() {
    // Guard against divide-by-zero or permanent-0 states.
    let mut b = TokenBucket::new(0);
    assert!(b.try_consume());
}

#[test]
fn inmem_allows_under_limit_then_blocks() {
    let s = InMemorySliding::default();
    let win = Duration::from_secs(60);
    for _ in 0..3 {
        assert!(matches!(
            s.check_and_record("k", 3, win),
            InmemOutcome::Allowed
        ));
    }
    assert!(matches!(
        s.check_and_record("k", 3, win),
        InmemOutcome::Limited(_)
    ));
}

#[test]
fn inmem_separate_keys_dont_share_budget() {
    let s = InMemorySliding::default();
    let win = Duration::from_secs(60);
    for _ in 0..3 {
        assert!(matches!(
            s.check_and_record("a", 3, win),
            InmemOutcome::Allowed
        ));
    }
    // "b" still has full budget because keys are isolated.
    assert!(matches!(
        s.check_and_record("b", 3, win),
        InmemOutcome::Allowed
    ));
}

#[test]
fn inmem_window_expiry_releases_budget() {
    let s = InMemorySliding::default();
    let key = "k".to_string();
    s.map.insert(key.clone(), {
        let mut d = VecDeque::new();
        d.push_back(Instant::now() - Duration::from_secs(120));
        d
    });
    assert!(matches!(
        s.check_and_record(&key, 1, Duration::from_secs(60)),
        InmemOutcome::Allowed
    ));
}

#[test]
fn inmem_concurrent_same_key_caps_at_limit() {
    use std::sync::Arc;
    use std::thread;

    let s = Arc::new(InMemorySliding::default());
    let win = Duration::from_secs(60);
    let limit: u32 = 10;
    let n_threads = 100;

    let handles: Vec<_> = (0..n_threads)
        .map(|_| {
            let s = Arc::clone(&s);
            thread::spawn(move || match s.check_and_record("hot", limit, win) {
                InmemOutcome::Allowed => 1u32,
                InmemOutcome::Limited(_) => 0,
            })
        })
        .collect();
    let allowed: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(allowed, limit);
}

#[test]
fn inmem_sweep_drops_idle_entries() {
    let s = InMemorySliding::default();
    s.map.insert("fresh".into(), {
        let mut d = VecDeque::new();
        d.push_back(Instant::now());
        d
    });
    s.map.insert("stale".into(), {
        let mut d = VecDeque::new();
        d.push_back(Instant::now() - Duration::from_secs(7200));
        d
    });
    let evicted = s.sweep_idle(Duration::from_secs(3600));
    assert_eq!(evicted, 1);
    assert!(s.map.contains_key("fresh"));
    assert!(!s.map.contains_key("stale"));
}

#[tokio::test]
async fn public_rate_limit_is_per_source_and_uses_a_dedicated_bucket() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .unwrap();
    let limiter = RateLimiter::new(
        pool,
        RateLimitConfig {
            public_rate_per_source_per_min: 2,
            ..RateLimitConfig::default()
        },
    );
    let first = "192.0.2.10".parse().unwrap();
    let second = "192.0.2.11".parse().unwrap();

    assert!(limiter.check_public_rate_per_source(first).await.is_ok());
    assert!(limiter.check_public_rate_per_source(first).await.is_ok());
    assert!(matches!(
        limiter.check_public_rate_per_source(first).await,
        Err(AppError::RateLimitedSender)
    ));
    assert!(limiter.check_public_rate_per_source(second).await.is_ok());

    // A pricing burst must not consume the unrelated general API bucket.
    assert!(limiter.check_api_per_ip(first).await.is_ok());
}
