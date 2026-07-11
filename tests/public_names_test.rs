use pay_service::db;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

const TEST_DESCRIPTOR: &str = "test-descriptor";

fn surface<'a>(
    nym: &'a str,
    kind: &'a str,
    alias: Option<Option<&'a str>>,
) -> db::UpsertDonationPage<'a> {
    db::UpsertDonationPage {
        nym,
        kind,
        ct_descriptor: Some(TEST_DESCRIPTOR),
        header: "Test merchant",
        description: "Public-name integration test",
        display_currency: "USD",
        website: None,
        twitter: None,
        instagram: None,
        pos_mode: None,
        enabled: true,
        alias,
    }
}

async fn cleanup(pool: &PgPool) {
    sqlx::query("DELETE FROM invoices")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM donation_pages")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users")
        .execute(pool)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('bullnym.allow_public_name_delete', 'on', TRUE)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM public_names")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM public_name_owners")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn public_names_enforce_lifetime_ownership_and_shared_alias_fallback() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for public-name integration tests");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .unwrap();
    cleanup(&pool).await;

    db::create_user(&pool, "alice", "npub-alice", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("alice", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("alice", db::KIND_POS, None))
        .await
        .unwrap();

    let alias_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM public_names \
         WHERE owner_npub = 'npub-alice' AND kind = 'alias'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(alias_count, 0, "nym fallback must not synthesize an alias");

    for kind in [db::KIND_PAYMENT_PAGE, db::KIND_POS] {
        let page = db::get_donation_page_by_nym(&pool, "alice", kind)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.alias, None);
        assert!(!page.alias_active);
    }

    db::upsert_donation_page(
        &pool,
        &surface("alice", db::KIND_PAYMENT_PAGE, Some(Some("coffee"))),
    )
    .await
    .unwrap();
    for kind in [db::KIND_PAYMENT_PAGE, db::KIND_POS] {
        let page = db::get_donation_page_by_nym(&pool, "alice", kind)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.alias.as_deref(), Some("coffee"));
        assert!(page.alias_active);
    }

    let second_alias =
        db::upsert_donation_page(&pool, &surface("alice", db::KIND_POS, Some(Some("tea")))).await;
    assert!(matches!(
        second_alias,
        Err(db::UpsertDonationPageError::AliasAlreadyAssigned)
    ));

    db::archive_donation_page(&pool, "alice", db::KIND_PAYMENT_PAGE)
        .await
        .unwrap()
        .unwrap();
    let alias_still_active: bool = sqlx::query_scalar(
        "SELECT active FROM public_names WHERE name = 'coffee' AND kind = 'alias'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        alias_still_active,
        "archiving a surface must not release its alias"
    );
    db::upsert_donation_page(&pool, &surface("alice", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();

    db::upsert_donation_page(&pool, &surface("alice", db::KIND_POS, Some(None)))
        .await
        .unwrap();
    let reserved: (bool, bool) = sqlx::query_as(
        "SELECT active, deactivated_at IS NOT NULL \
         FROM public_names WHERE name = 'coffee' AND kind = 'alias'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reserved, (false, true));
    for kind in [db::KIND_PAYMENT_PAGE, db::KIND_POS] {
        let page = db::get_donation_page_by_nym(&pool, "alice", kind)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.alias, None, "cleared alias must fall back to nym");
    }

    db::create_user(&pool, "bob", "npub-bob", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("bob", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();
    let takeover = db::upsert_donation_page(
        &pool,
        &surface("bob", db::KIND_PAYMENT_PAGE, Some(Some("coffee"))),
    )
    .await;
    assert!(matches!(
        takeover,
        Err(db::UpsertDonationPageError::NameTaken)
    ));

    db::upsert_donation_page(&pool, &surface("alice", db::KIND_POS, Some(Some("coffee"))))
        .await
        .unwrap();

    db::create_user(&pool, "charlie", "npub-charlie", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("charlie", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();
    let nym_collision = db::upsert_donation_page(
        &pool,
        &surface("charlie", db::KIND_PAYMENT_PAGE, Some(Some("alice"))),
    )
    .await;
    assert!(matches!(
        nym_collision,
        Err(db::UpsertDonationPageError::NameTaken)
    ));

    let alias_collision =
        db::register_user_atomic(&pool, "npub-delta", "coffee", TEST_DESCRIPTOR, None, 1)
            .await
            .unwrap();
    assert!(matches!(alias_collision, db::RegisterOutcome::NameTaken));

    db::deactivate_user(&pool, "npub-alice")
        .await
        .unwrap()
        .unwrap();
    let inactive_alias = db::get_donation_page_by_alias(&pool, "coffee", db::KIND_PAYMENT_PAGE)
        .await
        .unwrap()
        .unwrap();
    assert!(!inactive_alias.alias_active);
    assert!(inactive_alias.is_archived);

    let reactivated =
        db::register_user_atomic(&pool, "npub-alice", "alice", TEST_DESCRIPTOR, None, 1)
            .await
            .unwrap();
    assert!(matches!(reactivated, db::RegisterOutcome::Reactivated(_)));
    let page = db::get_donation_page_by_nym(&pool, "alice", db::KIND_PAYMENT_PAGE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        page.alias, None,
        "nym reactivation must not reactivate alias"
    );

    db::deactivate_user(&pool, "npub-alice")
        .await
        .unwrap()
        .unwrap();
    let second_nym =
        db::register_user_atomic(&pool, "npub-alice", "alice-two", TEST_DESCRIPTOR, None, 99)
            .await
            .unwrap();
    assert!(matches!(
        second_nym,
        db::RegisterOutcome::NymAlreadyAssigned { .. }
    ));

    let delete_attempt =
        sqlx::query("DELETE FROM public_names WHERE name = 'coffee' AND kind = 'alias'")
            .execute(&pool)
            .await
            .unwrap_err();
    assert!(matches!(
        &delete_attempt,
        sqlx::Error::Database(error)
            if error.constraint() == Some("public_names_permanent_reservation")
    ));

    for (nym, npub) in [("echo", "npub-echo"), ("foxtrot", "npub-foxtrot")] {
        db::create_user(&pool, nym, npub, TEST_DESCRIPTOR)
            .await
            .unwrap();
        db::upsert_donation_page(&pool, &surface(nym, db::KIND_PAYMENT_PAGE, None))
            .await
            .unwrap();
    }
    let echo = surface("echo", db::KIND_PAYMENT_PAGE, Some(Some("race-name")));
    let foxtrot = surface("foxtrot", db::KIND_PAYMENT_PAGE, Some(Some("race-name")));
    let (echo_result, foxtrot_result) = tokio::join!(
        db::upsert_donation_page(&pool, &echo),
        db::upsert_donation_page(&pool, &foxtrot),
    );
    let success_count = usize::from(echo_result.is_ok()) + usize::from(foxtrot_result.is_ok());
    let taken_count = usize::from(matches!(
        echo_result,
        Err(db::UpsertDonationPageError::NameTaken)
    )) + usize::from(matches!(
        foxtrot_result,
        Err(db::UpsertDonationPageError::NameTaken)
    ));
    assert_eq!((success_count, taken_count), (1, 1));

    db::create_user(&pool, "crossalias", "npub-crossalias", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("crossalias", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();
    let cross_alias = surface(
        "crossalias",
        db::KIND_PAYMENT_PAGE,
        Some(Some("cross-race")),
    );
    let (nym_result, alias_result) = tokio::join!(
        db::register_user_atomic(
            &pool,
            "npub-crossnym",
            "cross-race",
            TEST_DESCRIPTOR,
            None,
            1,
        ),
        db::upsert_donation_page(&pool, &cross_alias),
    );
    let nym_won = matches!(&nym_result, Ok(db::RegisterOutcome::Created(_)));
    let alias_won = alias_result.is_ok();
    let nym_lost = matches!(&nym_result, Ok(db::RegisterOutcome::NameTaken));
    let alias_lost = matches!(&alias_result, Err(db::UpsertDonationPageError::NameTaken));
    assert_eq!(usize::from(nym_won) + usize::from(alias_won), 1);
    assert_eq!(usize::from(nym_lost) + usize::from(alias_lost), 1);

    db::create_user(&pool, "purger", "npub-purger", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(
        &pool,
        &surface("purger", db::KIND_PAYMENT_PAGE, Some(Some("forever-link"))),
    )
    .await
    .unwrap();
    assert!(matches!(
        db::purge_user(&pool, "npub-purger").await.unwrap(),
        db::PurgeOutcome::Purged(_)
    ));
    let purged_claims: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE active) \
         FROM public_names WHERE owner_npub = 'npub-purger'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(purged_claims, (2, 0));

    db::create_user(&pool, "newcomer", "npub-newcomer", TEST_DESCRIPTOR)
        .await
        .unwrap();
    db::upsert_donation_page(&pool, &surface("newcomer", db::KIND_PAYMENT_PAGE, None))
        .await
        .unwrap();
    let purged_takeover = db::upsert_donation_page(
        &pool,
        &surface(
            "newcomer",
            db::KIND_PAYMENT_PAGE,
            Some(Some("forever-link")),
        ),
    )
    .await;
    assert!(matches!(
        purged_takeover,
        Err(db::UpsertDonationPageError::NameTaken)
    ));

    assert!(matches!(
        db::register_user_atomic(&pool, "npub-purger", "purger", TEST_DESCRIPTOR, None, 1,)
            .await
            .unwrap(),
        db::RegisterOutcome::Reactivated(_)
    ));
    let restored = db::upsert_donation_page(
        &pool,
        &surface("purger", db::KIND_PAYMENT_PAGE, Some(Some("forever-link"))),
    )
    .await
    .unwrap();
    assert_eq!(restored.alias.as_deref(), Some("forever-link"));
    assert!(restored.alias_active);

    cleanup(&pool).await;
}
