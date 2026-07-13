use std::error::Error;
use std::fmt;

use crate::bitcoin_fee_adapter::{MempoolFastestFeeObservation, OrderedMempoolFeeSources};
use crate::current_fee_snapshot::{CurrentFeeGeneration, CurrentFeeSnapshot};
use crate::fee_policy::{
    BitcoinFeePolicy, FeeProvenance, FeeRail, LiquidFeePolicy, LiveBitcoin, LiveLiquid, SatPerVbyte,
};
use crate::liquid_fee_adapter::LiquidEsploraTargetOneFeeObservation;
use crate::liquid_fee_sources::{LiquidFeeSourceId, LiquidFeeSources};
use crate::runtime_fee_sources::RuntimeFeeSourceSets;

/// Fixed failure from a caller-supplied current-process clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeRefreshClockError {
    Unavailable,
}

impl fmt::Display for FeeRefreshClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fee refresh clock unavailable")
    }
}

impl Error for FeeRefreshClockError {}

/// Why one rail retained its prior current-process observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeRefreshRetainedReason {
    NoAcceptableObservation,
    ClockUnavailable,
    SnapshotUnavailable,
}

/// Fixed, rail-local result of one bounded acquisition attempt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FeeRailRefreshOutcome {
    Updated { generation: CurrentFeeGeneration },
    Retained { reason: FeeRefreshRetainedReason },
}

impl FeeRailRefreshOutcome {
    pub const fn generation(self) -> Option<CurrentFeeGeneration> {
        match self {
            Self::Updated { generation } => Some(generation),
            Self::Retained { .. } => None,
        }
    }

    pub const fn retained_reason(self) -> Option<FeeRefreshRetainedReason> {
        match self {
            Self::Updated { .. } => None,
            Self::Retained { reason } => Some(reason),
        }
    }
}

impl fmt::Debug for FeeRailRefreshOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut diagnostic = formatter.debug_struct("FeeRailRefreshOutcome");
        match self {
            Self::Updated { generation } => {
                diagnostic
                    .field("status", &"updated")
                    .field("generation", generation);
            }
            Self::Retained { reason } => {
                diagnostic
                    .field("status", &"retained")
                    .field("reason", reason);
            }
        }
        diagnostic.field("observation", &"<redacted>").finish()
    }
}

/// Independent Bitcoin and Liquid outcomes from one refresh cycle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FeeRefreshCycleOutcome {
    bitcoin: FeeRailRefreshOutcome,
    liquid: FeeRailRefreshOutcome,
}

impl FeeRefreshCycleOutcome {
    pub const fn bitcoin(self) -> FeeRailRefreshOutcome {
        self.bitcoin
    }

    pub const fn liquid(self) -> FeeRailRefreshOutcome {
        self.liquid
    }
}

impl fmt::Debug for FeeRefreshCycleOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeRefreshCycleOutcome")
            .field("bitcoin", &self.bitcoin)
            .field("liquid", &self.liquid)
            .finish()
    }
}

/// An unwired, current-process coordinator for exactly one bounded refresh.
///
/// It owns no task, timer, readiness state, persistence, or fallback source.
/// The supplied policies are always evaluated with `None` for LKG evidence.
pub struct FeeRefreshCycle<'a> {
    source_sets: &'a RuntimeFeeSourceSets,
    bitcoin_policy: &'a BitcoinFeePolicy,
    liquid_policy: &'a LiquidFeePolicy,
    snapshot: &'a CurrentFeeSnapshot,
}

impl<'a> FeeRefreshCycle<'a> {
    pub const fn new(
        source_sets: &'a RuntimeFeeSourceSets,
        bitcoin_policy: &'a BitcoinFeePolicy,
        liquid_policy: &'a LiquidFeePolicy,
        snapshot: &'a CurrentFeeSnapshot,
    ) -> Self {
        Self {
            source_sets,
            bitcoin_policy,
            liquid_policy,
            snapshot,
        }
    }

    /// Run both rail-local acquisitions concurrently without spawning or
    /// retaining any background work. A failed rail never clears its snapshot
    /// and never prevents the other rail from committing accepted evidence.
    pub async fn refresh_once<C>(&self, clock: C) -> FeeRefreshCycleOutcome
    where
        C: Fn(FeeRail) -> Result<u64, FeeRefreshClockError> + Sync,
    {
        let (bitcoin, liquid) = tokio::join!(
            refresh_bitcoin(
                self.source_sets.bitcoin_sources(),
                self.bitcoin_policy,
                self.snapshot,
                &clock,
            ),
            refresh_liquid(
                self.source_sets.liquid_sources(),
                self.liquid_policy,
                self.snapshot,
                &clock,
            ),
        );
        FeeRefreshCycleOutcome { bitcoin, liquid }
    }
}

impl fmt::Debug for FeeRefreshCycle<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeRefreshCycle")
            .field("source_sets", &"<redacted>")
            .field("bitcoin_policy", &"<redacted>")
            .field("liquid_policy", &"<redacted>")
            .field("snapshot", &"<redacted>")
            .finish()
    }
}

async fn refresh_bitcoin<C>(
    sources: &OrderedMempoolFeeSources,
    policy: &BitcoinFeePolicy,
    snapshot: &CurrentFeeSnapshot,
    clock: &C,
) -> FeeRailRefreshOutcome
where
    C: Fn(FeeRail) -> Result<u64, FeeRefreshClockError> + Sync + ?Sized,
{
    match acquire_bitcoin(sources, policy, clock).await {
        Ok(observation) => snapshot
            .update_bitcoin(observation)
            .map(|generation| FeeRailRefreshOutcome::Updated { generation })
            .unwrap_or(FeeRailRefreshOutcome::Retained {
                reason: FeeRefreshRetainedReason::SnapshotUnavailable,
            }),
        Err(reason) => FeeRailRefreshOutcome::Retained { reason },
    }
}

async fn refresh_liquid<C>(
    sources: &LiquidFeeSources,
    policy: &LiquidFeePolicy,
    snapshot: &CurrentFeeSnapshot,
    clock: &C,
) -> FeeRailRefreshOutcome
where
    C: Fn(FeeRail) -> Result<u64, FeeRefreshClockError> + Sync + ?Sized,
{
    match acquire_liquid(sources, policy, clock).await {
        Ok(observation) => snapshot
            .update_liquid(observation)
            .map(|generation| FeeRailRefreshOutcome::Updated { generation })
            .unwrap_or(FeeRailRefreshOutcome::Retained {
                reason: FeeRefreshRetainedReason::SnapshotUnavailable,
            }),
        Err(reason) => FeeRailRefreshOutcome::Retained { reason },
    }
}

async fn acquire_bitcoin<C>(
    sources: &OrderedMempoolFeeSources,
    policy: &BitcoinFeePolicy,
    clock: &C,
) -> Result<LiveBitcoin, FeeRefreshRetainedReason>
where
    C: Fn(FeeRail) -> Result<u64, FeeRefreshClockError> + Sync + ?Sized,
{
    let mut accepted = None;
    let mut clock_failed = false;
    let acquisition = sources
        .observe_first_acceptable(|observation| {
            if clock_failed {
                return false;
            }
            let Some(candidate) = bitcoin_candidate(observation) else {
                return false;
            };
            let now_unix = match clock(FeeRail::Bitcoin) {
                Ok(now_unix) => now_unix,
                Err(_) => {
                    clock_failed = true;
                    return false;
                }
            };
            if policy
                .decide_typed(Some(&candidate), None, now_unix)
                .is_err()
            {
                return false;
            }
            accepted = Some(candidate);
            true
        })
        .await;

    if clock_failed {
        return Err(FeeRefreshRetainedReason::ClockUnavailable);
    }
    if acquisition.is_err() {
        return Err(FeeRefreshRetainedReason::NoAcceptableObservation);
    }
    accepted.ok_or(FeeRefreshRetainedReason::NoAcceptableObservation)
}

async fn acquire_liquid<C>(
    sources: &LiquidFeeSources,
    policy: &LiquidFeePolicy,
    clock: &C,
) -> Result<LiveLiquid, FeeRefreshRetainedReason>
where
    C: Fn(FeeRail) -> Result<u64, FeeRefreshClockError> + Sync + ?Sized,
{
    let mut clock_failed = false;
    let acquisition = sources
        .acquire(|source_id, observation| {
            if clock_failed {
                return None;
            }
            let candidate = liquid_candidate(source_id, observation)?;
            let now_unix = match clock(FeeRail::Liquid) {
                Ok(now_unix) => now_unix,
                Err(_) => {
                    clock_failed = true;
                    return None;
                }
            };
            policy
                .decide_typed(Some(&candidate), None, now_unix)
                .ok()
                .map(|_| candidate)
        })
        .await;

    if clock_failed {
        return Err(FeeRefreshRetainedReason::ClockUnavailable);
    }
    acquisition
        .map(|selected| selected.into_policy_value())
        .map_err(|_| FeeRefreshRetainedReason::NoAcceptableObservation)
}

fn bitcoin_candidate(observation: &MempoolFastestFeeObservation) -> Option<LiveBitcoin> {
    observation
        .clone()
        .try_into_policy_observation()
        .ok()
        .and_then(|observation| LiveBitcoin::try_from_observation(observation).ok())
}

fn liquid_candidate(
    source_id: &LiquidFeeSourceId,
    observation: LiquidEsploraTargetOneFeeObservation,
) -> Option<LiveLiquid> {
    let rate = SatPerVbyte::try_from(observation.target_one_fee_sat_per_vbyte()).ok()?;
    let provenance = FeeProvenance::new(format!(
        "{}:{}",
        observation.source().stable_label(),
        source_id.stable_label(),
    ))
    .ok()?;
    Some(LiveLiquid::new(
        rate,
        observation.observed_at().as_u64(),
        provenance,
    ))
}

#[cfg(test)]
mod tests {
    use std::future::{poll_fn, Future};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use crate::bitcoin_fee_adapter::MempoolFastestFeeAdapter;
    use crate::current_fee_snapshot::CurrentFeeUnavailableReason;
    use crate::fee_policy::FeeObservationSource;
    use crate::liquid_fee_adapter::LiquidEsploraTargetOneFeeAdapter;
    use crate::liquid_fee_sources::{LiquidFeeSource, LiquidFeeSourceId};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_millis(750);

    enum FakeResponse {
        Json(Vec<u8>),
        HeldJson {
            body: Vec<u8>,
            release: oneshot::Receiver<()>,
        },
        Close,
    }

    impl FakeResponse {
        fn json(body: impl Into<Vec<u8>>) -> Self {
            Self::Json(body.into())
        }
    }

    struct FakeServer {
        endpoint: String,
        task: JoinHandle<String>,
    }

    impl FakeServer {
        async fn spawn(
            label: &str,
            response: FakeResponse,
            order: Arc<Mutex<Vec<String>>>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let label = label.to_owned();
            let task = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1_024];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                order.lock().unwrap().push(label);
                let body = match response {
                    FakeResponse::Json(body) => Some(body),
                    FakeResponse::HeldJson { body, release } => {
                        release.await.unwrap();
                        Some(body)
                    }
                    FakeResponse::Close => None,
                };
                if let Some(body) = body {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                }
                String::from_utf8(request).unwrap()
            });
            Self {
                endpoint: format!("http://{address}/fees"),
                task,
            }
        }

        async fn spawn_held(
            label: &str,
            body: impl Into<Vec<u8>>,
            order: Arc<Mutex<Vec<String>>>,
        ) -> (Self, oneshot::Sender<()>) {
            let (release, held) = oneshot::channel();
            let server = Self::spawn(
                label,
                FakeResponse::HeldJson {
                    body: body.into(),
                    release: held,
                },
                order,
            )
            .await;
            (server, release)
        }

        fn bitcoin_adapter(&self, id: &str) -> MempoolFastestFeeAdapter {
            MempoolFastestFeeAdapter::new_for_test_loopback_http_with_identity(
                id,
                &self.endpoint,
                TEST_TIMEOUT,
            )
            .unwrap()
        }

        fn liquid_source(&self, id: &str) -> LiquidFeeSource {
            LiquidFeeSource::from_adapter(
                LiquidFeeSourceId::new(id).unwrap(),
                LiquidEsploraTargetOneFeeAdapter::new_for_test_loopback_http(
                    &self.endpoint,
                    TEST_TIMEOUT,
                )
                .unwrap(),
            )
        }

        async fn finish(self) -> String {
            self.task.await.unwrap()
        }
    }

    fn runtime_sources(
        bitcoin: &[(&str, &FakeServer)],
        liquid: &[(&str, &FakeServer)],
    ) -> RuntimeFeeSourceSets {
        let bitcoin = OrderedMempoolFeeSources::new(
            bitcoin
                .iter()
                .map(|(id, server)| server.bitcoin_adapter(id))
                .collect(),
        )
        .unwrap();
        let liquid = LiquidFeeSources::new(
            liquid
                .iter()
                .map(|(id, server)| server.liquid_source(id))
                .collect(),
        )
        .unwrap();
        RuntimeFeeSourceSets::with_source_sets_for_test(bitcoin, liquid)
    }

    fn rate(value: f64) -> SatPerVbyte {
        SatPerVbyte::try_from(value).unwrap()
    }

    fn provenance(value: &str) -> FeeProvenance {
        FeeProvenance::new(value).unwrap()
    }

    fn broad_policies() -> (BitcoinFeePolicy, LiquidFeePolicy) {
        (
            BitcoinFeePolicy::new(rate(1.0), rate(100.0), u64::MAX, 1).unwrap(),
            LiquidFeePolicy::with_freshness(rate(0.1), rate(10.0), u64::MAX, 1).unwrap(),
        )
    }

    async fn finish_all(servers: Vec<FakeServer>) {
        for server in servers {
            server.finish().await;
        }
    }

    fn updated(expected_generation: u64) -> FeeRailRefreshOutcome {
        let snapshot = CurrentFeeSnapshot::new();
        let generation = snapshot
            .update_bitcoin(LiveBitcoin::new(
                rate(1.0),
                1,
                provenance("generation-fixture"),
            ))
            .unwrap();
        assert_eq!(generation.as_u64(), expected_generation);
        FeeRailRefreshOutcome::Updated { generation }
    }

    fn retained(reason: FeeRefreshRetainedReason) -> FeeRailRefreshOutcome {
        FeeRailRefreshOutcome::Retained { reason }
    }

    async fn assert_fast_rail_commits_before_held_rail(fast_rail: FeeRail) {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let (bitcoin, liquid, release_held) = match fast_rail {
            FeeRail::Bitcoin => {
                let bitcoin = FakeServer::spawn(
                    "fast-bitcoin",
                    FakeResponse::json(br#"{"fastestFee":14.0,"minimumFee":1.0}"#),
                    Arc::clone(&bitcoin_order),
                )
                .await;
                let (liquid, release) = FakeServer::spawn_held(
                    "held-liquid",
                    br#"{"1":0.9}"#,
                    Arc::clone(&liquid_order),
                )
                .await;
                (bitcoin, liquid, release)
            }
            FeeRail::Liquid => {
                let (bitcoin, release) = FakeServer::spawn_held(
                    "held-bitcoin",
                    br#"{"fastestFee":14.0,"minimumFee":1.0}"#,
                    Arc::clone(&bitcoin_order),
                )
                .await;
                let liquid = FakeServer::spawn(
                    "fast-liquid",
                    FakeResponse::json(br#"{"1":0.9}"#),
                    Arc::clone(&liquid_order),
                )
                .await;
                (bitcoin, liquid, release)
            }
        };
        let sources = runtime_sources(&[("fast-bitcoin", &bitcoin)], &[("fast-liquid", &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();
        let cycle = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot);
        let (fast_evaluated, mut wait_for_fast_evaluation) = oneshot::channel();
        let fast_evaluated = Mutex::new(Some(fast_evaluated));
        let refresh = cycle.refresh_once(|rail| {
            if rail == fast_rail {
                fast_evaluated
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
            }
            Ok(u64::MAX)
        });
        tokio::pin!(refresh);

        tokio::select! {
            outcome = &mut refresh => panic!("held rail completed early: {outcome:?}"),
            signal = &mut wait_for_fast_evaluation => signal.unwrap(),
        }
        poll_fn(|context| match refresh.as_mut().poll(context) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(outcome) => panic!("held cycle was not pending: {outcome:?}"),
        })
        .await;

        match fast_rail {
            FeeRail::Bitcoin => {
                let current = snapshot.read_bitcoin(&bitcoin_policy, u64::MAX).unwrap();
                assert_eq!(current.generation().as_u64(), 1);
                assert_eq!(current.decision().rate(), rate(14.0));
                assert_eq!(
                    current.decision().source(),
                    FeeObservationSource::LiveBitcoin
                );
                assert_eq!(
                    current.decision().provenance().expose_for_persistence(),
                    "mempool_recommended_fastest_fee:fast-bitcoin"
                );
                let held = snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap_err();
                assert_eq!(held.generation().unwrap().as_u64(), 0);
                assert_eq!(held.reason(), Some(CurrentFeeUnavailableReason::Missing));
            }
            FeeRail::Liquid => {
                let current = snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap();
                assert_eq!(current.generation().as_u64(), 1);
                assert_eq!(current.decision().rate(), rate(0.9));
                assert_eq!(
                    current.decision().source(),
                    FeeObservationSource::LiveLiquid
                );
                assert_eq!(
                    current.decision().provenance().expose_for_persistence(),
                    "liquid_esplora_target_1_fee:fast-liquid"
                );
                let held = snapshot
                    .read_bitcoin(&bitcoin_policy, u64::MAX)
                    .unwrap_err();
                assert_eq!(held.generation().unwrap().as_u64(), 0);
                assert_eq!(held.reason(), Some(CurrentFeeUnavailableReason::Missing));
            }
        }

        release_held.send(()).unwrap();
        let outcome = refresh.await;
        assert_eq!(outcome.bitcoin().generation().unwrap().as_u64(), 1);
        assert_eq!(outcome.liquid().generation().unwrap().as_u64(), 1);
        let bitcoin_current = snapshot.read_bitcoin(&bitcoin_policy, u64::MAX).unwrap();
        assert_eq!(bitcoin_current.decision().rate(), rate(14.0));
        assert_eq!(
            bitcoin_current
                .decision()
                .provenance()
                .expose_for_persistence(),
            "mempool_recommended_fastest_fee:fast-bitcoin"
        );
        let liquid_current = snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap();
        assert_eq!(liquid_current.decision().rate(), rate(0.9));
        assert_eq!(
            liquid_current
                .decision()
                .provenance()
                .expose_for_persistence(),
            "liquid_esplora_target_1_fee:fast-liquid"
        );
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn bitcoin_fast_commits_before_held_liquid_cycle_completes() {
        assert_fast_rail_commits_before_held_rail(FeeRail::Bitcoin).await;
    }

    #[tokio::test]
    async fn liquid_fast_commits_before_held_bitcoin_cycle_completes() {
        assert_fast_rail_commits_before_held_rail(FeeRail::Liquid).await;
    }

    #[tokio::test]
    async fn both_rails_accept_typed_live_evidence_and_update_independently() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json(br#"{"fastestFee":12.5,"minimumFee":1.0}"#),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json(br#"{"1":0.75}"#),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();
        let cycle = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot);

        let outcome = cycle.refresh_once(|_| Ok(u64::MAX)).await;

        assert_eq!(outcome.bitcoin().generation().unwrap().as_u64(), 1);
        assert_eq!(outcome.liquid().generation().unwrap().as_u64(), 1);
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, u64::MAX)
                .unwrap()
                .decision()
                .rate(),
            rate(12.5)
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, u64::MAX)
                .unwrap()
                .decision()
                .rate(),
            rate(0.75)
        );

        let bitcoin_request = bitcoin.finish().await;
        let liquid_request = liquid.finish().await;
        assert!(bitcoin_request.starts_with("GET /fees/v1/fees/recommended HTTP/1.1\r\n"));
        assert!(liquid_request.starts_with("GET /fees/fee-estimates HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn transport_schema_and_policy_rejection_advance_in_exact_order() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin_servers = vec![
            FakeServer::spawn(
                "btc-transport",
                FakeResponse::Close,
                Arc::clone(&bitcoin_order),
            )
            .await,
            FakeServer::spawn(
                "btc-schema",
                FakeResponse::json("not-json"),
                Arc::clone(&bitcoin_order),
            )
            .await,
            FakeServer::spawn(
                "btc-policy",
                FakeResponse::json(br#"{"fastestFee":500.0,"minimumFee":1.0}"#),
                Arc::clone(&bitcoin_order),
            )
            .await,
            FakeServer::spawn(
                "btc-accepted",
                FakeResponse::json(br#"{"fastestFee":21.0,"minimumFee":1.0}"#),
                Arc::clone(&bitcoin_order),
            )
            .await,
        ];
        let liquid_servers = vec![
            FakeServer::spawn(
                "liquid-transport",
                FakeResponse::Close,
                Arc::clone(&liquid_order),
            )
            .await,
            FakeServer::spawn(
                "liquid-schema",
                FakeResponse::json("not-json"),
                Arc::clone(&liquid_order),
            )
            .await,
            FakeServer::spawn(
                "liquid-policy",
                FakeResponse::json(br#"{"1":20.0}"#),
                Arc::clone(&liquid_order),
            )
            .await,
            FakeServer::spawn(
                "liquid-accepted",
                FakeResponse::json(br#"{"1":0.5}"#),
                Arc::clone(&liquid_order),
            )
            .await,
        ];
        let bitcoin_refs = bitcoin_servers
            .iter()
            .enumerate()
            .map(|(index, server)| (format!("btc-{index}"), server))
            .collect::<Vec<_>>();
        let liquid_refs = liquid_servers
            .iter()
            .enumerate()
            .map(|(index, server)| (format!("liquid-{index}"), server))
            .collect::<Vec<_>>();
        let bitcoin_refs = bitcoin_refs
            .iter()
            .map(|(id, server)| (id.as_str(), *server))
            .collect::<Vec<_>>();
        let liquid_refs = liquid_refs
            .iter()
            .map(|(id, server)| (id.as_str(), *server))
            .collect::<Vec<_>>();
        let sources = runtime_sources(&bitcoin_refs, &liquid_refs);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();

        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| Ok(u64::MAX))
            .await;

        assert_eq!(outcome.bitcoin().generation().unwrap().as_u64(), 1);
        assert_eq!(outcome.liquid().generation().unwrap().as_u64(), 1);
        let bitcoin_current = snapshot.read_bitcoin(&bitcoin_policy, u64::MAX).unwrap();
        assert_eq!(bitcoin_current.decision().rate(), rate(21.0));
        assert_eq!(
            bitcoin_current.decision().source(),
            FeeObservationSource::LiveBitcoin
        );
        assert_eq!(
            bitcoin_current
                .decision()
                .provenance()
                .expose_for_persistence(),
            "mempool_recommended_fastest_fee:btc-3"
        );
        let liquid_current = snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap();
        assert_eq!(liquid_current.decision().rate(), rate(0.5));
        assert_eq!(
            liquid_current.decision().source(),
            FeeObservationSource::LiveLiquid
        );
        assert_eq!(
            liquid_current
                .decision()
                .provenance()
                .expose_for_persistence(),
            "liquid_esplora_target_1_fee:liquid-3"
        );
        finish_all(bitcoin_servers).await;
        finish_all(liquid_servers).await;
        assert_eq!(
            *bitcoin_order.lock().unwrap(),
            ["btc-transport", "btc-schema", "btc-policy", "btc-accepted"]
        );
        assert_eq!(
            *liquid_order.lock().unwrap(),
            [
                "liquid-transport",
                "liquid-schema",
                "liquid-policy",
                "liquid-accepted"
            ]
        );
    }

    #[tokio::test]
    async fn one_rail_failure_never_blocks_the_other_rail_in_either_direction() {
        for bitcoin_succeeds in [false, true] {
            let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
            let liquid_order = Arc::new(Mutex::new(Vec::new()));
            let bitcoin = FakeServer::spawn(
                "bitcoin",
                if bitcoin_succeeds {
                    FakeResponse::json(br#"{"fastestFee":8.0,"minimumFee":1.0}"#)
                } else {
                    FakeResponse::json("not-json")
                },
                Arc::clone(&bitcoin_order),
            )
            .await;
            let liquid = FakeServer::spawn(
                "liquid",
                if bitcoin_succeeds {
                    FakeResponse::json("not-json")
                } else {
                    FakeResponse::json(br#"{"1":0.8}"#)
                },
                Arc::clone(&liquid_order),
            )
            .await;
            let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
            let (bitcoin_policy, liquid_policy) = broad_policies();
            let snapshot = CurrentFeeSnapshot::new();

            let outcome =
                FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
                    .refresh_once(|_| Ok(u64::MAX))
                    .await;

            if bitcoin_succeeds {
                assert_eq!(outcome.bitcoin().generation().unwrap().as_u64(), 1);
                assert_eq!(
                    outcome.liquid().retained_reason(),
                    Some(FeeRefreshRetainedReason::NoAcceptableObservation)
                );
                assert!(snapshot.read_bitcoin(&bitcoin_policy, u64::MAX).is_ok());
                assert_eq!(
                    snapshot
                        .read_liquid(&liquid_policy, u64::MAX)
                        .unwrap_err()
                        .reason(),
                    Some(CurrentFeeUnavailableReason::Missing)
                );
            } else {
                assert_eq!(
                    outcome.bitcoin().retained_reason(),
                    Some(FeeRefreshRetainedReason::NoAcceptableObservation)
                );
                assert_eq!(outcome.liquid().generation().unwrap().as_u64(), 1);
                assert_eq!(
                    snapshot
                        .read_bitcoin(&bitcoin_policy, u64::MAX)
                        .unwrap_err()
                        .reason(),
                    Some(CurrentFeeUnavailableReason::Missing)
                );
                assert!(snapshot.read_liquid(&liquid_policy, u64::MAX).is_ok());
            }
            bitcoin.finish().await;
            liquid.finish().await;
        }
    }

    #[tokio::test]
    async fn both_rail_failures_retain_empty_generations_without_invention() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json("not-json"),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json("not-json"),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();

        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| -> Result<u64, FeeRefreshClockError> {
                panic!("schema failures must not consult the evaluation clock")
            })
            .await;

        assert_eq!(
            outcome.bitcoin(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            outcome.liquid(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        for error in [
            snapshot
                .read_bitcoin(&bitcoin_policy, u64::MAX)
                .unwrap_err(),
            snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap_err(),
        ] {
            assert_eq!(error.generation().unwrap().as_u64(), 0);
            assert_eq!(error.reason(), Some(CurrentFeeUnavailableReason::Missing));
        }
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn failed_refresh_retains_prior_evidence_which_later_reads_mark_stale() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json("not-json"),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json("not-json"),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let bitcoin_policy = BitcoinFeePolicy::new(rate(1.0), rate(100.0), 10, 10).unwrap();
        let liquid_policy = LiquidFeePolicy::with_freshness(rate(0.1), rate(10.0), 10, 10).unwrap();
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(LiveBitcoin::new(rate(5.0), 100, provenance("prior-btc")))
            .unwrap();
        snapshot
            .update_liquid(LiveLiquid::new(rate(0.5), 100, provenance("prior-liquid")))
            .unwrap();

        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| -> Result<u64, FeeRefreshClockError> {
                panic!("schema failures must not consult the evaluation clock")
            })
            .await;

        assert_eq!(
            outcome.bitcoin(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            outcome.liquid(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, 110)
                .unwrap()
                .generation()
                .as_u64(),
            1
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, 110)
                .unwrap()
                .generation()
                .as_u64(),
            1
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, 111)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Stale)
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, 111)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Stale)
        );
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn generations_change_exactly_once_only_for_accepted_updates() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json(br#"{"fastestFee":9.0,"minimumFee":1.0}"#),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json("not-json"),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();
        snapshot
            .update_bitcoin(LiveBitcoin::new(rate(5.0), 100, provenance("initial-btc")))
            .unwrap();
        snapshot
            .update_liquid(LiveLiquid::new(
                rate(0.5),
                100,
                provenance("initial-liquid"),
            ))
            .unwrap();

        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| Ok(u64::MAX))
            .await;

        assert_eq!(outcome.bitcoin().generation().unwrap().as_u64(), 2);
        assert_eq!(
            outcome.liquid(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, u64::MAX)
                .unwrap()
                .generation()
                .as_u64(),
            2
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, u64::MAX)
                .unwrap()
                .generation()
                .as_u64(),
            1
        );
        bitcoin.finish().await;
        liquid.finish().await;

        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin-failed",
            FakeResponse::json("not-json"),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid-failed",
            FakeResponse::json("not-json"),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| Ok(u64::MAX))
            .await;
        assert_eq!(
            outcome.bitcoin(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            outcome.liquid(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, u64::MAX)
                .unwrap()
                .generation()
                .as_u64(),
            2
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, u64::MAX)
                .unwrap()
                .generation()
                .as_u64(),
            1
        );
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn clock_failure_and_future_observations_fail_closed_per_rail() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json(br#"{"fastestFee":7.0,"minimumFee":1.0}"#),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json(br#"{"1":0.7}"#),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();
        let bitcoin_clock_calls = AtomicUsize::new(0);
        let liquid_clock_calls = AtomicUsize::new(0);

        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|rail| match rail {
                FeeRail::Bitcoin => {
                    bitcoin_clock_calls.fetch_add(1, Ordering::SeqCst);
                    Err(FeeRefreshClockError::Unavailable)
                }
                FeeRail::Liquid => {
                    liquid_clock_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(u64::MAX)
                }
            })
            .await;

        assert_eq!(
            outcome.bitcoin(),
            retained(FeeRefreshRetainedReason::ClockUnavailable)
        );
        assert_eq!(outcome.liquid().generation().unwrap().as_u64(), 1);
        assert_eq!(bitcoin_clock_calls.load(Ordering::SeqCst), 1);
        assert_eq!(liquid_clock_calls.load(Ordering::SeqCst), 1);
        bitcoin.finish().await;
        liquid.finish().await;

        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin-future",
            FakeResponse::json(br#"{"fastestFee":7.0,"minimumFee":1.0}"#),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid-future",
            FakeResponse::json(br#"{"1":0.7}"#),
            Arc::clone(&liquid_order),
        )
        .await;
        let sources = runtime_sources(&[("bitcoin", &bitcoin)], &[("liquid", &liquid)]);
        let snapshot = CurrentFeeSnapshot::new();
        let outcome = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot)
            .refresh_once(|_| Ok(0))
            .await;
        assert_eq!(
            outcome.bitcoin(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            outcome.liquid(),
            retained(FeeRefreshRetainedReason::NoAcceptableObservation)
        );
        assert_eq!(
            snapshot
                .read_bitcoin(&bitcoin_policy, 0)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Missing)
        );
        assert_eq!(
            snapshot
                .read_liquid(&liquid_policy, 0)
                .unwrap_err()
                .reason(),
            Some(CurrentFeeUnavailableReason::Missing)
        );
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[tokio::test]
    async fn cycle_outcomes_and_state_diagnostics_redact_source_details() {
        let bitcoin_order = Arc::new(Mutex::new(Vec::new()));
        let liquid_order = Arc::new(Mutex::new(Vec::new()));
        let bitcoin = FakeServer::spawn(
            "bitcoin",
            FakeResponse::json(br#"{"fastestFee":6.0,"minimumFee":1.0}"#),
            Arc::clone(&bitcoin_order),
        )
        .await;
        let liquid = FakeServer::spawn(
            "liquid",
            FakeResponse::json(br#"{"1":0.6}"#),
            Arc::clone(&liquid_order),
        )
        .await;
        let bitcoin_id = "password-bitcoin-source";
        let liquid_id = "token-liquid-source";
        let bitcoin_endpoint = bitcoin.endpoint.clone();
        let liquid_endpoint = liquid.endpoint.clone();
        let sources = runtime_sources(&[(bitcoin_id, &bitcoin)], &[(liquid_id, &liquid)]);
        let (bitcoin_policy, liquid_policy) = broad_policies();
        let snapshot = CurrentFeeSnapshot::new();
        let cycle = FeeRefreshCycle::new(&sources, &bitcoin_policy, &liquid_policy, &snapshot);
        let cycle_diagnostic = format!("{cycle:?}");
        let outcome = cycle.refresh_once(|_| Ok(u64::MAX)).await;
        let bitcoin_current = snapshot.read_bitcoin(&bitcoin_policy, u64::MAX).unwrap();
        let liquid_current = snapshot.read_liquid(&liquid_policy, u64::MAX).unwrap();

        for diagnostic in [
            cycle_diagnostic,
            format!("{outcome:?}"),
            format!("{snapshot:?}"),
            format!("{bitcoin_current:?}"),
            format!("{liquid_current:?}"),
        ] {
            assert!(diagnostic.contains("<redacted>"));
            assert!(!diagnostic.contains(bitcoin_id));
            assert!(!diagnostic.contains(liquid_id));
            assert!(!diagnostic.contains(&bitcoin_endpoint));
            assert!(!diagnostic.contains(&liquid_endpoint));
            assert!(!diagnostic.contains("password"));
            assert!(!diagnostic.contains("token"));
        }
        bitcoin.finish().await;
        liquid.finish().await;
    }

    #[test]
    fn fixed_outcomes_expose_only_generation_or_reason() {
        assert_eq!(
            retained(FeeRefreshRetainedReason::ClockUnavailable).generation(),
            None
        );
        assert_eq!(
            retained(FeeRefreshRetainedReason::SnapshotUnavailable).retained_reason(),
            Some(FeeRefreshRetainedReason::SnapshotUnavailable)
        );
        assert_eq!(updated(1).retained_reason(), None);
        assert!(
            format!("{:?}", retained(FeeRefreshRetainedReason::ClockUnavailable))
                .contains("<redacted>")
        );
        assert_eq!(
            FeeRefreshClockError::Unavailable.to_string(),
            "fee refresh clock unavailable"
        );
    }
}
