use std::error::Error;
use std::fmt;
use std::time::Duration;

use crate::bitcoin_fee_adapter::{MempoolFastestFeeAdapter, OrderedMempoolFeeSources};
use crate::config::{
    FeePolicyConfig, FeePolicyConfigValidationFacts, FeeRailConfigValidationFacts,
};
use crate::fee_policy::{FeeRail, SatPerVbyte};
use crate::liquid_fee_sources::{LiquidFeeSource, LiquidFeeSources};

/// Immutable, typed acquisition-cycle settings for one explicitly identified
/// rail. Bounds are validation values only; this type cannot create fee
/// observations or decisions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RuntimeFeeRailSettings {
    rail: FeeRail,
    refresh_interval: Duration,
    live_max_age: Duration,
    last_known_good_max_age: Duration,
    floor: SatPerVbyte,
    cap: SatPerVbyte,
}

impl RuntimeFeeRailSettings {
    pub const fn rail(self) -> FeeRail {
        self.rail
    }

    pub const fn refresh_interval(self) -> Duration {
        self.refresh_interval
    }

    pub const fn live_max_age(self) -> Duration {
        self.live_max_age
    }

    pub const fn last_known_good_max_age(self) -> Duration {
        self.last_known_good_max_age
    }

    pub const fn floor(self) -> SatPerVbyte {
        self.floor
    }

    pub const fn cap(self) -> SatPerVbyte {
        self.cap
    }
}

/// Validated, immutable runtime source sets and rail-local timing/boundary
/// settings. Construction creates HTTP clients but performs no request.
#[derive(Clone)]
pub struct RuntimeFeeSourceSets {
    bitcoin_sources: OrderedMempoolFeeSources,
    liquid_sources: LiquidFeeSources,
    bitcoin_settings: RuntimeFeeRailSettings,
    liquid_settings: RuntimeFeeRailSettings,
}

impl RuntimeFeeSourceSets {
    pub fn from_config(config: &FeePolicyConfig) -> Result<Self, RuntimeFeeSourceProjectionError> {
        Self::build_with(
            config,
            |source| {
                MempoolFastestFeeAdapter::new_with_source_identity(&source.id, &source.endpoint)
                    .map_err(|_| ())
            },
            |source| LiquidFeeSource::new(source.id.clone(), &source.endpoint).map_err(|_| ()),
        )
    }

    pub const fn bitcoin_sources(&self) -> &OrderedMempoolFeeSources {
        &self.bitcoin_sources
    }

    pub const fn liquid_sources(&self) -> &LiquidFeeSources {
        &self.liquid_sources
    }

    pub const fn bitcoin_settings(&self) -> RuntimeFeeRailSettings {
        self.bitcoin_settings
    }

    pub const fn liquid_settings(&self) -> RuntimeFeeRailSettings {
        self.liquid_settings
    }

    #[cfg(test)]
    pub(crate) fn with_source_sets_for_test(
        bitcoin_sources: OrderedMempoolFeeSources,
        liquid_sources: LiquidFeeSources,
    ) -> Self {
        let mut projected = Self::from_config(&FeePolicyConfig::default())
            .expect("default runtime fee source configuration must remain valid");
        projected.bitcoin_sources = bitcoin_sources;
        projected.liquid_sources = liquid_sources;
        projected
    }

    fn build_with<BuildBitcoin, BuildLiquid>(
        config: &FeePolicyConfig,
        mut build_bitcoin: BuildBitcoin,
        mut build_liquid: BuildLiquid,
    ) -> Result<Self, RuntimeFeeSourceProjectionError>
    where
        BuildBitcoin:
            FnMut(&crate::config::FeeSourceConfig) -> Result<MempoolFastestFeeAdapter, ()>,
        BuildLiquid: FnMut(&crate::config::FeeSourceConfig) -> Result<LiquidFeeSource, ()>,
    {
        validate_config_facts(config.validation_facts())?;

        let bitcoin_settings = build_settings(
            FeeRail::Bitcoin,
            config.bitcoin.refresh_interval_secs,
            config.bitcoin.live_max_age_secs,
            config.bitcoin.last_known_good_max_age_secs,
            config.bitcoin.floor_sat_per_vbyte,
            config.bitcoin.cap_sat_per_vbyte,
        )?;
        let liquid_settings = build_settings(
            FeeRail::Liquid,
            config.liquid.refresh_interval_secs,
            config.liquid.live_max_age_secs,
            config.liquid.last_known_good_max_age_secs,
            config.liquid.floor_sat_per_vbyte,
            config.liquid.cap_sat_per_vbyte,
        )?;

        let bitcoin_adapters = config
            .bitcoin
            .sources
            .iter()
            .map(&mut build_bitcoin)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| projection_error(FeeRail::Bitcoin))?;
        let bitcoin_sources = OrderedMempoolFeeSources::new(bitcoin_adapters)
            .map_err(|_| projection_error(FeeRail::Bitcoin))?;

        let liquid_adapters = config
            .liquid
            .sources
            .iter()
            .map(&mut build_liquid)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| projection_error(FeeRail::Liquid))?;
        let liquid_sources = LiquidFeeSources::new(liquid_adapters)
            .map_err(|_| projection_error(FeeRail::Liquid))?;

        Ok(Self {
            bitcoin_sources,
            liquid_sources,
            bitcoin_settings,
            liquid_settings,
        })
    }
}

impl TryFrom<&FeePolicyConfig> for RuntimeFeeSourceSets {
    type Error = RuntimeFeeSourceProjectionError;

    fn try_from(config: &FeePolicyConfig) -> Result<Self, Self::Error> {
        Self::from_config(config)
    }
}

impl fmt::Debug for RuntimeFeeSourceSets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeFeeSourceSets")
            .field("bitcoin_source_count", &self.bitcoin_sources.len())
            .field("liquid_source_count", &self.liquid_sources.len())
            .field("bitcoin_settings", &self.bitcoin_settings)
            .field("liquid_settings", &self.liquid_settings)
            .field("configured_sources", &"<redacted>")
            .finish()
    }
}

fn build_settings(
    rail: FeeRail,
    refresh_interval_secs: u64,
    live_max_age_secs: u64,
    last_known_good_max_age_secs: u64,
    floor: f64,
    cap: f64,
) -> Result<RuntimeFeeRailSettings, RuntimeFeeSourceProjectionError> {
    let floor = SatPerVbyte::try_from(floor).map_err(|_| bounds_error(rail))?;
    let cap = SatPerVbyte::try_from(cap).map_err(|_| bounds_error(rail))?;
    if floor > cap {
        return Err(bounds_error(rail));
    }
    Ok(RuntimeFeeRailSettings {
        rail,
        refresh_interval: Duration::from_secs(refresh_interval_secs),
        live_max_age: Duration::from_secs(live_max_age_secs),
        last_known_good_max_age: Duration::from_secs(last_known_good_max_age_secs),
        floor,
        cap,
    })
}

fn validate_config_facts(
    facts: FeePolicyConfigValidationFacts,
) -> Result<(), RuntimeFeeSourceProjectionError> {
    validate_rail_facts(FeeRail::Bitcoin, facts.bitcoin)?;
    validate_rail_facts(FeeRail::Liquid, facts.liquid)
}

fn validate_rail_facts(
    rail: FeeRail,
    facts: FeeRailConfigValidationFacts,
) -> Result<(), RuntimeFeeSourceProjectionError> {
    for (valid, fact) in [
        (facts.sources_valid, RuntimeFeeProjectionFact::Sources),
        (
            facts.refresh_interval_valid,
            RuntimeFeeProjectionFact::RefreshInterval,
        ),
        (
            facts.live_freshness_window_valid,
            RuntimeFeeProjectionFact::LiveFreshnessWindow,
        ),
        (
            facts.last_known_good_freshness_window_valid,
            RuntimeFeeProjectionFact::LastKnownGoodFreshnessWindow,
        ),
        (facts.bounds_valid, RuntimeFeeProjectionFact::Bounds),
    ] {
        if !valid {
            return Err(RuntimeFeeSourceProjectionError { rail, fact });
        }
    }
    Ok(())
}

const fn bounds_error(rail: FeeRail) -> RuntimeFeeSourceProjectionError {
    RuntimeFeeSourceProjectionError {
        rail,
        fact: RuntimeFeeProjectionFact::Bounds,
    }
}

const fn projection_error(rail: FeeRail) -> RuntimeFeeSourceProjectionError {
    RuntimeFeeSourceProjectionError {
        rail,
        fact: RuntimeFeeProjectionFact::AdapterConstruction,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFeeProjectionFact {
    Sources,
    RefreshInterval,
    LiveFreshnessWindow,
    LastKnownGoodFreshnessWindow,
    Bounds,
    AdapterConstruction,
}

impl RuntimeFeeProjectionFact {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sources => "sources",
            Self::RefreshInterval => "refresh interval",
            Self::LiveFreshnessWindow => "live freshness window",
            Self::LastKnownGoodFreshnessWindow => "last-known-good freshness window",
            Self::Bounds => "fee bounds",
            Self::AdapterConstruction => "adapter construction",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFeeSourceProjectionError {
    rail: FeeRail,
    fact: RuntimeFeeProjectionFact,
}

impl RuntimeFeeSourceProjectionError {
    pub const fn rail(self) -> FeeRail {
        self.rail
    }

    pub const fn fact(self) -> RuntimeFeeProjectionFact {
        self.fact
    }
}

impl fmt::Debug for RuntimeFeeSourceProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeFeeSourceProjectionError")
            .field("rail", &self.rail)
            .field("fact", &self.fact)
            .field("configured_value", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for RuntimeFeeSourceProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} runtime fee {}",
            self.rail.as_str(),
            self.fact.as_str()
        )
    }
}

impl Error for RuntimeFeeSourceProjectionError {}

#[cfg(test)]
mod tests {
    use crate::config::FeeSourceConfig;

    use super::*;

    fn assert_settings(
        actual: RuntimeFeeRailSettings,
        rail: FeeRail,
        refresh: u64,
        live: u64,
        last_known_good: u64,
        floor: f64,
        cap: f64,
    ) {
        assert_eq!(actual.rail(), rail);
        assert_eq!(actual.refresh_interval(), Duration::from_secs(refresh));
        assert_eq!(actual.live_max_age(), Duration::from_secs(live));
        assert_eq!(
            actual.last_known_good_max_age(),
            Duration::from_secs(last_known_good)
        );
        assert_eq!(actual.floor(), SatPerVbyte::try_from(floor).unwrap());
        assert_eq!(actual.cap(), SatPerVbyte::try_from(cap).unwrap());
    }

    #[test]
    fn defaults_project_to_exact_source_counts_and_rail_settings() {
        let projected = RuntimeFeeSourceSets::from_config(&FeePolicyConfig::default()).unwrap();
        assert_eq!(projected.bitcoin_sources().len(), 2);
        assert_eq!(projected.liquid_sources().len(), 1);
        assert_settings(
            projected.bitcoin_settings(),
            FeeRail::Bitcoin,
            30,
            120,
            900,
            1.0,
            500.0,
        );
        assert_settings(
            projected.liquid_settings(),
            FeeRail::Liquid,
            30,
            120,
            900,
            0.1,
            10.0,
        );
    }

    #[test]
    fn custom_projection_preserves_exact_per_rail_mapping_order_and_settings() {
        let config: FeePolicyConfig = toml::from_str(
            r#"
            [bitcoin]
            refresh_interval_secs = 11
            live_max_age_secs = 22
            last_known_good_max_age_secs = 33
            floor_sat_per_vbyte = 1.25
            cap_sat_per_vbyte = 250.5
            [[bitcoin.sources]]
            id = "btc-first"
            endpoint = "https://btc-first.example/api"
            [[bitcoin.sources]]
            id = "btc-second"
            endpoint = "https://btc-second.example/mempool"

            [liquid]
            refresh_interval_secs = 44
            live_max_age_secs = 55
            last_known_good_max_age_secs = 66
            floor_sat_per_vbyte = 0.125
            cap_sat_per_vbyte = 5.5
            [[liquid.sources]]
            id = "liquid-first"
            endpoint = "https://liquid-first.example/api"
            [[liquid.sources]]
            id = "liquid-second"
            endpoint = "https://liquid-second.example/esplora"
            "#,
        )
        .unwrap();
        let mut bitcoin_mappings = Vec::new();
        let mut liquid_mappings = Vec::new();
        let projected = RuntimeFeeSourceSets::build_with(
            &config,
            |source| {
                bitcoin_mappings.push((source.id.clone(), source.endpoint.clone()));
                MempoolFastestFeeAdapter::new_with_source_identity(&source.id, &source.endpoint)
                    .map_err(|_| ())
            },
            |source| {
                liquid_mappings.push((source.id.clone(), source.endpoint.clone()));
                LiquidFeeSource::new(source.id.clone(), &source.endpoint).map_err(|_| ())
            },
        )
        .unwrap();

        assert_eq!(
            bitcoin_mappings,
            vec![
                (
                    "btc-first".to_string(),
                    "https://btc-first.example/api".to_string(),
                ),
                (
                    "btc-second".to_string(),
                    "https://btc-second.example/mempool".to_string(),
                ),
            ]
        );
        assert_eq!(
            liquid_mappings,
            vec![
                (
                    "liquid-first".to_string(),
                    "https://liquid-first.example/api".to_string(),
                ),
                (
                    "liquid-second".to_string(),
                    "https://liquid-second.example/esplora".to_string(),
                ),
            ]
        );
        assert_eq!(projected.bitcoin_sources().len(), 2);
        assert_eq!(projected.liquid_sources().len(), 2);
        assert_settings(
            projected.bitcoin_settings(),
            FeeRail::Bitcoin,
            11,
            22,
            33,
            1.25,
            250.5,
        );
        assert_settings(
            projected.liquid_settings(),
            FeeRail::Liquid,
            44,
            55,
            66,
            0.125,
            5.5,
        );
    }

    #[test]
    fn every_false_validation_fact_is_typed_and_rail_local() {
        for rail in [FeeRail::Bitcoin, FeeRail::Liquid] {
            for fact in [
                RuntimeFeeProjectionFact::Sources,
                RuntimeFeeProjectionFact::RefreshInterval,
                RuntimeFeeProjectionFact::LiveFreshnessWindow,
                RuntimeFeeProjectionFact::LastKnownGoodFreshnessWindow,
                RuntimeFeeProjectionFact::Bounds,
            ] {
                let mut config = FeePolicyConfig::default();
                match (rail, fact) {
                    (FeeRail::Bitcoin, RuntimeFeeProjectionFact::Sources) => {
                        config.bitcoin.sources.clear()
                    }
                    (FeeRail::Liquid, RuntimeFeeProjectionFact::Sources) => {
                        config.liquid.sources.clear()
                    }
                    (FeeRail::Bitcoin, RuntimeFeeProjectionFact::RefreshInterval) => {
                        config.bitcoin.refresh_interval_secs = 0
                    }
                    (FeeRail::Liquid, RuntimeFeeProjectionFact::RefreshInterval) => {
                        config.liquid.refresh_interval_secs = 0
                    }
                    (FeeRail::Bitcoin, RuntimeFeeProjectionFact::LiveFreshnessWindow) => {
                        config.bitcoin.live_max_age_secs = 0
                    }
                    (FeeRail::Liquid, RuntimeFeeProjectionFact::LiveFreshnessWindow) => {
                        config.liquid.live_max_age_secs = 0
                    }
                    (FeeRail::Bitcoin, RuntimeFeeProjectionFact::LastKnownGoodFreshnessWindow) => {
                        config.bitcoin.last_known_good_max_age_secs = 0
                    }
                    (FeeRail::Liquid, RuntimeFeeProjectionFact::LastKnownGoodFreshnessWindow) => {
                        config.liquid.last_known_good_max_age_secs = 0
                    }
                    (FeeRail::Bitcoin, RuntimeFeeProjectionFact::Bounds) => {
                        config.bitcoin.floor_sat_per_vbyte = 0.0
                    }
                    (FeeRail::Liquid, RuntimeFeeProjectionFact::Bounds) => {
                        config.liquid.cap_sat_per_vbyte = 0.0
                    }
                    (_, RuntimeFeeProjectionFact::AdapterConstruction) => unreachable!(),
                }

                let error = RuntimeFeeSourceSets::build_with(
                    &config,
                    |_| panic!("invalid config must not construct a Bitcoin adapter"),
                    |_| panic!("invalid config must not construct a Liquid adapter"),
                )
                .unwrap_err();
                assert_eq!(error.rail(), rail);
                assert_eq!(error.fact(), fact);
            }
        }
    }

    #[test]
    fn representational_bound_overflow_and_adapter_build_failures_stay_typed() {
        let mut config = FeePolicyConfig::default();
        config.bitcoin.floor_sat_per_vbyte = u64::MAX as f64;
        config.bitcoin.cap_sat_per_vbyte = u64::MAX as f64;
        let error = RuntimeFeeSourceSets::from_config(&config).unwrap_err();
        assert_eq!(error.rail(), FeeRail::Bitcoin);
        assert_eq!(error.fact(), RuntimeFeeProjectionFact::Bounds);

        let config = FeePolicyConfig::default();
        let bitcoin_error = RuntimeFeeSourceSets::build_with(
            &config,
            |_| Err(()),
            |_| panic!("Liquid must not build after Bitcoin projection fails"),
        )
        .unwrap_err();
        assert_eq!(bitcoin_error.rail(), FeeRail::Bitcoin);
        assert_eq!(
            bitcoin_error.fact(),
            RuntimeFeeProjectionFact::AdapterConstruction
        );

        let liquid_error = RuntimeFeeSourceSets::build_with(
            &config,
            |source| {
                MempoolFastestFeeAdapter::new_with_source_identity(&source.id, &source.endpoint)
                    .map_err(|_| ())
            },
            |_| Err(()),
        )
        .unwrap_err();
        assert_eq!(liquid_error.rail(), FeeRail::Liquid);
        assert_eq!(
            liquid_error.fact(),
            RuntimeFeeProjectionFact::AdapterConstruction
        );
    }

    #[test]
    fn diagnostics_redact_all_configured_ids_and_endpoints() {
        let secret_id = "operator-private-source";
        let secret_endpoint = "https://private-fees.example/secret-path";
        let mut config = FeePolicyConfig::default();
        config.bitcoin.sources = vec![FeeSourceConfig {
            id: secret_id.to_string(),
            endpoint: secret_endpoint.to_string(),
        }];
        let projected = RuntimeFeeSourceSets::from_config(&config).unwrap();
        let diagnostic = format!("{projected:?}");
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains(secret_id));
        assert!(!diagnostic.contains(secret_endpoint));
        assert!(!diagnostic.contains("secret-path"));

        config.bitcoin.sources[0].endpoint =
            "https://user:password@private-fees.example/secret-path".to_string();
        let error = RuntimeFeeSourceSets::from_config(&config).unwrap_err();
        for diagnostic in [format!("{error:?}"), error.to_string()] {
            assert!(!diagnostic.contains(secret_id));
            assert!(!diagnostic.contains("password"));
            assert!(!diagnostic.contains("private-fees.example"));
            assert!(!diagnostic.contains("secret-path"));
        }
        assert!(format!("{error:?}").contains("<redacted>"));
    }

    #[test]
    fn configured_quote_keys_are_rejected_instead_of_becoming_projection_input() {
        for rail in ["bitcoin", "liquid"] {
            for key in [
                "default_sat_per_vbyte",
                "fee_rate_sat_per_vbyte",
                "fallback_sat_per_vbyte",
                "configured_quote_sat_per_vbyte",
            ] {
                let input = format!("[{rail}]\n{key} = 2.0\n");
                assert!(
                    toml::from_str::<FeePolicyConfig>(&input).is_err(),
                    "accepted configured quote key {rail}.{key}"
                );
            }
        }
    }

    #[test]
    fn changing_one_rail_never_contaminates_the_other_projection() {
        let mut bitcoin_changed = FeePolicyConfig::default();
        bitcoin_changed.bitcoin.sources = vec![FeeSourceConfig {
            id: "bitcoin-only".to_string(),
            endpoint: "https://bitcoin-only.example/api".to_string(),
        }];
        bitcoin_changed.bitcoin.refresh_interval_secs = 7;
        bitcoin_changed.bitcoin.live_max_age_secs = 8;
        bitcoin_changed.bitcoin.last_known_good_max_age_secs = 9;
        bitcoin_changed.bitcoin.floor_sat_per_vbyte = 3.0;
        bitcoin_changed.bitcoin.cap_sat_per_vbyte = 4.0;

        let projected = RuntimeFeeSourceSets::from_config(&bitcoin_changed).unwrap();
        assert_eq!(projected.bitcoin_sources().len(), 1);
        assert_settings(
            projected.bitcoin_settings(),
            FeeRail::Bitcoin,
            7,
            8,
            9,
            3.0,
            4.0,
        );
        assert_eq!(projected.liquid_sources().len(), 1);
        assert_settings(
            projected.liquid_settings(),
            FeeRail::Liquid,
            30,
            120,
            900,
            0.1,
            10.0,
        );

        let mut liquid_changed = FeePolicyConfig::default();
        liquid_changed.liquid.sources = vec![
            FeeSourceConfig {
                id: "liquid-first".to_string(),
                endpoint: "https://liquid-first.example/api".to_string(),
            },
            FeeSourceConfig {
                id: "liquid-second".to_string(),
                endpoint: "https://liquid-second.example/api".to_string(),
            },
        ];
        liquid_changed.liquid.refresh_interval_secs = 17;
        liquid_changed.liquid.live_max_age_secs = 18;
        liquid_changed.liquid.last_known_good_max_age_secs = 19;
        liquid_changed.liquid.floor_sat_per_vbyte = 1.5;
        liquid_changed.liquid.cap_sat_per_vbyte = 2.5;

        let projected = RuntimeFeeSourceSets::from_config(&liquid_changed).unwrap();
        assert_eq!(projected.bitcoin_sources().len(), 2);
        assert_settings(
            projected.bitcoin_settings(),
            FeeRail::Bitcoin,
            30,
            120,
            900,
            1.0,
            500.0,
        );
        assert_eq!(projected.liquid_sources().len(), 2);
        assert_settings(
            projected.liquid_settings(),
            FeeRail::Liquid,
            17,
            18,
            19,
            1.5,
            2.5,
        );
    }
}
