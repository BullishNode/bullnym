-- Chain-swap cooperative-refused flag.
--
-- Set when Boltz reports `swap.expired` for a chain swap (or when a cooperative
-- claim is refused at runtime). Once set, the claimer builds the script-path
-- (preimage) claim instead of the cooperative MuSig2 claim that Boltz refuses
-- after the wall-clock swap timer expires — the on-chain server lockup stays
-- claimable until its timeoutBlockHeight, so we must not abandon it.
--
-- Mirrors swap_records.cooperative_refused (reverse-swap path). One-way flag:
-- never cleared, so the row stays on the script path once it flips.
ALTER TABLE chain_swap_records
    ADD COLUMN IF NOT EXISTS cooperative_refused BOOLEAN NOT NULL DEFAULT FALSE;
