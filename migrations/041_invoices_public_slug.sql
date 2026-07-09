-- Alias slug an invoice was created under, so its public-facing URL (the
-- bolt11 description and the BIP21 `message=` parameter the payer's wallet
-- shows) points at `/a/<slug>/i/<id>` instead of `/<nym>/i/<id>`.
--
-- Without this, an invoice created via `/a/<slug>/invoice` still embeds the
-- nym in the payment payload (the swap lockup BIP21 message and the Boltz
-- reverse-swap bolt11 description are generated from the nym), leaking the nym
-- the alias feature is meant to hide. The column is a pure label/pointer — it
-- is never looked up, so no index is needed. NULL means the nym path (or the
-- wallet-origin `/invoice/<id>` path) is used, unchanged.

ALTER TABLE invoices
    ADD COLUMN public_slug TEXT;
