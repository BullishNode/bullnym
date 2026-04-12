-- Remove EasyDNS record tracking (DNS deferred to Phase 2)
ALTER TABLE users DROP COLUMN IF EXISTS dns_record_id;

-- Add comment field for LUD-12 support
ALTER TABLE swap_records ADD COLUMN comment TEXT;
