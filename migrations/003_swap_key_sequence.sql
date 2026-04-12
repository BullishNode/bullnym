-- Persistent swap key index using a PostgreSQL sequence.
-- Replaces the in-memory Mutex counter that reset on restart.
-- START WITH 100 skips past any indices already consumed at Boltz.
CREATE SEQUENCE swap_key_seq START WITH 100;
