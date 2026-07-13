-- ============================================================================
-- 049: Restart-safe direct-watcher lane rotation
-- ============================================================================
--
-- Persist only the last fully visited invoice key for each direct watcher and
-- recent/historical lane.  This is a rotation offset, never health evidence:
-- every process still has to traverse its own frozen lane snapshot, including
-- the wrap from the end back through the saved starting boundary.
-- ============================================================================

BEGIN;

CREATE TABLE watcher_lane_progress (
    worker TEXT NOT NULL,
    lane TEXT NOT NULL,
    cursor_created_at TIMESTAMPTZ,
    cursor_invoice_id UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT watcher_lane_progress_pkey PRIMARY KEY (worker, lane),
    CONSTRAINT watcher_lane_progress_worker_check CHECK (
        worker IN ('bitcoin_direct', 'liquid_direct')
    ),
    CONSTRAINT watcher_lane_progress_lane_check CHECK (
        lane IN ('recent', 'historical')
    ),
    CONSTRAINT watcher_lane_progress_cursor_shape_check CHECK (
        (cursor_created_at IS NULL) = (cursor_invoice_id IS NULL)
    )
);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'payservice') THEN
    GRANT SELECT, INSERT, UPDATE ON watcher_lane_progress TO payservice;
  END IF;
END
$$;

COMMIT;
