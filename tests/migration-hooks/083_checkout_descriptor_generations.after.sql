SELECT set_config('bullnym.migration_runtime_role', :'runtime_role', FALSE);

DO $$
DECLARE
    runtime_role_name TEXT := current_setting('bullnym.migration_runtime_role');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'donation_pages'
           AND column_name = 'descriptor_generation'
           AND is_nullable = 'NO'
    ) OR to_regclass('public.checkout_liquid_address_reservations') IS NULL THEN
        RAISE EXCEPTION 'migration 083 did not install checkout generation storage';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'checkout_liquid_address_reservations'::regclass
           AND conname = 'checkout_liquid_reservation_derivation_key'
           AND contype = 'u'
           AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'checkout_liquid_address_reservations'::regclass
           AND conname = 'checkout_liquid_reservation_address_key'
           AND contype = 'u'
           AND convalidated
    ) THEN
        RAISE EXCEPTION 'migration 083 reservation uniqueness is incomplete';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid = 'donation_pages'::regclass
           AND trigger_info.tgname = 'donation_pages_enforce_descriptor_generation'
           AND NOT trigger_info.tgisinternal
           AND trigger_info.tgenabled = 'O'
           AND function_info.proname = 'enforce_checkout_descriptor_generation'
    ) THEN
        RAISE EXCEPTION 'migration 083 descriptor-generation trigger is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger trigger_info
          JOIN pg_proc function_info ON function_info.oid = trigger_info.tgfoid
         WHERE trigger_info.tgrelid =
               'checkout_liquid_address_reservations'::regclass
           AND trigger_info.tgname =
               'checkout_liquid_reservations_enforce_transition'
           AND NOT trigger_info.tgisinternal
           AND trigger_info.tgenabled = 'O'
           AND function_info.proname =
               'enforce_checkout_liquid_reservation_transition'
    ) THEN
        RAISE EXCEPTION 'migration 083 reservation transition trigger is missing';
    END IF;

    IF NOT has_table_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'SELECT')
       OR NOT has_column_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'address', 'INSERT')
       OR has_column_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'status', 'INSERT')
       OR NOT has_column_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'status', 'UPDATE')
       OR has_column_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'address', 'UPDATE')
       OR has_table_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'DELETE')
       OR has_table_privilege(runtime_role_name,
            'checkout_liquid_address_reservations', 'TRUNCATE') THEN
        RAISE EXCEPTION 'migration 083 reservation ACL is incorrect';
    END IF;
END
$$;
