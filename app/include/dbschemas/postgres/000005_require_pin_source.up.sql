-- Refuses the upgrade while any slot would lose its only credential when 000006 drops the column.
--
-- This is a separate step, not a guard at the top of 000006, because the migrator runs each file
-- through one ExecContext whose transactional behaviour the persistence layer documents as not
-- guaranteed. Steps do stop on the first failure, so a guard that owns its own step cannot be
-- half-applied whatever the driver does.
--
-- 'pin <> \'\'' is load-bearing: before pin sources existed the insert always bound the column, so an
-- AKV or Local Key Vault slot holds an empty string rather than NULL. Testing only for NULL would
-- block every deployment that never had a PKCS#11 slot.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM cfg_hardware_security_module_slot
    WHERE pin IS NOT NULL AND pin <> '' AND COALESCE(pin_source, '') = ''
  ) THEN
    RAISE EXCEPTION 'one or more HSM slots still hold a stored pin and name no pin source. Set a pinSource for each with admin.slots.updatePinSource before upgrading, or their PIN is lost. See the database reference for recovery.';
  END IF;
END $$;
