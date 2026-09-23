-- Drops the cleartext pin column, refusing while any slot still depends on it.
--
-- The guard is in the same statement as the drop, not a step of its own. migrateStep stamps the
-- version before running a step and does not roll it back on failure, so a refused step leaves
-- (version = N, dirty = true); clearing only the dirty flag then makes mapMigrationsUp skip step N and
-- run N+1. A guard in its own step is therefore disarmed by the obvious recovery. Here there is no step
-- to skip: reaching the DROP means the guard passed in the same execution.
--
-- The whole body is idempotent and re-runnable. If the column is already gone, because a previous run
-- dropped it but failed before recording the version, this returns without touching anything, so the
-- documented recovery cannot loop.
--
-- Only a PKCS#11 slot is blocked. An AKV or Local Key Vault slot never authenticated with this column,
-- and before pin sources existed slot creation bound it for every module kind, so such a slot can hold
-- a stray value that is not a credential for anything. Blocking on those would refuse the upgrade and
-- send the operator to set a pinSource the API rejects for that module kind.
--
-- 's.pin <> \'\'' is load-bearing for the same reason: creation always bound the column, so a slot that
-- never had a PIN holds an empty string rather than NULL.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'cfg_hardware_security_module_slot' AND column_name = 'pin'
  ) THEN
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM cfg_hardware_security_module_slot s
    JOIN cfg_hardware_security_module m ON m.id = s.hardware_security_module_id
    WHERE m.kind = 'SoftHSM'
      AND s.pin IS NOT NULL AND s.pin <> ''
      AND COALESCE(s.pin_source, '') = ''
  ) THEN
    RAISE EXCEPTION 'one or more SoftHSM slots still hold a stored pin and name no pin source. Set a pinSource for each before upgrading, or their PIN is lost. See the database reference for recovery.';
  END IF;

  -- Overwrite before dropping, so the live row no longer carries the value. This does not erase it: the
  -- old tuple survives in dead tuples, WAL archives and every existing backup, which is why the
  -- pin-source step required rotating each PIN on the token.
  EXECUTE 'UPDATE cfg_hardware_security_module_slot SET pin = NULL WHERE pin IS NOT NULL';
  EXECUTE 'ALTER TABLE cfg_hardware_security_module_slot DROP COLUMN pin';
END $$;
