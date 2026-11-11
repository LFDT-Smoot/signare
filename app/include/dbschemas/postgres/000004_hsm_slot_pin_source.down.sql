ALTER TABLE cfg_hardware_security_module_slot DROP COLUMN pin_source;
-- The default goes with it. The previous release binds pin on every insert, so it does not need one,
-- and leaving it behind would be a silent change to a reverted schema.
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN pin DROP DEFAULT;
