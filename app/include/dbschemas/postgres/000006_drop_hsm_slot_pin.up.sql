-- Overwrite before dropping, so the live row no longer carries the value. This does not erase it:
-- the old tuple survives in dead tuples, WAL archives and every existing backup, which is why the
-- PIN-source step required rotating each PIN on the token.
UPDATE cfg_hardware_security_module_slot SET pin = NULL WHERE pin IS NOT NULL;
ALTER TABLE cfg_hardware_security_module_slot DROP COLUMN pin;
