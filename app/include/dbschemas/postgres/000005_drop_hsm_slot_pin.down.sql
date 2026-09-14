-- Restores the column but not the values, which is the point: a PIN that reached this migration is
-- gone from the database for good, and a slot resolves its PIN from its source.
ALTER TABLE cfg_hardware_security_module_slot ADD COLUMN pin VARCHAR(256) NULL;
