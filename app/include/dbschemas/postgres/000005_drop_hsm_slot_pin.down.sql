-- Restores the column but not the values, which is the point: a PIN that reached this migration is
-- gone from the database for good, and a slot resolves its PIN from its source.
-- IF NOT EXISTS so it pairs with an up step that may have returned early, leaving the column in place.
ALTER TABLE cfg_hardware_security_module_slot ADD COLUMN IF NOT EXISTS pin VARCHAR(256) NULL;
