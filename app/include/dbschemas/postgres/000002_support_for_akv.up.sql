ALTER TABLE cfg_hardware_security_module_slot ADD COLUMN configuration TEXT NULL;
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN pin DROP NOT NULL;
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN slot DROP NOT NULL;
