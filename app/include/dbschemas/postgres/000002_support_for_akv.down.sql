ALTER TABLE cfg_hardware_security_module_slot DROP COLUMN configuration;
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN pin SET NOT NULL;
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN slot SET NOT NULL;
