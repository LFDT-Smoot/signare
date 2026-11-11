ALTER TABLE cfg_hardware_security_module_slot ADD COLUMN pin_source VARCHAR(256) NOT NULL DEFAULT '';

-- The insert no longer binds pin, so without a default every new row would store NULL there. The
-- previous release reads the column into a plain string, so a NULL row breaks every slot read on a
-- binary rollback, including a module-wide listing. An empty string reads back fine on both releases
-- and is indistinguishable from NULL to this one.
ALTER TABLE cfg_hardware_security_module_slot ALTER COLUMN pin SET DEFAULT '';
UPDATE cfg_hardware_security_module_slot SET pin = '' WHERE pin IS NULL;
