-- Rewrite a leftover legacy brand name that 0006 missed.
-- 0006 handled 'Sigaint' / 'Sigaint Secret Server'; plain 'Secret Server'
-- slipped through and keeps rendering on every themed page (incl. errors).
-- 'Corvus' matches config.DEFAULT_SETTINGS["brand_name"].

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'brand_name'
   AND value = 'Secret Server';