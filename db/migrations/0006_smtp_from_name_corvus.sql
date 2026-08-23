-- Rewrite leftover product names seeded by older defaults. Do not edit 0001:
-- its checksum is already recorded on existing databases.

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'smtp_from_name'
   AND value IN ('Sigaint Secret Server', 'Sigaint');

UPDATE private.server_settings
   SET value = 'Corvus'
 WHERE key = 'brand_name'
   AND value IN ('Sigaint', 'Sigaint Secret Server');

UPDATE private.server_settings
   SET value = 'Keep your secrets.'
 WHERE key = 'brand_tagline'
   AND value IN ('Secret Server', 'Secret Server v0.1.0', '');

INSERT INTO private.server_settings (key, value)
VALUES ('brand_tagline', 'Keep your secrets.')
ON CONFLICT (key) DO NOTHING;
