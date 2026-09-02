-- Machine token description (free-text label, shown in UI/API lists).
-- Ponytail: plain text column, no index; follows api.projects.description convention.

ALTER TABLE api.machine_tokens
  ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
