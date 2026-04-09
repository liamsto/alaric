CREATE TYPE attestation_mode AS ENUM ('required', 'preferred', 'disabled');

ALTER TABLE principals
    ADD COLUMN attestation_mode attestation_mode NOT NULL DEFAULT 'preferred';

DROP TRIGGER IF EXISTS trg_principals_auth_config_changed ON principals;
CREATE TRIGGER trg_principals_auth_config_changed
AFTER INSERT OR UPDATE OF kind, external_id, disabled_at, attestation_mode OR DELETE
ON principals
FOR EACH ROW
EXECUTE FUNCTION notify_auth_config_changed();
