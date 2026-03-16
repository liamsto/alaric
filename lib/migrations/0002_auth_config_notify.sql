CREATE OR REPLACE FUNCTION notify_auth_config_changed()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('alaric_auth_config_changed', TG_TABLE_NAME || ':' || TG_OP);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_principals_auth_config_changed ON principals;
CREATE TRIGGER trg_principals_auth_config_changed
AFTER INSERT OR UPDATE OF kind, external_id, disabled_at OR DELETE
ON principals
FOR EACH ROW
EXECUTE FUNCTION notify_auth_config_changed();

DROP TRIGGER IF EXISTS trg_principal_keys_auth_config_changed ON principal_keys;
CREATE TRIGGER trg_principal_keys_auth_config_changed
AFTER INSERT OR UPDATE OF principal_id, key_id, algorithm, public_key, valid_from, valid_to, revoked_at OR DELETE
ON principal_keys
FOR EACH ROW
EXECUTE FUNCTION notify_auth_config_changed();
