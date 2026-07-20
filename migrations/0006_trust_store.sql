BEGIN;

CREATE TABLE trusted_verification_keys (
    signer_id TEXT NOT NULL CHECK (signer_id <> ''),
    key_id TEXT NOT NULL CHECK (key_id <> ''),
    algorithm TEXT NOT NULL CHECK (algorithm <> ''),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (signer_id, key_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE TABLE trust_key_revocations (
    signer_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (signer_id, key_id),
    FOREIGN KEY (signer_id, key_id)
        REFERENCES trusted_verification_keys (signer_id, key_id)
);

CREATE OR REPLACE FUNCTION cargoos_reject_trust_store_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Trust Store records are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION cargoos_validate_key_revocation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_valid_from TIMESTAMPTZ;
BEGIN
    SELECT valid_from INTO key_valid_from
      FROM trusted_verification_keys
     WHERE signer_id = NEW.signer_id AND key_id = NEW.key_id;
    IF NEW.revoked_at < key_valid_from THEN
        RAISE EXCEPTION 'Key revocation precedes key validity'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trusted_verification_keys_immutable
BEFORE UPDATE OR DELETE ON trusted_verification_keys
FOR EACH ROW EXECUTE FUNCTION cargoos_reject_trust_store_mutation();

CREATE TRIGGER trust_key_revocations_immutable
BEFORE UPDATE OR DELETE ON trust_key_revocations
FOR EACH ROW EXECUTE FUNCTION cargoos_reject_trust_store_mutation();

CREATE TRIGGER trust_key_revocations_valid_time
BEFORE INSERT ON trust_key_revocations
FOR EACH ROW EXECUTE FUNCTION cargoos_validate_key_revocation();

COMMIT;
