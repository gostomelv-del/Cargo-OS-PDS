BEGIN;

ALTER TABLE policy_versions
    ADD COLUMN signer_id TEXT,
    ADD COLUMN key_id TEXT,
    ADD COLUMN signature_algorithm TEXT,
    ADD COLUMN signed_at TIMESTAMPTZ,
    ADD COLUMN signature_value TEXT;

ALTER TABLE policy_versions
    ADD CONSTRAINT policy_versions_signature_complete CHECK (
        num_nulls(signer_id, key_id, signature_algorithm, signed_at, signature_value) = 5
        OR
        (num_nulls(signer_id, key_id, signature_algorithm, signed_at, signature_value) = 0
            AND signer_id <> '' AND key_id <> '' AND signature_algorithm <> ''
            AND signature_value <> '')
    );

COMMIT;
