
CREATE TABLE IF NOT EXISTS image_metadata (
    image_id VARBINARY(192) PRIMARY KEY,
    firmware_version VARCHAR(1024) DEFAULT NULL,
    filename VARCHAR(4096) DEFAULT NULL,
    size BIGINT NOT NULL,
    ts_add TIMESTAMP DEFAULT NOW(),
    ts_upload TIMESTAMP NULL DEFAULT NULL,
    hash_sha2_512 BINARY(64) NOT NULL,
    hash_blake3_512 BINARY(64) NOT NULL,
    hash_stable BINARY(128) DEFAULT NULL,
    INDEX (filename(16)),
    INDEX (firmware_version(16), firmware_date),
    INDEX (hash_sha2_512),
    INDEX (hash_blake3_512),
    UNIQUE INDEX (hash_stable)
) DEFAULT CHARSET UTF8MB4;
