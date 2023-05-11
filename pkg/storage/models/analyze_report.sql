
CREATE TABLE IF NOT EXISTS `analyze_report` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `job_id` BINARY(16) NOT NULL,
    `asset_id` BIGINT UNSIGNED DEFAULT NULL,
    `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `processed_at` TIMESTAMP,
    `group_key` BINARY(128) NULL,
    PRIMARY KEY (`id`),
    KEY `job_id` (`job_id`),
    KEY `asset_id` (`asset_id`),
    KEY `timestamp` (`timestamp`),
    KEY `processed_at` (`processed_at`),
    KEY `group_key` (`group_key`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
