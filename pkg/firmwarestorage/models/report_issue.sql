CREATE TABLE IF NOT EXISTS report_issue (
    `id` BIGINT unsigned NOT NULL AUTO_INCREMENT,
    `analyzer_report_id` BIGINT NOT NULL,
    `custom` TEXT DEFAULT NULL,
    `severity` TINYINT,
    `description` TEXT DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `analyzer_report_id` (`analyzer_report_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
