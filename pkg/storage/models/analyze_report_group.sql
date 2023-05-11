
CREATE TABLE IF NOT EXISTS `analyze_report_group` (
    `group_key` BINARY(128),
    `post_id` BIGINT UNSIGNED DEFAULT NULL,
    `task_id` BIGINT UNSIGNED DEFAULT NULL,
    PRIMARY KEY (`group_key`),
    KEY `post_id` (`post_id`),
    KEY `task_id` (`task_id`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
