
-- this is not a real production-ready model, it is just a demonstration
CREATE TABLE IF NOT EXISTS `firmware_target` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`firmware_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware`.`id`', 
	`model_id` BIGINT UNSIGNED DEFAULT NULL,
	`hostname` VARCHAR(255) DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `firmware_id` (`firmware_id`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
