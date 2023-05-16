
-- these are not a real production-ready model, it is just a demonstration

CREATE TABLE IF NOT EXISTS `firmware_measurement_type` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`name` VARCHAR(255) NOT NULL,
	`description` TEXT DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

CREATE TABLE IF NOT EXISTS `firmware_measurement` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`firmware_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware`.`id`', 
	`measurement_type_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware_measurement_type`.`id`',
	`value` BLOB,
    PRIMARY KEY (`id`),
    KEY `firmware_id` (`firmware_id`, `measurement_type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

CREATE TABLE IF NOT EXISTS `firmware_measurement_metadata` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`measurement_type_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware_measurement_type`.`id`',
	`key` BLOB,
	`value` BLOB,
    PRIMARY KEY (`id`),
    KEY `measurement_type_id` (`measurement_type_id`, `key`),
    KEY `key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
