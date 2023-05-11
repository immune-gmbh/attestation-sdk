
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
	`type_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware_measurement_type`.`id`',
	`value` BLOB,
    PRIMARY KEY (`id`),
    KEY `firmware_id` (`firmware_id`, `type_id`),
    KEY `type_id` (`type_id`, `firmware_id`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

CREATE TABLE IF NOT EXISTS `firmware_measurement_metadata` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	`type_id` BIGINT UNSIGNED NOT NULL COMMENT 'reference to `firmware_measurement_type`.`id`',
	`key` VARCHAR(255),
	`value` BLOB,
    PRIMARY KEY (`id`),
    KEY `type_id` (`type_id`, `key`),
    KEY `key` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
