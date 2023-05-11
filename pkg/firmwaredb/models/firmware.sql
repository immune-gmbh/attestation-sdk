
-- this is not a real production-ready model, it is just a demonstration
CREATE TABLE IF NOT EXISTS `firmware` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `type` ENUM("BIOS", "BMC", "NIC", "SSD"),
    `version` VARCHAR(255),
	`image_url` BLOB,
    PRIMARY KEY (`id`),
    KEY `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
