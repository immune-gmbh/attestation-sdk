CREATE TABLE IF NOT EXISTS `reproduced_pcrs` (
  `id` BIGINT unsigned NOT NULL AUTO_INCREMENT,
  `hash_stable` BINARY(128) NOT NULL,
  `registers` text,
  `registers_sha512` binary(64) NOT NULL,
  `tpm_device` enum('unknown','1.2','2.0') DEFAULT NULL,
  `pcr0_sha1` binary(20) DEFAULT NULL,
  `pcr0_sha256` binary(32) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `image_id` (`hash_stable`,`registers_sha512`,`tpm_device`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
