
CREATE TABLE IF NOT EXISTS `analyzer_report` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `analyze_report_id` BIGINT UNSIGNED NOT NULL,
    `analyzer_id` VARCHAR(64) NOT NULL,
    `exec_error` JSON DEFAULT NULL,
    `input` JSON DEFAULT NULL,
    `report` JSON DEFAULT NULL,
    `diagnosis_code` VARCHAR(255) NULL,
    `input_actual_firmware_image_id` BINARY(128) DEFAULT NULL,
    `input_original_firmware_image_id` BINARY(128) DEFAULT NULL,
    `exec_error_code` ENUM('OK', 'ErrNotApplicable', 'ErrOther') DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `analyze_report_id` (`analyze_report_id`),
    KEY `analyzer_diagnosis` (`analyzer_id`, `diagnosis_code`),
    KEY `input_actual_firmware_image_id` (`input_actual_firmware_image_id`),
    KEY `input_original_firmware_image_id` (`input_original_firmware_image_id`),
    KEY `exec_error_code` (`exec_error_code`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;

-- Columns input_actual_firmware_image_id, input_original_firmware_image_id and exec_error_code
-- supposed to be VIRTUAL, but AOSC does not support that. And it also does not support
-- `DEFAULT (..stuff-here..)` properties. So the only way left is to duplicate source
-- of truth and set this values from the AFAS side :(
--
-- Also AOSC does not support `COMMENT`, so I'm writing this right here :(
