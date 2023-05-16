
CREATE TABLE IF NOT EXISTS `analyzer_report` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `analyze_report_id` BIGINT UNSIGNED NOT NULL,
    `analyzer_id` VARCHAR(64) NOT NULL,
    `exec_error` JSON DEFAULT NULL,
    `input` JSON DEFAULT NULL,
    `report` JSON DEFAULT NULL,
    `diagnosis_code` VARCHAR(255) NULL,
    `input_actual_firmware_image_id` BINARY(128) GENERATED ALWAYS AS (UNHEX(input ->> '$.ActualFirmwareBlob.Blob."./pkg/server/controller.AnalyzerFirmwareAccessor".ImageID')),
    `input_original_firmware_image_id` BINARY(128) GENERATED ALWAYS AS (UNHEX(input ->> '$.OriginalFirmwareBlob.Blob."./pkg/server/controller.AnalyzerFirmwareAccessor".ImageID')),
    `exec_error_code` ENUM('OK', 'ErrNotApplicable', 'ErrOther') GENERATED ALWAYS AS (IF(exec_error IS NULL, 'OK',IF(JSON_CONTAINS_PATH(exec_error, 'one', '$**.ErrNotApplicable'), 'ErrNotApplicable', 'ErrOther'))),
    PRIMARY KEY (`id`),
    KEY `analyze_report_id` (`analyze_report_id`),
    KEY `analyzer_diagnosis` (`analyzer_id`, `diagnosis_code`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8MB4;
