CREATE TABLE IF NOT EXISTS bl_sources (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  name          VARCHAR(64)  NOT NULL,
  url           VARCHAR(512) NOT NULL,
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,

  `delimiter`   VARCHAR(16)  NOT NULL DEFAULT '\n',
  cidr_mode     ENUM('32','24','auto') NOT NULL DEFAULT '32',

  timeout_hours INT NOT NULL DEFAULT 2,
  comment       VARCHAR(64) NOT NULL DEFAULT 'blocklist',

  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

  INDEX idx_bl_sources_active (is_active)
);
