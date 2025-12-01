CREATE TABLE IF NOT EXISTS bl_sources (
  id            BIGINT PRIMARY KEY AUTO_INCREMENT,
  name          VARCHAR(64)  NOT NULL,          -- ex: "BlockList.de"
  url           VARCHAR(512) NOT NULL,
  is_active     TINYINT(1)   NOT NULL DEFAULT 1,

  delimiter     VARCHAR(16)  DEFAULT '\n',      -- "\n", "\t", "_", etc.
  cidr_mode     ENUM('32','24','auto') NOT NULL DEFAULT '32',
  -- '32'  = on stocke des IP /32
  -- '24'  = on force le /24 pour chaque IP trouvée (1.2.3.x -> 1.2.3.0/24)
  -- 'auto'= /32, mais sera éventuellement regroupé en /24 si >= seuil global

  timeout_hours INT NOT NULL DEFAULT 2,         -- timeout Mikrotik
  comment       VARCHAR(64) NOT NULL DEFAULT 'blocklist', -- comment sur l'address-list

  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP
);

-- Petit index pratique
CREATE INDEX idx_bl_sources_active ON bl_sources(is_active);
