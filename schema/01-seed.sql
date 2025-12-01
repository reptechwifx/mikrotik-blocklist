INSERT INTO bl_sources (name, url, delimiter, cidr_mode, timeout_hours, comment)
VALUES
  ('DShield', 'https://www.dshield.org/block.txt', '\t', '24', 2, 'DShield'),
  ('BlockList.de', 'https://lists.blocklist.de/lists/all.txt', '\n', 'auto', 2, 'BlockList.de'),
ON DUPLICATE KEY UPDATE
  url           = VALUES(url),
  delimiter     = VALUES(delimiter),
  cidr_mode     = VALUES(cidr_mode),
  timeout_hours = VALUES(timeout_hours),
  comment       = VALUES(comment);
