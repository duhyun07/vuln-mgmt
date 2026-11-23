-- 예시용 가짜 데이터 (실제 CVE 아님)

INSERT INTO software (software_id, name, source_package) VALUES
  (1, 'Apache HTTP Server', 'apache2'),
  (2, 'OpenSSH', 'openssh');

INSERT INTO vulnerabilities (cve_id, description, cvss_score) VALUES
  ('CVE-0000-0001', '[FAKE] 예시 취약점 0001', '9.8'),
  ('CVE-0000-0002', '[FAKE] 예시 취약점 0002', '7.5'),
  ('CVE-0000-0003', '[FAKE] 예시 취약점 0003', NULL),
  ('CVE-0000-0004', '[FAKE] 예시 취약점 0004', '5.3');

INSERT INTO systems (system_id, hostname, ubuntu_release, environment) VALUES
  (1, 'web-01', '24.04', 'prod'),
  (2, 'web-02', '24.04', 'prod'),
  (3, 'db-01', '24.04', 'prod'),
  (4, 'dev-01', '24.04', 'dev');

INSERT INTO installed_software (system_id, software_id, installed_version) VALUES
  (1, 1, '2.4.58-1ubuntu8.99'),
  (1, 2, '1:9.6p1-3ubuntu13.99'),
  (2, 1, '2.4.58-1ubuntu8.99'),
  (2, 2, '1:9.6p1-3ubuntu13.99'),
  (3, 1, '2.4.58-1ubuntu8.99'),
  (3, 2, '1:9.6p1-3ubuntu13.99'),
  (4, 1, '2.4.58-1ubuntu8.99'),
  (4, 2, '1:9.6p1-3ubuntu13.99');

INSERT INTO staff (staff_id, name, team, email) VALUES
  (1, '김보안', '보안팀', 'kim.security@example.com'),
  (2, '이서버', '인프라팀', 'lee.infra@example.com'),
  (3, '박운영', '운영팀', 'park.ops@example.com');

INSERT INTO system_vulnerabilities (sv_id, system_id, cve_id, software_id, status, assignee_id, due_date, detected_at, patched_at, updated_by) VALUES
  (1, 1, 'CVE-0000-0001', 2, 'open', 1, NULL, '2026-11-01 09:00:00', NULL, NULL),
  (2, 1, 'CVE-0000-0002', 1, 'open', NULL, NULL, '2026-11-01 09:00:00', NULL, NULL),
  (3, 1, 'CVE-0000-0003', 2, 'in_progress', 2, NULL, '2026-11-01 09:00:00', NULL, 2),
  (4, 2, 'CVE-0000-0001', 2, 'open', 1, NULL, '2026-11-01 09:00:00', NULL, NULL),
  (5, 2, 'CVE-0000-0002', 1, 'patched', 1, NULL, '2026-11-01 09:00:00', '2026-11-20 10:00:00', 1),
  (6, 3, 'CVE-0000-0001', 2, 'in_progress', 2, NULL, '2026-11-01 09:00:00', NULL, 2),
  (7, 3, 'CVE-0000-0004', 1, 'risk_accepted', 3, NULL, '2026-11-01 09:00:00', NULL, 3),
  (8, 4, 'CVE-0000-0001', 2, 'patched', 2, NULL, '2026-11-01 09:00:00', '2026-11-21 10:00:00', 2);
