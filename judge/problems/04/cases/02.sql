-- 예시용 가짜 데이터 (실제 CVE 아님)

INSERT INTO software (software_id, name, source_package) VALUES
  (1, 'Apache HTTP Server', 'apache2'),
  (2, 'OpenSSH', 'openssh');

INSERT INTO vulnerabilities (cve_id, description, cvss_score) VALUES
  ('CVE-0000-0001', '[FAKE] 예시 취약점 0001', '9.8');

INSERT INTO systems (system_id, hostname, ubuntu_release, environment) VALUES
  (1, 'web-01', '24.04', 'prod');

INSERT INTO installed_software (system_id, software_id, installed_version) VALUES
  (1, 1, '2.4.58-1ubuntu8.99'),
  (1, 2, '1:9.6p1-3ubuntu13.99');

INSERT INTO staff (staff_id, name, team, email) VALUES
  (1, '김보안', '보안팀', 'kim.security@example.com'),
  (2, '이서버', '인프라팀', 'lee.infra@example.com'),
  (3, '박운영', '운영팀', 'park.ops@example.com');

INSERT INTO system_vulnerabilities (sv_id, system_id, cve_id, software_id, status, assignee_id, due_date, detected_at, patched_at, updated_by) VALUES
  (1, 1, 'CVE-0000-0001', 2, 'in_progress', 1, '2026-11-30', '2026-11-01 09:00:00', NULL, 2);
