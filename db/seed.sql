-- =====================================================================
-- vuln_mgmt — 개발용 시드 데이터
--
-- !!! 개발용 가짜 데이터, 실제 CVE 아님 !!!
-- CVE-0000-xxxx 번호, 설명, 점수, 패키지 버전, USN 번호, 서버, 담당자는
-- 모두 지어낸 값이다. 실제 데이터는 데이터 수집 담당이 별도로 적재한다.
--
-- 날짜는 CURDATE()/NOW() 기준 상대값이라 언제 적재해도
-- "기한 지남" 같은 분석 결과가 동일하게 나온다.
-- 전제: schema.sql을 먼저 실행한 빈 DB.
-- =====================================================================

USE vuln_mgmt;
SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

START TRANSACTION;

-- ---------------------------------------------------------------------
-- software (software_id 1 = apache2, 2 = openssh)
-- ---------------------------------------------------------------------
INSERT INTO software (software_id, name, source_package) VALUES
  (1, 'Apache HTTP Server', 'apache2'),
  (2, 'OpenSSH',            'openssh');

-- ---------------------------------------------------------------------
-- vulnerabilities (가짜 CVE 5개)
--   0001: CVSS 9.8 (apache2)    0002: CVSS 7.5 (openssh)
--   0003: CVSS 5.3 (apache2)    0004: CVSS 없음 = NULL (openssh)
--   0005: CVSS 4.3 (apache2)
-- ---------------------------------------------------------------------
INSERT INTO vulnerabilities
  (cve_id, description, published_date, cvss_score, cvss_version, cvss_vector, cvss_source, ubuntu_priority, source_url)
VALUES
  ('CVE-0000-0001', '[FAKE] mod_fake 요청 처리 중 원격 코드 실행', DATE_SUB(CURDATE(), INTERVAL 40 DAY),
   9.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'NVD', 'high', NULL),
  ('CVE-0000-0002', '[FAKE] sshd 인증 단계 경쟁 조건으로 인한 권한 상승', DATE_SUB(CURDATE(), INTERVAL 30 DAY),
   7.5, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'NVD', 'medium', NULL),
  ('CVE-0000-0003', '[FAKE] 특정 헤더 처리 시 정보 노출', DATE_SUB(CURDATE(), INTERVAL 20 DAY),
   5.3, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 'NVD', 'medium', NULL),
  ('CVE-0000-0004', '[FAKE] scp 클라이언트 경로 처리 문제 (점수 미산정)', DATE_SUB(CURDATE(), INTERVAL 7 DAY),
   NULL, NULL, NULL, NULL, 'low', NULL),
  ('CVE-0000-0005', '[FAKE] mod_fake_proxy 로그 위조', DATE_SUB(CURDATE(), INTERVAL 10 DAY),
   4.3, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N', 'NVD', 'low', NULL);

-- ---------------------------------------------------------------------
-- cve_package_status (모든 CVE에 24.04 행 1개 이상)
-- ---------------------------------------------------------------------
INSERT INTO cve_package_status
  (cve_id, software_id, ubuntu_release, status, fixed_version, usn_id, source_url)
VALUES
  ('CVE-0000-0001', 1, '24.04', 'released',     '2.4.58-1ubuntu8.99', 'USN-0000-1', NULL),
  ('CVE-0000-0001', 1, '22.04', 'released',     '2.4.52-1ubuntu4.99', 'USN-0000-1', NULL),
  ('CVE-0000-0002', 2, '24.04', 'released',     '1:9.6p1-3ubuntu13.99', 'USN-0000-2', NULL),
  ('CVE-0000-0003', 1, '24.04', 'needed',       NULL, NULL, NULL),
  ('CVE-0000-0003', 1, '22.04', 'not-affected', NULL, NULL, NULL),
  ('CVE-0000-0004', 2, '24.04', 'deferred',     NULL, NULL, NULL),
  ('CVE-0000-0005', 1, '24.04', 'needed',       NULL, NULL, NULL);

-- ---------------------------------------------------------------------
-- systems (prod 2대, dev 1대)
-- ---------------------------------------------------------------------
INSERT INTO systems (system_id, hostname, ubuntu_release, environment) VALUES
  (1, 'web-prod-01', '24.04', 'prod'),
  (2, 'web-prod-02', '24.04', 'prod'),
  (3, 'dev-01',      '24.04', 'dev');

-- ---------------------------------------------------------------------
-- installed_software
--   dev-01에는 apache2가 없다 → dev-01 + apache2 취약점은 복합 FK로 거부됨
-- ---------------------------------------------------------------------
INSERT INTO installed_software (system_id, software_id, installed_version, collected_at) VALUES
  (1, 1, '2.4.58-1ubuntu8.4',    NOW()),
  (1, 2, '1:9.6p1-3ubuntu13.5',  NOW()),
  (2, 1, '2.4.58-1ubuntu8.99',   NOW()),
  (2, 2, '1:9.6p1-3ubuntu13.5',  NOW()),
  (3, 2, '1:9.6p1-3ubuntu13.99', NOW());

-- ---------------------------------------------------------------------
-- staff
-- ---------------------------------------------------------------------
INSERT INTO staff (staff_id, name, team, email) VALUES
  (1, '김보안', '보안팀',   'kim.security@example.com'),
  (2, '이서버', '인프라팀', 'lee.infra@example.com'),
  (3, '박운영', '운영팀',   'park.ops@example.com');

-- ---------------------------------------------------------------------
-- system_vulnerabilities (9건) — 모두 'open'으로 등록 후 아래 UPDATE로 진행
--   INSERT 트리거가 patch_history에 (NULL → open) 이력 9건을 남긴다.
--   updated_by NULL = 자동 탐지 스크립트가 등록
--
--  sv | 서버        | CVE  | 최종 상태      | 담당   | 기한
--   1 | web-prod-01 | 0001 | open           | 김보안 | 10일 전 (기한 지남)
--   2 | web-prod-01 | 0002 | in_progress    | 이서버 | 3일 전  (기한 지남)
--   3 | web-prod-01 | 0003 | open           | 없음   | 14일 후
--   4 | web-prod-01 | 0004 | open           | 없음   | 없음
--   5 | web-prod-02 | 0001 | patched        | 김보안 | 5일 전  (완료)
--   6 | web-prod-02 | 0002 | risk_accepted  | 박운영 | 없음
--   7 | web-prod-02 | 0005 | open           | 박운영 | 30일 후
--   8 | dev-01      | 0002 | patched        | 이서버 | 7일 후
--   9 | dev-01      | 0004 | patched        | 이서버 | 없음
--  → dev-01 완료율 100%, CVE-0000-0001/0002/0004는 여러 서버에 존재
-- ---------------------------------------------------------------------
INSERT INTO system_vulnerabilities
  (sv_id, system_id, cve_id, software_id, status, assignee_id, due_date, detected_at, updated_by)
VALUES
  (1, 1, 'CVE-0000-0001', 1, 'open', 1,    DATE_SUB(CURDATE(), INTERVAL 10 DAY), DATE_SUB(NOW(), INTERVAL 35 DAY), NULL),
  (2, 1, 'CVE-0000-0002', 2, 'open', 2,    DATE_SUB(CURDATE(), INTERVAL 3 DAY),  DATE_SUB(NOW(), INTERVAL 25 DAY), NULL),
  (3, 1, 'CVE-0000-0003', 1, 'open', NULL, DATE_ADD(CURDATE(), INTERVAL 14 DAY), DATE_SUB(NOW(), INTERVAL 15 DAY), NULL),
  (4, 1, 'CVE-0000-0004', 2, 'open', NULL, NULL,                                 DATE_SUB(NOW(), INTERVAL 5 DAY),  NULL),
  (5, 2, 'CVE-0000-0001', 1, 'open', 1,    DATE_SUB(CURDATE(), INTERVAL 5 DAY),  DATE_SUB(NOW(), INTERVAL 35 DAY), NULL),
  (6, 2, 'CVE-0000-0002', 2, 'open', 3,    NULL,                                 DATE_SUB(NOW(), INTERVAL 25 DAY), NULL),
  (7, 2, 'CVE-0000-0005', 1, 'open', 3,    DATE_ADD(CURDATE(), INTERVAL 30 DAY), DATE_SUB(NOW(), INTERVAL 8 DAY),  NULL),
  (8, 3, 'CVE-0000-0002', 2, 'open', 2,    DATE_ADD(CURDATE(), INTERVAL 7 DAY),  DATE_SUB(NOW(), INTERVAL 25 DAY), 2),
  (9, 3, 'CVE-0000-0004', 2, 'open', 2,    NULL,                                 DATE_SUB(NOW(), INTERVAL 5 DAY),  2);

-- ---------------------------------------------------------------------
-- 상태 변경 (규칙: status를 바꿀 때 updated_by를 반드시 함께 SET)
--   UPDATE 트리거가 patch_history에 7건을 추가 → 총 16건
-- ---------------------------------------------------------------------
-- sv 2: open → in_progress
UPDATE system_vulnerabilities SET status = 'in_progress', updated_by = 2 WHERE sv_id = 2;

-- sv 5: open → in_progress → patched
UPDATE system_vulnerabilities SET status = 'in_progress', updated_by = 1 WHERE sv_id = 5;
UPDATE system_vulnerabilities
   SET status = 'patched', patched_at = DATE_SUB(NOW(), INTERVAL 6 DAY), updated_by = 1
 WHERE sv_id = 5;

-- sv 6: open → risk_accepted
UPDATE system_vulnerabilities SET status = 'risk_accepted', updated_by = 3 WHERE sv_id = 6;

-- sv 8: open → patched
UPDATE system_vulnerabilities
   SET status = 'patched', patched_at = DATE_SUB(NOW(), INTERVAL 2 DAY), updated_by = 2
 WHERE sv_id = 8;

-- sv 9: open → in_progress → patched
UPDATE system_vulnerabilities SET status = 'in_progress', updated_by = 2 WHERE sv_id = 9;
UPDATE system_vulnerabilities
   SET status = 'patched', patched_at = DATE_SUB(NOW(), INTERVAL 1 DAY), updated_by = 2
 WHERE sv_id = 9;

-- 상태 변경 없는 UPDATE (기한만 변경) → 이력이 추가되지 않아야 함
UPDATE system_vulnerabilities SET due_date = DATE_ADD(CURDATE(), INTERVAL 14 DAY), updated_by = 1 WHERE sv_id = 3;

-- risk_accepted 사유를 이력에 남기는 예시 (트리거가 만든 최신 행에 note 추가)
UPDATE patch_history
   SET note = '내부망 전용 서버, 다음 정기 점검 때 재검토'
 WHERE sv_id = 6 AND new_status = 'risk_accepted';

COMMIT;
