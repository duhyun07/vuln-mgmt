-- =====================================================================
-- vuln_mgmt — 무결성 테스트 케이스
--
-- tests/run_tests.sh가 이 파일을 블록 단위로 잘라 실행한다.
-- 각 블록은 START TRANSACTION ... ROLLBACK 안에서 따로 실행되므로
-- 시드 데이터는 변하지 않는다. (실패 시에는 연결이 끊기며 자동 롤백)
-- 전제: seed.sql이 적재된 상태.
--
-- 블록 형식
--   -- @test: <ID> <설명>
--   -- @expect: error <MySQL 오류 코드>   ← 이 오류로 실패해야 PASS
--   -- @expect: result <값>               ← 성공하고 마지막 출력값이 일치해야 PASS
--   <SQL ...>
--   -- @end
--
-- 주요 오류 코드
--   1062 중복 키 (PK/UNIQUE)          3819 CHECK 제약조건 위반
--   1452 FK 부모 행 없음 (자식 INSERT) 1451 FK 자식 행 존재 (부모 DELETE)
--   1265 ENUM 등에 허용되지 않는 값 (strict 모드)
--
-- 주의: 이 파일을 mysql에 통째로 넣으면 첫 실패에서 멈춘다. run_tests.sh를 사용할 것.
-- =====================================================================


-- ---------------------------------------------------------------------
-- vulnerabilities
-- ---------------------------------------------------------------------

-- @test: T01 중복 cve_id INSERT → 실패해야 함 (PK)
-- @expect: error 1062
INSERT INTO vulnerabilities (cve_id, description) VALUES ('CVE-0000-0001', 'dup');
-- @end

-- @test: T02 형식이 잘못된 cve_id 'CVE-ABC' → 실패해야 함 (CHECK)
-- @expect: error 3819
INSERT INTO vulnerabilities (cve_id, description) VALUES ('CVE-ABC', 'bad format');
-- @end

-- @test: T03 소문자 cve_id 'cve-0000-9999' → 실패해야 함 (CHECK, 대소문자 구분)
-- @expect: error 3819
INSERT INTO vulnerabilities (cve_id, description) VALUES ('cve-0000-9999', 'lowercase');
-- @end

-- @test: T04 cvss_score 11.0 → 실패해야 함 (CHECK)
-- @expect: error 3819
INSERT INTO vulnerabilities (cve_id, cvss_score) VALUES ('CVE-0000-9999', 11.0);
-- @end

-- @test: T05 cvss_score -0.1 → 실패해야 함 (CHECK)
-- @expect: error 3819
INSERT INTO vulnerabilities (cve_id, cvss_score) VALUES ('CVE-0000-9999', -0.1);
-- @end

-- @test: T06 cvss_score 생략 시 0이 아니라 NULL로 저장 → 성공, 결과 1
-- @expect: result 1
INSERT INTO vulnerabilities (cve_id, description) VALUES ('CVE-0000-9999', 'no score');
SELECT cvss_score IS NULL FROM vulnerabilities WHERE cve_id = 'CVE-0000-9999';
-- @end


-- ---------------------------------------------------------------------
-- cve_package_status
-- ---------------------------------------------------------------------

-- @test: T07 status='released'인데 fixed_version NULL → 실패해야 함 (CHECK)
-- @expect: error 3819
INSERT INTO cve_package_status (cve_id, software_id, ubuntu_release, status, fixed_version)
VALUES ('CVE-0000-0003', 1, '20.04', 'released', NULL);
-- @end


-- ---------------------------------------------------------------------
-- system_vulnerabilities
-- ---------------------------------------------------------------------

-- @test: T08 존재하지 않는 system_id(9999)로 조치 건 INSERT → 실패해야 함 (FK)
-- @expect: error 1452
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id)
VALUES (9999, 'CVE-0000-0001', 1);
-- @end

-- @test: T09 서버에 설치되지 않은 소프트웨어(dev-01 + apache2) 조치 건 INSERT → 실패해야 함 (복합 FK)
-- @expect: error 1452
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id)
VALUES ((SELECT system_id FROM systems WHERE hostname = 'dev-01'),
        'CVE-0000-0003',
        (SELECT software_id FROM software WHERE source_package = 'apache2'));
-- @end

-- @test: T10 존재하지 않는 cve_id로 조치 건 INSERT → 실패해야 함 (FK)
-- @expect: error 1452
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id)
VALUES (1, 'CVE-0000-8888', 1);
-- @end

-- @test: T11 같은 (system_id, cve_id) 중복 INSERT → 실패해야 함 (UNIQUE)
-- @expect: error 1062
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id)
VALUES (1, 'CVE-0000-0001', 1);
-- @end

-- @test: T12 status='patched'인데 patched_at NULL로 INSERT → 실패해야 함 (CHECK)
-- @expect: error 3819
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id, status, patched_at)
VALUES (2, 'CVE-0000-0003', 1, 'patched', NULL);
-- @end

-- @test: T13 patched_at 없이 status만 'patched'로 UPDATE → 실패해야 함 (CHECK)
-- @expect: error 3819
UPDATE system_vulnerabilities SET status = 'patched', updated_by = 1 WHERE sv_id = 1;
-- @end

-- @test: T14 허용되지 않는 status 값 'done' → 실패해야 함 (ENUM, strict 모드)
-- @expect: error 1265
UPDATE system_vulnerabilities SET status = 'done', updated_by = 1 WHERE sv_id = 1;
-- @end


-- ---------------------------------------------------------------------
-- 트리거 → patch_history
-- ---------------------------------------------------------------------

-- @test: T15 정상 상태 UPDATE(open→in_progress) → 성공, patch_history 1건 증가
-- @expect: result 1
SET @before = (SELECT COUNT(*) FROM patch_history);
UPDATE system_vulnerabilities SET status = 'in_progress', updated_by = 1 WHERE sv_id = 1;
SELECT (SELECT COUNT(*) FROM patch_history) - @before;
-- @end

-- @test: T16 같은 상태로 UPDATE(open→open, 기한 변경) → 성공, patch_history 변화 없음
-- @expect: result 0
SET @before = (SELECT COUNT(*) FROM patch_history);
UPDATE system_vulnerabilities
   SET status = 'open', due_date = DATE_ADD(CURDATE(), INTERVAL 60 DAY), updated_by = 1
 WHERE sv_id = 1;
SELECT (SELECT COUNT(*) FROM patch_history) - @before;
-- @end

-- @test: T17 UPDATE 이력의 old/new 상태와 changed_by(=updated_by)가 정확히 기록됨
-- @expect: result open>in_progress@3
UPDATE system_vulnerabilities SET status = 'in_progress', updated_by = 3 WHERE sv_id = 3;
SELECT CONCAT(old_status, '>', new_status, '@', changed_by)
  FROM patch_history WHERE sv_id = 3 ORDER BY history_id DESC LIMIT 1;
-- @end

-- @test: T18 조치 건 INSERT → patch_history에 (NULL → open) 1건 기록
-- @expect: result NULL>open@2
INSERT INTO system_vulnerabilities (system_id, cve_id, software_id, updated_by)
VALUES (2, 'CVE-0000-0003', 1, 2);
SELECT CONCAT(IFNULL(old_status, 'NULL'), '>', new_status, '@', changed_by)
  FROM patch_history WHERE sv_id = LAST_INSERT_ID();
-- @end

-- @test: T19 조치 건 DELETE → 해당 patch_history 연쇄 삭제 (CASCADE), 남은 이력 0
-- @expect: result 0
DELETE FROM system_vulnerabilities WHERE sv_id = 5;
SELECT COUNT(*) FROM patch_history WHERE sv_id = 5;
-- @end


-- ---------------------------------------------------------------------
-- 삭제 제한 (ON DELETE RESTRICT)
-- ---------------------------------------------------------------------

-- @test: T20 조치 건이 배정된 담당자 DELETE → 실패해야 함 (RESTRICT)
-- @expect: error 1451
DELETE FROM staff WHERE staff_id = 1;
-- @end

-- @test: T21 조치 건이 있는 CVE DELETE → 실패해야 함 (RESTRICT)
-- @expect: error 1451
DELETE FROM vulnerabilities WHERE cve_id = 'CVE-0000-0001';
-- @end

-- @test: T22 조치 건이 걸린 설치 정보 DELETE → 실패해야 함 (복합 FK RESTRICT)
-- @expect: error 1451
DELETE FROM installed_software WHERE system_id = 1 AND software_id = 1;
-- @end


-- ---------------------------------------------------------------------
-- 뷰
-- ---------------------------------------------------------------------

-- @test: T23 조치 건이 0개인 서버도 v_system_patch_rate에 나오고 완료율은 NULL
-- @expect: result 0|NULL
INSERT INTO systems (hostname, ubuntu_release, environment) VALUES ('stg-empty-01', '24.04', 'staging');
SELECT CONCAT(total_count, '|', IFNULL(patch_rate_pct, 'NULL'))
  FROM v_system_patch_rate WHERE hostname = 'stg-empty-01';
-- @end
