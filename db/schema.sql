-- =====================================================================
-- Ubuntu 보안 취약점·패치 관리 DB (vuln_mgmt) — 스키마
-- MySQL 8.0.16+ / InnoDB / utf8mb4 / utf8mb4_0900_ai_ci
--
-- 이 파일은 몇 번이고 다시 실행할 수 있다(DROP 후 CREATE).
-- 주의: 기존 데이터가 모두 삭제된다.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS vuln_mgmt
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_0900_ai_ci;
USE vuln_mgmt;

SET NAMES utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------
-- DROP (의존 관계 역순)
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_system_patch_rate;
DROP VIEW IF EXISTS v_open_risks;

DROP TABLE IF EXISTS patch_history;
DROP TABLE IF EXISTS system_vulnerabilities;
DROP TABLE IF EXISTS staff;
DROP TABLE IF EXISTS installed_software;
DROP TABLE IF EXISTS systems;
DROP TABLE IF EXISTS cve_package_status;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS software;

-- ---------------------------------------------------------------------
-- 1. software — 관리 대상 소프트웨어 (실제 데이터)
-- ---------------------------------------------------------------------
CREATE TABLE software (
  software_id     INT           NOT NULL AUTO_INCREMENT COMMENT '소프트웨어 ID',
  name            VARCHAR(100)  NOT NULL COMMENT '표시 이름 (예: Apache HTTP Server)',
  source_package  VARCHAR(100)  NOT NULL COMMENT 'Ubuntu 소스 패키지명 (예: apache2, openssh)',
  CONSTRAINT pk_software PRIMARY KEY (software_id),
  CONSTRAINT uq_software_name UNIQUE (name),
  CONSTRAINT uq_software_source_package UNIQUE (source_package)
) ENGINE=InnoDB COMMENT='관리 대상 소프트웨어';

-- ---------------------------------------------------------------------
-- 2. vulnerabilities — CVE 정보 (실제 데이터)
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
  cve_id           VARCHAR(20)   NOT NULL COMMENT 'CVE 식별자 (CVE-YYYY-NNNN...)',
  description      TEXT          NULL     COMMENT 'CVE 설명',
  published_date   DATE          NULL     COMMENT 'CVE 공개일',
  cvss_score       DECIMAL(3,1)  NULL     COMMENT 'CVSS 기본 점수 0.0~10.0, 없으면 NULL',
  cvss_version     VARCHAR(5)    NULL     COMMENT 'CVSS 버전 (3.1, 4.0 등)',
  cvss_vector      VARCHAR(200)  NULL     COMMENT 'CVSS 벡터 문자열',
  cvss_source      VARCHAR(50)   NULL     COMMENT '점수 출처 (NVD, Ubuntu 등)',
  ubuntu_priority  ENUM('negligible','low','medium','high','critical') NULL COMMENT 'Ubuntu 보안팀 우선순위',
  source_url       VARCHAR(500)  NULL     COMMENT '수집 출처 URL',
  created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '행 생성 시각',
  CONSTRAINT pk_vulnerabilities PRIMARY KEY (cve_id),
  -- 'c' = 대소문자 구분 (ai_ci 콜레이션에서도 소문자 'cve-'를 거부)
  CONSTRAINT chk_vuln_cve_id_format
    CHECK (REGEXP_LIKE(cve_id, '^CVE-[0-9]{4}-[0-9]{4,}$', 'c')),
  CONSTRAINT chk_vuln_cvss_score_range
    CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0.0 AND 10.0)
) ENGINE=InnoDB COMMENT='CVE 취약점 정보';

-- ---------------------------------------------------------------------
-- 3. cve_package_status — Ubuntu 릴리스·패키지별 영향/수정 상태 (실제 데이터)
-- ---------------------------------------------------------------------
CREATE TABLE cve_package_status (
  cve_id          VARCHAR(20)   NOT NULL COMMENT 'CVE 식별자',
  software_id     INT           NOT NULL COMMENT '소프트웨어 ID',
  ubuntu_release  VARCHAR(10)   NOT NULL COMMENT 'Ubuntu 릴리스 (예: 24.04)',
  status          ENUM('needed','released','not-affected','deferred','ignored') NOT NULL COMMENT 'Ubuntu 수정 상태',
  fixed_version   VARCHAR(100)  NULL     COMMENT '수정된 패키지 버전 (released일 때 필수)',
  usn_id          VARCHAR(20)   NULL     COMMENT 'Ubuntu Security Notice ID (예: USN-6000-1)',
  source_url      VARCHAR(500)  NULL     COMMENT '수집 출처 URL',
  CONSTRAINT pk_cve_package_status PRIMARY KEY (cve_id, software_id, ubuntu_release),
  CONSTRAINT fk_cps_cve FOREIGN KEY (cve_id)
    REFERENCES vulnerabilities (cve_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_cps_software FOREIGN KEY (software_id)
    REFERENCES software (software_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT chk_cps_released_has_fixed_version
    CHECK (status <> 'released' OR fixed_version IS NOT NULL),
  CONSTRAINT chk_cps_release_format
    CHECK (REGEXP_LIKE(ubuntu_release, '^[0-9]{2}[.][0-9]{2}$')),
  CONSTRAINT chk_cps_usn_format
    CHECK (usn_id IS NULL OR REGEXP_LIKE(usn_id, '^USN-[0-9]+-[0-9]+$', 'c'))
) ENGINE=InnoDB COMMENT='Ubuntu 릴리스·패키지별 CVE 영향 및 수정 상태';

-- ---------------------------------------------------------------------
-- 4. systems — 관리 대상 서버 (가상 데이터)
-- ---------------------------------------------------------------------
CREATE TABLE systems (
  system_id       INT           NOT NULL AUTO_INCREMENT COMMENT '서버 ID',
  hostname        VARCHAR(100)  NOT NULL COMMENT '호스트명',
  ubuntu_release  VARCHAR(10)   NOT NULL COMMENT 'Ubuntu 릴리스 (예: 24.04)',
  environment     ENUM('prod','staging','dev') NOT NULL COMMENT '운영 환경',
  created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '행 생성 시각',
  CONSTRAINT pk_systems PRIMARY KEY (system_id),
  CONSTRAINT uq_systems_hostname UNIQUE (hostname),
  CONSTRAINT chk_systems_release_format
    CHECK (REGEXP_LIKE(ubuntu_release, '^[0-9]{2}[.][0-9]{2}$'))
) ENGINE=InnoDB COMMENT='관리 대상 서버';

-- ---------------------------------------------------------------------
-- 5. installed_software — 서버별 설치 패키지 (가상 데이터)
--    installed_version은 Debian 버전 문자열이므로 DB에서 크기 비교하지 않는다.
-- ---------------------------------------------------------------------
CREATE TABLE installed_software (
  system_id          INT           NOT NULL COMMENT '서버 ID',
  software_id        INT           NOT NULL COMMENT '소프트웨어 ID',
  installed_version  VARCHAR(100)  NOT NULL COMMENT '설치 버전 (Debian 버전 문자열, 예: 1:9.6p1-3ubuntu13.5)',
  collected_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '버전 수집 시각',
  CONSTRAINT pk_installed_software PRIMARY KEY (system_id, software_id),
  CONSTRAINT fk_is_system FOREIGN KEY (system_id)
    REFERENCES systems (system_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_is_software FOREIGN KEY (software_id)
    REFERENCES software (software_id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB COMMENT='서버별 설치 패키지';

-- ---------------------------------------------------------------------
-- 6. staff — 조치 담당자 (가상 데이터)
-- ---------------------------------------------------------------------
CREATE TABLE staff (
  staff_id  INT           NOT NULL AUTO_INCREMENT COMMENT '담당자 ID',
  name      VARCHAR(50)   NOT NULL COMMENT '이름',
  team      VARCHAR(50)   NULL     COMMENT '소속 팀',
  email     VARCHAR(255)  NOT NULL COMMENT '이메일',
  CONSTRAINT pk_staff PRIMARY KEY (staff_id),
  CONSTRAINT uq_staff_email UNIQUE (email),
  CONSTRAINT chk_staff_email_format CHECK (email LIKE '_%@_%')
) ENGINE=InnoDB COMMENT='조치 담당자';

-- ---------------------------------------------------------------------
-- 7. system_vulnerabilities — 서버별 취약점 조치 건 (핵심 업무 테이블)
--    규칙: 앱은 status를 변경할 때 반드시 updated_by도 함께 SET 한다.
--          (트리거가 NEW.updated_by를 patch_history.changed_by로 기록)
-- ---------------------------------------------------------------------
CREATE TABLE system_vulnerabilities (
  sv_id        INT          NOT NULL AUTO_INCREMENT COMMENT '조치 건 ID',
  system_id    INT          NOT NULL COMMENT '서버 ID',
  cve_id       VARCHAR(20)  NOT NULL COMMENT 'CVE 식별자',
  software_id  INT          NOT NULL COMMENT '취약한 소프트웨어 ID (해당 서버에 설치되어 있어야 함)',
  status       ENUM('open','in_progress','patched','risk_accepted') NOT NULL DEFAULT 'open' COMMENT '조치 상태',
  assignee_id  INT          NULL     COMMENT '담당자 ID (미배정이면 NULL)',
  due_date     DATE         NULL     COMMENT '조치 기한',
  detected_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '탐지 시각',
  patched_at   DATETIME     NULL     COMMENT '패치 완료 시각 (patched일 때 필수)',
  updated_by   INT          NULL     COMMENT '마지막 변경자 staff_id (자동 처리면 NULL)',
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '마지막 변경 시각',
  CONSTRAINT pk_system_vulnerabilities PRIMARY KEY (sv_id),
  CONSTRAINT uq_sv_system_cve UNIQUE (system_id, cve_id),
  -- 복합 FK: 서버에 설치되지 않은 소프트웨어의 취약점은 등록 불가
  CONSTRAINT fk_sv_installed_software FOREIGN KEY (system_id, software_id)
    REFERENCES installed_software (system_id, software_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_sv_cve FOREIGN KEY (cve_id)
    REFERENCES vulnerabilities (cve_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_sv_assignee FOREIGN KEY (assignee_id)
    REFERENCES staff (staff_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_sv_updated_by FOREIGN KEY (updated_by)
    REFERENCES staff (staff_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT chk_sv_patched_has_patched_at
    CHECK (status <> 'patched' OR patched_at IS NOT NULL)
) ENGINE=InnoDB COMMENT='서버별 취약점 조치 건';

-- ---------------------------------------------------------------------
-- 8. patch_history — 조치 상태 변경 이력 (트리거가 기록)
-- ---------------------------------------------------------------------
CREATE TABLE patch_history (
  history_id  INT           NOT NULL AUTO_INCREMENT COMMENT '이력 ID',
  sv_id       INT           NOT NULL COMMENT '조치 건 ID',
  old_status  ENUM('open','in_progress','patched','risk_accepted') NULL COMMENT '이전 상태 (최초 등록이면 NULL)',
  new_status  ENUM('open','in_progress','patched','risk_accepted') NOT NULL COMMENT '변경 후 상태',
  changed_by  INT           NULL     COMMENT '변경자 staff_id (자동 처리면 NULL)',
  changed_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '변경 시각',
  note        VARCHAR(500)  NULL     COMMENT '비고',
  CONSTRAINT pk_patch_history PRIMARY KEY (history_id),
  CONSTRAINT fk_ph_sv FOREIGN KEY (sv_id)
    REFERENCES system_vulnerabilities (sv_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_ph_changed_by FOREIGN KEY (changed_by)
    REFERENCES staff (staff_id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB COMMENT='조치 상태 변경 이력';

-- ---------------------------------------------------------------------
-- 트리거
-- ---------------------------------------------------------------------
DELIMITER $$

CREATE TRIGGER trg_sv_after_insert
AFTER INSERT ON system_vulnerabilities
FOR EACH ROW
BEGIN
  INSERT INTO patch_history (sv_id, old_status, new_status, changed_by, changed_at, note)
  VALUES (NEW.sv_id, NULL, NEW.status, NEW.updated_by, NOW(), '조치 건 등록');
END$$

CREATE TRIGGER trg_sv_after_update
AFTER UPDATE ON system_vulnerabilities
FOR EACH ROW
BEGIN
  -- status는 NOT NULL이므로 <> 비교로 충분하다.
  IF OLD.status <> NEW.status THEN
    INSERT INTO patch_history (sv_id, old_status, new_status, changed_by, changed_at)
    VALUES (NEW.sv_id, OLD.status, NEW.status, NEW.updated_by, NOW());
  END IF;
END$$

DELIMITER ;

-- ---------------------------------------------------------------------
-- 뷰
-- ---------------------------------------------------------------------

-- 미해결(open, in_progress) 조치 건
-- is_overdue: 기한이 지났으면 1, 아니거나 기한이 없으면 0
CREATE VIEW v_open_risks AS
SELECT
  sv.sv_id,
  sv.status,
  s.system_id,
  s.hostname,
  s.environment,
  sw.software_id,
  sw.name                                 AS software_name,
  v.cve_id,
  v.cvss_score,
  v.ubuntu_priority,
  sv.assignee_id,
  st.name                                 AS assignee_name,
  sv.due_date,
  sv.detected_at,
  IF(sv.due_date IS NOT NULL AND sv.due_date < CURDATE(), 1, 0) AS is_overdue
FROM system_vulnerabilities sv
JOIN systems         s  ON s.system_id   = sv.system_id
JOIN software        sw ON sw.software_id = sv.software_id
JOIN vulnerabilities v  ON v.cve_id      = sv.cve_id
LEFT JOIN staff      st ON st.staff_id   = sv.assignee_id
WHERE sv.status IN ('open', 'in_progress');

-- 서버별 조치 현황 및 완료율
-- unresolved_count = open + in_progress, risk_accepted는 별도 집계
-- patch_rate_pct  = patched / 전체 × 100 (조치 건이 0개면 NULL)
CREATE VIEW v_system_patch_rate AS
SELECT
  s.system_id,
  s.hostname,
  s.environment,
  COUNT(sv.sv_id)                                                   AS total_count,
  COALESCE(SUM(sv.status = 'patched'), 0)                           AS patched_count,
  COALESCE(SUM(sv.status IN ('open', 'in_progress')), 0)            AS unresolved_count,
  COALESCE(SUM(sv.status = 'risk_accepted'), 0)                     AS risk_accepted_count,
  ROUND(100 * SUM(sv.status = 'patched') / NULLIF(COUNT(sv.sv_id), 0), 1) AS patch_rate_pct
FROM systems s
LEFT JOIN system_vulnerabilities sv ON sv.system_id = s.system_id
GROUP BY s.system_id, s.hostname, s.environment;
