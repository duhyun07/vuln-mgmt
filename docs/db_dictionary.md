# 데이터 사전 — vuln_mgmt

팀 공통 연동 규격이다. 컬럼 이름·타입을 바꾸려면 DB 담당과 먼저 합의한 뒤
`db/schema.sql`, 이 문서, `docs/erd.md`를 함께 고친다.

- DBMS: MySQL 8.0.16+ (개발 환경 8.0.46), InnoDB, `utf8mb4` / `utf8mb4_0900_ai_ci`
- 이름: snake_case. 시각은 모두 `DATETIME`(서버 시간대 `Asia/Seoul`), 날짜는 `DATE`
- 키 표기: **PK** 기본키, **FK** 외래키, **UK** 유니크, **AI** AUTO_INCREMENT
- 문자열 비교는 대소문자를 구분하지 않는다(`_ai_ci`). `cve_id` 형식 검사만 대소문자를 구분한다.

---

## ⚠️ 앱 규칙: status를 바꿀 때 updated_by도 함께 SET

`system_vulnerabilities`의 상태 변경 이력은 트리거가 `patch_history`에 자동으로 기록하고,
**변경자(`changed_by`)는 `NEW.updated_by` 값을 그대로 쓴다.**
앱이 `updated_by`를 같은 UPDATE 문에서 지정하지 않으면 이전 변경자의 ID가 그대로 남아
**엉뚱한 사람이 변경한 것으로 기록된다.**

```sql
-- ✅ 올바른 예
UPDATE system_vulnerabilities
   SET status = 'patched', patched_at = NOW(), updated_by = %s
 WHERE sv_id = %s;

-- ❌ 잘못된 예 (updated_by 누락 → 이력의 changed_by가 틀림)
UPDATE system_vulnerabilities SET status = 'in_progress' WHERE sv_id = %s;
```

- 자동화 스크립트(탐지 등)가 등록·변경할 때는 `updated_by = NULL`을 명시한다.
- `patch_history`에 직접 INSERT하지 않는다(트리거 전용). `note`를 남길 때만 UPDATE한다.
- `status = 'patched'`로 바꿀 때는 `patched_at`을 함께 지정해야 한다(CHECK 제약).

---

## 1. software — 관리 대상 소프트웨어 (실제 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| software_id | INT | N | PK, AI | | 소프트웨어 ID |
| name | VARCHAR(100) | N | UK | | 표시 이름 (예: `Apache HTTP Server`) |
| source_package | VARCHAR(100) | N | UK | | Ubuntu **소스** 패키지명 (예: `apache2`, `openssh`). 바이너리 패키지명(`openssh-server`)이 아님 |

## 2. vulnerabilities — CVE 정보 (실제 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| cve_id | VARCHAR(20) | N | PK | CHECK `^CVE-[0-9]{4}-[0-9]{4,}$` (대문자만) | CVE 식별자 |
| description | TEXT | Y | | | 설명 |
| published_date | DATE | Y | | | 공개일 |
| cvss_score | DECIMAL(3,1) | Y | | CHECK 0.0~10.0 | CVSS 기본 점수. **정보가 없으면 NULL** (0으로 채우지 말 것) |
| cvss_version | VARCHAR(5) | Y | | `3.1`, `4.0` 등 | CVSS 버전 |
| cvss_vector | VARCHAR(200) | Y | | | 벡터 문자열 (예: `CVSS:3.1/AV:N/...`) |
| cvss_source | VARCHAR(50) | Y | | `NVD`, `Ubuntu` 등 | 점수 출처 |
| ubuntu_priority | ENUM | Y | | `negligible`, `low`, `medium`, `high`, `critical` | Ubuntu 보안팀 우선순위 |
| source_url | VARCHAR(500) | Y | | | 수집 출처 URL |
| created_at | DATETIME | N | | `CURRENT_TIMESTAMP` | 행 생성 시각 |

## 3. cve_package_status — Ubuntu 릴리스·패키지별 영향/수정 상태 (실제 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| cve_id | VARCHAR(20) | N | PK, FK → vulnerabilities | | CVE |
| software_id | INT | N | PK, FK → software | | 소프트웨어 |
| ubuntu_release | VARCHAR(10) | N | PK | CHECK `^[0-9]{2}.[0-9]{2}$` (예: `24.04`) | Ubuntu 릴리스 번호. 코드명(`noble`) 아님 |
| status | ENUM | N | | `needed`, `released`, `not-affected`, `deferred`, `ignored` | Ubuntu 수정 상태 (하이픈 주의: `not-affected`) |
| fixed_version | VARCHAR(100) | Y | | CHECK: status=`released`이면 NOT NULL | 수정된 패키지 버전 |
| usn_id | VARCHAR(20) | Y | | CHECK `^USN-[0-9]+-[0-9]+$` | Ubuntu Security Notice ID |
| source_url | VARCHAR(500) | Y | | | 수집 출처 URL |

PK: (cve_id, software_id, ubuntu_release)

## 4. systems — 관리 대상 서버 (가상 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| system_id | INT | N | PK, AI | | 서버 ID |
| hostname | VARCHAR(100) | N | UK | | 호스트명 |
| ubuntu_release | VARCHAR(10) | N | | CHECK `^[0-9]{2}.[0-9]{2}$` | 설치된 Ubuntu 릴리스 |
| environment | ENUM | N | | `prod`, `staging`, `dev` | 운영 환경 |
| created_at | DATETIME | N | | `CURRENT_TIMESTAMP` | 행 생성 시각 |

## 5. installed_software — 서버별 설치 패키지 (가상 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| system_id | INT | N | PK, FK → systems | | 서버 |
| software_id | INT | N | PK, FK → software | | 소프트웨어 |
| installed_version | VARCHAR(100) | N | | | Debian 버전 문자열 (예: `1:9.6p1-3ubuntu13.5`). **DB에서 크기 비교 금지** — 영향 판정은 Python에서 |
| collected_at | DATETIME | N | | `CURRENT_TIMESTAMP` | 버전 수집 시각 |

PK: (system_id, software_id)

## 6. staff — 조치 담당자 (가상 데이터)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| staff_id | INT | N | PK, AI | | 담당자 ID |
| name | VARCHAR(50) | N | | | 이름 |
| team | VARCHAR(50) | Y | | | 소속 팀 |
| email | VARCHAR(255) | N | UK | CHECK `LIKE '_%@_%'` | 이메일 |

## 7. system_vulnerabilities — 서버별 취약점 조치 건 (핵심 업무 테이블)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| sv_id | INT | N | PK, AI | | 조치 건 ID |
| system_id | INT | N | UK①, FK② | | 서버 |
| cve_id | VARCHAR(20) | N | UK①, FK → vulnerabilities | | CVE |
| software_id | INT | N | FK② | | 취약한 소프트웨어. **해당 서버에 설치되어 있어야 함** |
| status | ENUM | N | | `open`(기본), `in_progress`, `patched`, `risk_accepted` | 조치 상태 |
| assignee_id | INT | Y | FK → staff | NULL = 미배정 | 담당자 |
| due_date | DATE | Y | | | 조치 기한 |
| detected_at | DATETIME | N | | `CURRENT_TIMESTAMP` | 탐지 시각 |
| patched_at | DATETIME | Y | | CHECK: status=`patched`이면 NOT NULL | 패치 완료 시각 |
| updated_by | INT | Y | FK → staff | NULL = 자동 처리 | 마지막 변경자. **status 변경 시 반드시 함께 SET** |
| updated_at | DATETIME | N | | `CURRENT_TIMESTAMP ON UPDATE` | 마지막 변경 시각 (값이 실제로 바뀐 경우에만 갱신) |

- ① UNIQUE (system_id, cve_id): 한 서버에 같은 CVE 조치 건은 1개
- ② 복합 FK (system_id, software_id) → installed_software (system_id, software_id)

## 8. patch_history — 조치 상태 변경 이력 (트리거가 기록)

| 컬럼 | 타입 | NULL | 키 | 기본값 / 허용값 | 의미 |
|---|---|---|---|---|---|
| history_id | INT | N | PK, AI | | 이력 ID |
| sv_id | INT | N | FK → system_vulnerabilities (**ON DELETE CASCADE**) | | 조치 건 |
| old_status | ENUM | Y | | system_vulnerabilities.status와 동일 | 이전 상태. 최초 등록이면 NULL |
| new_status | ENUM | N | | 위와 동일 | 변경 후 상태 |
| changed_by | INT | Y | FK → staff | 트리거가 `NEW.updated_by`로 채움 | 변경자 |
| changed_at | DATETIME | N | | `CURRENT_TIMESTAMP` | 변경 시각 |
| note | VARCHAR(500) | Y | | INSERT 트리거는 `'조치 건 등록'` | 비고 |

---

## 트리거

| 이름 | 시점 | 동작 |
|---|---|---|
| trg_sv_after_insert | AFTER INSERT ON system_vulnerabilities | `(sv_id, NULL, NEW.status, NEW.updated_by)` 이력 기록 |
| trg_sv_after_update | AFTER UPDATE ON system_vulnerabilities | `OLD.status <> NEW.status`일 때만 `(sv_id, OLD.status, NEW.status, NEW.updated_by)` 기록 |

## 뷰

### v_open_risks — 미해결 조치 건 (status IN ('open','in_progress'))

| 컬럼 | 타입 | 의미 |
|---|---|---|
| sv_id, status | | 조치 건 |
| system_id, hostname, environment | | 서버 |
| software_id, software_name | | 소프트웨어 (`software.name`) |
| cve_id, cvss_score, ubuntu_priority | | CVE (cvss_score는 NULL일 수 있음) |
| assignee_id, assignee_name | | 담당자 (미배정이면 둘 다 NULL) |
| due_date, detected_at | | 기한, 탐지 시각 |
| is_overdue | 0/1 | `due_date < CURDATE()`이면 1. 기한이 없으면 0 |

### v_system_patch_rate — 서버별 조치 현황 (조치 건이 없는 서버도 포함)

| 컬럼 | 타입 | 의미 |
|---|---|---|
| system_id, hostname, environment | | 서버 |
| total_count | 정수 | 전체 조치 건수 |
| patched_count | 정수 | `patched` 건수 |
| unresolved_count | 정수 | `open` + `in_progress` 건수 |
| risk_accepted_count | 정수 | `risk_accepted` 건수 (완료도 미해결도 아님) |
| patch_rate_pct | DECIMAL(1자리) | `patched / total × 100`. **조치 건이 0개면 NULL** |

---

## MySQL 오류 코드 (앱에서 처리할 것)

| 코드 | 의미 | 예 |
|---|---|---|
| 1062 | PK/UNIQUE 중복 | 이미 있는 CVE, 같은 서버·CVE 조치 건 재등록 |
| 1452 | FK 부모 없음 | 설치되지 않은 소프트웨어의 취약점 등록 |
| 1451 | FK 자식 존재 (삭제 불가) | 조치 건이 배정된 담당자 삭제 |
| 3819 | CHECK 위반 | cvss 11.0, `patched`인데 patched_at 없음 |
| 1265 | ENUM 등 허용되지 않는 값 | status = `'done'` |
