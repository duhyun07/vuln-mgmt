# 설계 결정 기록 — vuln_mgmt

각 항목에 **[결정]** 은 이미 구현된 내용, **[검토 필요]** 는 DB 담당이 정해야 할 사항,
**[제안]** 은 받은 설계를 바꾸자는 제안(구현하지 않음)이다.

---

## 1. 정규화

- 모든 테이블이 3NF를 만족한다. 비키 속성은 모두 키 전체에만 종속된다.
  - `cve_package_status`의 `fixed_version`, `usn_id`는 (cve_id, software_id, ubuntu_release) 전체에 종속된다.
    같은 CVE라도 릴리스마다 수정 버전이 다르다.
  - `installed_software.installed_version`은 (system_id, software_id) 전체에 종속된다.
- 의도적인 중복 1건: `system_vulnerabilities.software_id`.
  CVE 하나가 여러 패키지에 영향을 줄 수 있어 cve_id만으로는 소프트웨어가 정해지지 않는다.
  그래서 이 컬럼이 필요하고, 복합 FK로 "설치된 소프트웨어"인지 검증한다(아래 3-1).
- `patch_history`는 상태 변화 이벤트를 쌓는 테이블이다. 현재 상태(`system_vulnerabilities.status`)와는 목적이 달라
  중복으로 보지 않는다.

## 2. 데이터 타입·기본값

| 항목 | 결정 | 이유 |
|---|---|---|
| 시각 컬럼 | 모두 `DATETIME` | TIMESTAMP의 2038년 한계와 세션 시간대 자동 변환을 피한다. 서버 시간대는 compose에서 `TZ=Asia/Seoul` |
| `cvss_score` | `DECIMAL(3,1) NULL`, 기본값 없음 | 점수가 없는 CVE를 0점(=안전)으로 오인하지 않게 하려고. 정렬·평균 쿼리에서 NULL 처리 필요 |
| 상태값 | `ENUM` | 허용값을 DB가 강제한다. strict 모드(기본값)에서 잘못된 값은 오류 1265 |
| `cve_id` CHECK | `REGEXP_LIKE(..., 'c')` | 콜레이션이 `_ai_ci`라 일반 REGEXP는 대소문자를 무시한다. `'c'` 플래그로 소문자 `cve-`도 거부 |
| `ubuntu_release` | `VARCHAR(10)` + CHECK `^[0-9]{2}.[0-9]{2}$` | `24.04` 형식만 허용. 코드명(`noble`)이 섞이는 것을 막는다 |
| `usn_id` | CHECK `^USN-[0-9]+-[0-9]+$` | 요청 범위 밖이지만 수집 데이터 형식 오류를 일찍 잡으려고 추가 |
| `staff.email` | CHECK `LIKE '_%@_%'` | 최소한의 형식 검사만 |
| `source_url` | `VARCHAR(500) NULL` | 긴 URL 대비. 시드는 가짜 데이터라 NULL |
| `note` | `VARCHAR(500)` | TEXT 대신 길이 제한 |

## 3. 무결성 제약

### 3-1. 복합 FK (system_id, software_id) → installed_software
- 서버에 설치되지 않은 소프트웨어의 취약점은 등록할 수 없다(테스트 T09).
- `systems`, `software`로 가는 별도 FK는 두지 않았다. 복합 FK의 부모가 이미 각각을 참조하기 때문이다.
- **[검토 필요] 부작용:** 조치 건이 하나라도 있으면 `installed_software` 행을 삭제할 수 없다(RESTRICT, 테스트 T22).
  서버에서 패키지를 제거하는 시나리오가 있다면 정책을 정해야 한다.
  (a) 조치 건을 먼저 정리, (b) installed_software에 `removed_at` 컬럼을 두고 논리 삭제 — (b)를 추천한다.
- 같은 이유로 패키지 버전을 갱신할 때는 DELETE+INSERT가 아니라 `UPDATE installed_software SET installed_version=...`를 써야 한다.
  데이터 수집 담당에게 전달할 것.

### 3-2. 검증하지 않는 것 (애플리케이션 책임)
- **CVE와 소프트웨어의 대응.** 조치 건의 (cve_id, software_id)가 실제로 그 CVE가 영향을 주는 패키지인지는 DB가 검증하지 않는다.
  예: `CVE-0000-0001`(apache2 취약점)을 openssh에 등록해도 들어간다.
  `cve_package_status`의 PK에 `ubuntu_release`가 있어 그대로 FK 대상으로 쓸 수 없기 때문이다.
  - **[제안 A]** `system_vulnerabilities`에 `ubuntu_release`를 추가하고 복합 FK (cve_id, software_id, ubuntu_release) →
    `cve_package_status`를 건다. 단점: `systems.ubuntu_release`와 값이 중복된다(복합 FK를 하나 더 걸면 일관성은 보장되지만 구조가 복잡해진다).
  - **[제안 B]** BEFORE INSERT 트리거로 `cve_package_status`에 (cve_id, software_id, 해당 서버의 릴리스) 행이 있는지 확인하고
    없으면 `SIGNAL SQLSTATE '45000'`. 구조 변경이 없어 가장 간단하다.
  - 제안 B를 추천한다. 다만 데이터 수집 순서(cve_package_status를 먼저 적재)가 강제되므로 팀과 합의가 필요하다.
- **영향 판정.** Debian 버전 비교는 Python에서 한다(요구사항). DB는 결과만 저장한다.
- **status 전이 규칙.** `patched → open` 같은 역방향 전이도 허용한다. 재발(regression)을 표현할 수 있어야 해서다.
  **[검토 필요]** 이때 `patched_at`이 이전 값으로 남는다.
  CHECK `(status = 'patched') = (patched_at IS NOT NULL)`로 바꾸면 patched가 아닐 때 patched_at이 NULL이어야 하므로
  재오픈 시 앱이 patched_at을 비워야 한다. 엄격하게 할지 정해야 한다.
- **날짜 순서.** `patched_at >= detected_at`, `due_date >= DATE(detected_at)` 같은 CHECK는 넣지 않았다.
  넣을 수는 있다(컬럼끼리 비교는 CHECK에서 허용). 넣을지 결정 필요.
- `risk_accepted`일 때 사유(note) 필수 같은 규칙은 이력 테이블에 걸려 있어 CHECK로 표현할 수 없다.

### 3-3. FK 삭제·변경 정책
- 요구대로 기본 RESTRICT, `patch_history.sv_id`만 `ON DELETE CASCADE`.
- `patch_history.sv_id`는 `ON UPDATE CASCADE`도 줬다. sv_id는 AUTO_INCREMENT라 바뀔 일이 없어 실질적인 차이는 없다.
- **[검토 필요] 이력 보존 vs CASCADE:** 조치 건을 삭제하면 감사 이력도 사라진다.
  감사 관점에서는 조치 건을 삭제하지 않고 상태로만 관리하는 편이 낫다. 정책을 "조치 건은 DELETE하지 않는다"로 정하고
  `patch_history.sv_id`를 RESTRICT로 바꾸는 방안도 있다. 수업 요구에 맞춰 현재는 CASCADE를 유지한다.
- `changed_by`/`updated_by`/`assignee_id`가 RESTRICT이므로 퇴사자를 삭제할 수 없다.
  **[제안]** `staff.is_active TINYINT(1) DEFAULT 1` 컬럼으로 논리 삭제. (현재 미구현)

## 4. 트리거와 updated_by 규칙

- 변경자 기록은 `NEW.updated_by`에 의존한다. MySQL 트리거는 "앱 사용자"를 알 수 없어서다.
  (모든 팀원이 같은 DB 계정을 쓰므로 `CURRENT_USER()`로는 구분이 안 된다.)
- **약점:** 앱이 상태만 바꾸고 `updated_by`를 지정하지 않으면 이전 변경자의 ID가 그대로 남아 이력에 잘못 기록된다.
  DB는 "값을 지정하지 않음"과 "같은 값으로 지정함"을 구별할 수 없어서 제약으로 막을 수 없다.
  - 대응: README와 데이터 사전에 규칙 명시, Streamlit 코드 리뷰에서 확인.
  - **[제안]** 상태 변경을 저장 프로시저 `sp_change_status(sv_id, new_status, staff_id, note)`로만 하게 하면
    변경자 누락과 note 기록을 한 번에 해결한다. 프로시저 사용을 강제하려면 앱 계정의 UPDATE 권한을 제한해야 한다.
- INSERT 트리거는 `note = '조치 건 등록'`을 남긴다. UPDATE 트리거는 note를 NULL로 둔다.
  사유를 남기려면 상태 변경 직후 해당 이력 행의 note를 UPDATE한다(seed.sql에 예시 있음).
- 같은 트랜잭션에서 여러 번 바꾸면 이력도 여러 건 생긴다. `changed_at`은 `NOW()`라 한 트랜잭션 안에서는 같은 값이다.
  순서는 `history_id`로 판단해야 한다.

## 5. 뷰

- `v_open_risks.is_overdue`: 요청식 `due_date < CURDATE()`는 기한이 NULL이면 NULL이 된다.
  **[결정]** 0/1로 나오게 `IF(due_date IS NOT NULL AND due_date < CURDATE(), 1, 0)`로 했다.
  Python에서 NULL을 따로 처리하지 않아도 된다.
- `v_open_risks`에는 요청 항목 외에 `sv_id`, `status`, `system_id`, `software_id`, `assignee_id`, `detected_at`을 추가했다.
  앱에서 상세 화면 이동, 필터링에 필요하다.
- `v_system_patch_rate`
  - 미해결 = `open + in_progress`. `risk_accepted`는 완료도 미해결도 아니어서 `risk_accepted_count`로 따로 뺐다.
  - **[검토 필요] 완료율의 분모.** 현재 `patched / 전체`. risk_accepted를 "처리 완료"로 볼지,
    분모에서 뺄지(`patched / (전체 − risk_accepted)`)는 보고서 관점에 따라 다르다.
  - **[검토 필요] 조치 건 0개인 서버의 완료율.** 현재 NULL(정의되지 않음). 대시보드에서 100%로 보이길 원하면
    `IFNULL(..., 100)`로 바꾸면 된다. 0으로 표시하면 오해 소지가 있어 추천하지 않는다.
- 뷰는 `CURDATE()`를 쓰므로 결과가 날짜에 따라 바뀐다. 시드도 상대 날짜라 항상 같은 결과가 나온다.

## 6. 인덱스

요구대로 PK·FK·UNIQUE로 자동 생성되는 것 외에는 만들지 않았다.
현재 존재하는 인덱스(자동 생성):

| 테이블 | 인덱스 | 출처 |
|---|---|---|
| system_vulnerabilities | (sv_id) | PK |
| | (system_id, cve_id) | UNIQUE |
| | (system_id, software_id) | 복합 FK가 자동 생성 |
| | (cve_id), (assignee_id), (updated_by) | FK가 자동 생성 |
| patch_history | (sv_id), (changed_by) | FK |
| cve_package_status | (cve_id, software_id, ubuntu_release), (software_id) | PK, FK |
| installed_software | (system_id, software_id), (software_id) | PK, FK |

### 추천 인덱스 후보 (성능 비교 실험용)

데이터가 수십 건이면 차이가 거의 없다. 비교 실험 전에 수천~수만 건의 대량 데이터를 먼저 생성해야 한다.
`EXPLAIN` / `EXPLAIN ANALYZE`로 `type`(ALL → ref/range), `rows`, 실제 시간을 비교하면 된다.

| # | 인덱스 | 대상 쿼리 |
|---|---|---|
| 1 | `system_vulnerabilities (status, due_date)` | `v_open_risks`, 기한 지난 미해결 건 (`WHERE status IN (...) AND due_date < CURDATE()`) |
| 2 | `system_vulnerabilities (assignee_id, status)` | 담당자별 미해결 건수. 기존 FK 인덱스 (assignee_id)를 대체 가능 |
| 3 | `vulnerabilities (cvss_score)` | 고위험 CVE 필터·정렬 (`WHERE cvss_score >= 9.0 ORDER BY cvss_score DESC`) |
| 4 | `vulnerabilities (ubuntu_priority)` | 우선순위별 집계. 카디널리티가 낮아 효과가 작을 수 있음 — 비교 실험 대상으로 적합 |
| 5 | `vulnerabilities (published_date)` | 기간별 CVE 추이 |
| 6 | `patch_history (changed_at)` | 기간별 조치 이력, 월별 패치 건수 |
| 7 | `patch_history (sv_id, changed_at)` | 조치 건별 타임라인, 평균 조치 소요 시간. 기존 (sv_id) FK 인덱스를 대체 가능 |
| 8 | `cve_package_status (ubuntu_release, status)` | "24.04에서 아직 needed인 CVE" |
| 9 | `system_vulnerabilities (detected_at)` | 탐지 추이, MTTR 계산 |
| 10 | `systems (environment)` | 환경별 집계. 카디널리티가 3이라 효과가 거의 없을 것으로 예상 — 반례로 쓸 수 있음 |

## 7. 시드 데이터

- 가짜 CVE 번호 `CVE-0000-0001` ~ `0005`. 연도 0000은 실제 존재할 수 없어 혼동되지 않고 CHECK 형식은 통과한다.
- 패키지 버전 `...ubuntu8.99`, USN `USN-0000-1` 등도 가짜다. 이메일은 예약 도메인 `example.com`.
- 날짜는 `CURDATE()`/`NOW()` 기준 상대값이다.
- 한계: 시드의 상태 변경은 한 번에 실행되므로 `patch_history.changed_at`이 모두 적재 시각으로 같다.
  "평균 조치 소요 시간" 같은 분석에는 `detected_at`과 `patched_at`(상대 날짜로 넣음)을 쓰거나,
  SQL 담당이 대량 데이터를 만들 때 changed_at을 따로 지정해야 한다.
- 서버는 요구대로 3대다. "조치 건이 0개인 서버" 경우는 시드에 없고 테스트 T23에서 확인한다.

시드 기준 기대 결과:

| hostname | 전체 | patched | 미해결 | risk_accepted | 완료율 |
|---|---|---|---|---|---|
| web-prod-01 | 4 | 0 | 4 | 0 | 0.0 |
| web-prod-02 | 3 | 1 | 1 | 1 | 33.3 |
| dev-01 | 2 | 2 | 0 | 0 | 100.0 |

`v_open_risks`: 5건 (sv 1, 2, 3, 4, 7), 그중 기한 지남 2건 (sv 1, 2), 미배정 2건 (sv 3, 4).
`patch_history`: 16건 (등록 9 + 상태 변경 7).

## 8. 환경

- `mysql:8.0` 태그는 8.0.x 최신(현재 8.0.46)을 받는다. 팀원 간 버전을 고정하려면 `mysql:8.0.46`으로 바꿀 것.
- 초기화 스크립트(`docker-entrypoint-initdb.d`)는 **볼륨이 비어 있을 때 한 번만** 실행된다.
  schema.sql을 고친 뒤에는 README의 재적재 명령을 쓰거나 `docker compose down -v`로 볼륨을 지워야 한다.
- 앱 계정(`MYSQL_USER`)은 `vuln_mgmt.*`에 대한 모든 권한을 가진다. 스키마 재적재와 테스트는 root로 한다.
  **[제안]** 최종 시연에서는 앱 계정 권한을 SELECT/INSERT/UPDATE로 줄이는 것이 보안 주제에 맞다.

---

## 결정이 필요한 사항 요약

1. CVE↔소프트웨어 대응 검증 추가 여부 (3-2, 제안 B 트리거 추천)
2. installed_software 삭제 정책 / 논리 삭제 컬럼 (3-1)
3. 재오픈 시 patched_at 처리 — CHECK를 양방향으로 엄격하게 할지 (3-2)
4. 날짜 순서 CHECK 추가 여부 (3-2)
5. 조치 건 삭제 시 이력 CASCADE 유지 vs 조치 건 삭제 금지 (3-3)
6. staff 논리 삭제 (3-3)
7. 상태 변경을 저장 프로시저로 강제할지 (4)
8. 완료율 분모에서 risk_accepted 처리, 조치 건 0개 서버 표시 (5)
9. MySQL 이미지 버전 고정 (8)
