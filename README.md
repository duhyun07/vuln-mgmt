# Ubuntu 보안 취약점·패치 관리 DB (vuln_mgmt)

데이터베이스 수업 PBL 프로젝트. Ubuntu 24.04 서버의 Apache HTTP Server, OpenSSH 취약점(CVE),
CVSS 위험도, Ubuntu 패키지별 수정 상태, 서버별 조치 상태·담당자·기한, 상태 변경 이력을 관리한다.

무결성은 앱 코드가 아니라 DB 제약조건(PK, FK, UNIQUE, CHECK, TRIGGER)으로 보장한다.

## 구성

```
docker-compose.yml        MySQL 8.0 (DB vuln_mgmt, 포트 3306)
.env.example              접속 정보 템플릿 (.env는 git에 올리지 않음)
db/schema.sql             테이블 8개, 제약조건, 트리거 2개, 뷰 2개 (재실행 가능)
db/seed.sql               개발용 가짜 데이터 (실제 CVE 아님)
tests/integrity_tests.sql 무결성 테스트 케이스
tests/run_tests.sh        테스트 실행기 (PASS/FAIL 출력)
docs/erd.md               ERD (Mermaid)
docs/db_dictionary.md     데이터 사전 — 팀 공통 연동 규격
docs/design_decisions.md  설계 결정과 검토할 사항, 추천 인덱스
sql/  data/  app/         분석 SQL / 수집 데이터 / Streamlit 앱 (각 담당)
```

## 실행 방법

필요한 것: Docker, Docker Compose v2

### 1. 실행

```bash
cp .env.example .env        # 필요하면 비밀번호 수정
docker compose up -d
docker compose ps           # STATUS가 (healthy)가 될 때까지 대기 (처음엔 20~30초)
```

**처음 실행할 때**(볼륨이 비어 있을 때) `db/schema.sql` → `db/seed.sql`이 자동으로 적재된다.

### 2. 스키마·시드 다시 적재

schema.sql이나 seed.sql을 고친 뒤에는 자동 적재가 다시 돌지 않으므로 직접 실행한다.
**기존 데이터는 모두 삭제된다.**

```bash
docker compose exec db sh -c \
  'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" --default-character-set=utf8mb4 < /work/db/schema.sql &&
   mysql -uroot -p"$MYSQL_ROOT_PASSWORD" --default-character-set=utf8mb4 < /work/db/seed.sql'
```

또는 볼륨째 초기화: `docker compose down -v && docker compose up -d`

### 3. 테스트

```bash
./tests/run_tests.sh
```

각 테스트는 트랜잭션 안에서 실행 후 ROLLBACK되므로 데이터가 바뀌지 않는다(실행 후 자동 검사).
모두 통과하면 `총 23건: PASS 23, FAIL 0`과 종료 코드 0.

### 4. 접속

| 항목 | 값 |
|---|---|
| host | `127.0.0.1` (컨테이너끼리는 `db`) |
| port | `3306` |
| database | `vuln_mgmt` |
| user / password | `.env`의 `MYSQL_USER` / `MYSQL_PASSWORD` |

```bash
docker compose exec db sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" vuln_mgmt'
```

Python 예시 (`pip install pymysql`):

```python
import pymysql
conn = pymysql.connect(host="127.0.0.1", port=3306, user="vuln_app",
                       password="...", database="vuln_mgmt", charset="utf8mb4")
```

## ⚠️ 팀 공통 규칙

1. **`system_vulnerabilities.status`를 바꿀 때는 반드시 같은 UPDATE 문에서 `updated_by`도 SET한다.**
   트리거가 `updated_by` 값을 `patch_history.changed_by`(변경자)로 기록한다.
   빼먹으면 이전 변경자의 이름으로 이력이 남는다. 자동 스크립트는 `updated_by = NULL`.
   ```sql
   UPDATE system_vulnerabilities
      SET status = 'patched', patched_at = NOW(), updated_by = %s
    WHERE sv_id = %s;
   ```
2. `status = 'patched'`로 바꿀 때는 `patched_at`도 함께 넣는다(없으면 CHECK 오류 3819).
3. `patch_history`에는 직접 INSERT하지 않는다(트리거 전용).
4. `cvss_score`가 없으면 NULL로 넣는다. 0으로 채우지 않는다.
5. 버전 비교(영향 판정)는 Python에서 하고, 결과만 `system_vulnerabilities`에 INSERT한다.
   설치되지 않은 소프트웨어의 취약점은 복합 FK 때문에 들어가지 않는다(오류 1452).
6. `installed_software`의 버전 갱신은 DELETE+INSERT가 아니라 UPDATE로 한다(조치 건이 걸려 있으면 삭제 불가).
7. 컬럼 이름·타입은 [docs/db_dictionary.md](docs/db_dictionary.md)를 따른다. 바꿀 일이 있으면 DB 담당과 먼저 상의한다.

## 시드 데이터

`db/seed.sql`은 **개발용 가짜 데이터**다. CVE 번호(`CVE-0000-0001` 등), 버전, USN, 서버, 담당자 모두 지어낸 값이다.
날짜는 오늘 기준 상대값이라 언제 적재해도 같은 분석 결과가 나온다.
기대 결과는 [docs/design_decisions.md](docs/design_decisions.md#7-시드-데이터) 참고.
