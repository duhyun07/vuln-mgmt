# 채점기 (judge)

팀 사이트의 "문제" 페이지(백준식)를 채점한다. 문제 설명은 사이트 `problems/`에 있고,
이 폴더에는 채점 데이터와 채점기만 있다. 담당: 팀장.

## 실행

```bash
pip install -r judge/requirements.txt     # 처음 한 번 (③의 requirements.txt를 이미 설치했으면 생략)
python judge/judge.py --list              # 문제 목록
python judge/judge.py 5                   # 5번 채점
python judge/judge.py --all               # 전체 채점
```

- 레포 루트에서 실행한다. 접속 정보는 루트의 `.env`(`MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`)를 읽는다.
- Docker 대신 수업용 MySQL(Plan B)을 써도 된다. `.env`의 포트·계정만 맞추면 된다.
- Windows에서도 같은 명령으로 실행된다 (PowerShell, Git Bash 모두).

## 결과 메시지

| 메시지 | 뜻 |
|---|---|
| `맞았습니다!!` | 모든 케이스 통과 |
| `틀렸습니다 (케이스 n: 기대 … / 실제 …)` | 예제 케이스 결과가 다름 |
| `틀렸습니다 (숨은 케이스 n)` | 숨은 케이스 결과가 다름 (입력은 공개하지 않음) |
| `런타임 에러 (케이스 n: MySQL 코드 …)` | 제출 SQL 실행 중 오류 |
| `오류가 나야 하는데 성공했습니다` | 실패해야 정답인 케이스에서 성공함 |

## 제출 파일 규칙

- 위치: `sql/qNN.sql` (문제마다 이름이 정해져 있음, 사이트 문제 페이지 참고). `sql/query_catalog.json`에 넣는 SQL과 같은 문장.
- 파일에는 SQL 문장 **하나만**. 끝의 `;`와 `--`로 시작하는 주석 줄은 채점기가 지운다.
- 파라미터는 `%s`(문제에 적힌 순서) 또는 `%(이름)s`. 값을 SQL에 직접 쓰지 않는다.
- 파라미터가 있는 SQL에서 `%` 문자가 필요하면 `%%`로 쓴다 (`LIKE '%%x'`, `DATE_FORMAT(d, '%%Y')`).
  줄 끝 주석(`SELECT … -- 설명`)이나 `/* */` 안의 `%`도 같다.

## 동작 방식

케이스마다:

1. 트랜잭션 시작
2. 모든 테이블의 행을 FK 역순으로 DELETE (`patch_history` → … → `software`)
3. 케이스 데이터(`cases/NN.sql`) INSERT
4. 제출 SQL 실행 (필요하면 확인 쿼리도 실행)
5. 기대 결과와 비교 — DATE·DECIMAL·NULL은 문자열로 맞춰 비교, 문제에 정렬이 정해져 있으면 순서까지 비교
6. **ROLLBACK** — 트리거가 만든 `patch_history`도 함께 취소된다

스키마는 건드리지 않는다. 채점 전후로 행 수와 상태를 비교해 `데이터 오염 검사: OK`를 출력한다.
(AUTO_INCREMENT 카운터는 ROLLBACK돼도 줄어들지 않는다. 데이터에는 영향 없음)

## 폴더 구조

```
judge/
├── judge.py
├── requirements.txt
├── problems/
│   └── NN/
│       ├── problem.json      # 제목, 유형, 담당, 제출 파일, 파라미터, 정렬 여부, 사이트용 설명
│       └── cases/
│           ├── 01.sql        # 케이스 입력 데이터 (FK를 만족하는 전체 INSERT, 가짜 CVE만)
│           └── 01.json       # 파라미터, hidden 여부, 기대 결과(rows) 또는 기대 오류 코드(error)
└── solutions/                # 팀장 검증용 정답 SQL — 커밋 금지 (.gitignore)
```

문제 유형(`problem.json`의 `type`):

| type | 채점 |
|---|---|
| `result` | 케이스마다 결과 행 비교 (DML 문제는 `expect.check` 쿼리로 확인) |
| `error` | 케이스마다 기대 오류 코드 비교 (성공해야 하는 케이스도 섞일 수 있음) |
| `state` | 케이스 없이 현재 DB 상태를 `checks` 쿼리로 검사 (읽기만 함) |
| `checklist` | 채점하지 않고 확인 항목 출력. `auto_checks`가 있으면 자동 확인 결과도 출력 |

케이스 `.json`의 기대 결과와 사이트 문제 페이지의 예제는 같아야 한다. 케이스를 고치면 사이트도 같이 고친다.
