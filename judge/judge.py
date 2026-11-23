"""vuln_mgmt 문제 채점기.

사용법 (레포 루트에서):
  python judge/judge.py 5            # 5번 문제 채점
  python judge/judge.py --all        # 전체 채점
  python judge/judge.py --list       # 문제 목록
  python judge/judge.py 5 --from judge/solutions   # 제출 파일을 다른 폴더에서 읽기

케이스마다 트랜잭션을 열고, 기존 행을 지운 뒤 케이스 데이터를 넣고, 제출 SQL을 실행해 비교한 다음
ROLLBACK한다. 스키마와 기존 데이터는 바뀌지 않는다 (끝에 오염 검사를 한다).
"""
import argparse
import datetime
import decimal
import json
import os
import re
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
PROBLEMS = Path(__file__).resolve().parent / "problems"
load_dotenv(ROOT / ".env")

# 케이스마다 비울 테이블 (FK 자식 → 부모 순서)
DELETE_ORDER = [
    "patch_history", "system_vulnerabilities", "installed_software", "cve_package_status",
    "staff", "systems", "vulnerabilities", "software",
]

SNAPSHOT_SQL = """
SELECT CONCAT_WS(',',
  (SELECT COUNT(*) FROM software), (SELECT COUNT(*) FROM vulnerabilities),
  (SELECT COUNT(*) FROM cve_package_status), (SELECT COUNT(*) FROM systems),
  (SELECT COUNT(*) FROM installed_software), (SELECT COUNT(*) FROM staff),
  (SELECT COUNT(*) FROM system_vulnerabilities), (SELECT COUNT(*) FROM patch_history),
  (SELECT IFNULL(GROUP_CONCAT(CONCAT(sv_id, ':', status, ':', IFNULL(updated_by, '-')) ORDER BY sv_id), '')
     FROM system_vulnerabilities))"""


def connect():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE", "vuln_mgmt"),
        charset="utf8mb4",
        autocommit=False,
    )


# ---------------------------------------------------------------------
# SQL 파일 읽기
# ---------------------------------------------------------------------
def split_sql(text):
    """세미콜론으로 문장을 나눈다. 따옴표 안의 세미콜론과 -- 주석 줄은 무시한다."""
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("--")]
    text = "\n".join(lines)
    statements, buf, quote = [], [], None
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
        else:
            buf.append(ch)
    stmt = "".join(buf).strip()
    if stmt:
        statements.append(stmt)
    return statements


def read_submission(path):
    """제출 파일에서 SQL 한 문장을 꺼낸다. 파일이 없거나 문장이 여러 개면 오류 메시지를 돌려준다."""
    if not path.exists():
        return None, f"제출 파일이 없습니다: {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}"
    statements = split_sql(path.read_text(encoding="utf-8"))
    if len(statements) != 1:
        return None, f"제출 파일에는 SQL 문장이 하나만 있어야 합니다 (지금 {len(statements)}개): {path.name}"
    return statements[0], None


# ---------------------------------------------------------------------
# 값 비교
# ---------------------------------------------------------------------
def norm(value):
    """DB 값과 기대값을 같은 문자열로 맞춘다. NULL은 'NULL'."""
    if value is None:
        return "NULL"
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def norm_rows(rows):
    return [tuple(norm(v) for v in row) for row in rows]


def show(rows, limit=6):
    if not rows:
        return "(0행)"
    text = " ".join("(" + ", ".join(r) + ")" for r in rows[:limit])
    if len(rows) > limit:
        text += f" ... 외 {len(rows) - limit}행"
    return text


def bind(sql, names, params):
    """%(이름)s를 쓰면 dict로, %s를 쓰면 문제에 정한 순서의 list로 넘긴다."""
    if not names:
        return None
    if "%(" in sql:
        return {n: params[n] for n in names}
    return [params[n] for n in names]


# ---------------------------------------------------------------------
# 케이스 실행
# ---------------------------------------------------------------------
def load_cases(pdir):
    cases = []
    for meta_path in sorted((pdir / "cases").glob("*.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        sql_path = meta_path.with_suffix(".sql")
        meta["setup"] = split_sql(sql_path.read_text(encoding="utf-8")) if sql_path.exists() else []
        meta["file"] = meta_path.stem
        cases.append(meta)
    examples = [c for c in cases if not c.get("hidden")]
    hidden = [c for c in cases if c.get("hidden")]
    for i, c in enumerate(examples, 1):
        c["label"] = f"케이스 {i}"
    for i, c in enumerate(hidden, 1):
        c["label"] = f"숨은 케이스 {i}"
    return examples + hidden


def run_case(conn, problem, case, submissions):
    """케이스 하나를 실행하고 (통과 여부, 메시지)를 돌려준다."""
    key = case.get("submission", "main")
    sql = submissions[key]
    names = problem.get("params", {}).get(key, [])
    params = case.get("params", {})
    expect = case["expect"]
    hidden = case.get("hidden", False)
    label = case["label"]

    with conn.cursor() as cur:
        conn.begin()
        try:
            for table in DELETE_ORDER:
                cur.execute(f"DELETE FROM {table}")
            for stmt in case["setup"]:
                try:
                    cur.execute(stmt)
                except pymysql.MySQLError as e:
                    return False, f"채점 데이터 오류 ({case['file']}.sql): {e.args[0]} {e.args[1]} — 팀장에게 알려 주세요"

            error = None
            rows = None
            try:
                cur.execute(sql, bind(sql, names, params))
                rows = norm_rows(cur.fetchall()) if cur.description else None
            except pymysql.MySQLError as e:
                if not isinstance(e.args[0], int):
                    # MySQL까지 가기 전에 pymysql이 %s 바인딩에서 실패한 경우
                    return False, (f"런타임 에러 ({label}: 파라미터 바인딩 실패 - {e.args[0]}. "
                                   f"이 문제의 파라미터는 {', '.join(names) or '없음'}이에요)")
                error = (e.args[0], e.args[1] if len(e.args) > 1 else "")
            except (TypeError, KeyError, ValueError) as e:
                return False, (f"런타임 에러 ({label}: 파라미터 바인딩 실패 - {e}. "
                               f"이 문제의 파라미터는 {', '.join(names) or '없음'}이에요)")

            if "error" in expect:
                want = expect["error"]
                if error is None:
                    return False, f"오류가 나야 하는데 성공했습니다 ({label}: 기대 오류 {want})"
                if error[0] != want:
                    detail = "" if hidden else f": 기대 오류 {want} / 실제 오류 {error[0]}"
                    return False, f"틀렸습니다 ({label}{detail})"
                return True, f"{label}: 통과 (예상대로 오류 {want})"

            if error is not None:
                return False, f"런타임 에러 ({label}: MySQL {error[0]} {error[1]})"

            # DML 제출이면 check 쿼리로 결과를 확인
            if "check" in expect:
                rows = []
                for check in expect["check"]:
                    cur.execute(check, params or None)
                    rows += norm_rows(cur.fetchall())
            want_rows = [tuple(norm(v) for v in r) for r in expect["rows"]]
            ordered = case.get("ordered", problem.get("ordered", False))
            got_cmp, want_cmp = (rows, want_rows) if ordered else (sorted(rows), sorted(want_rows))
            if got_cmp != want_cmp:
                if hidden:
                    return False, f"틀렸습니다 ({label})"
                return False, f"틀렸습니다 ({label}: 기대 {show(want_rows)} / 실제 {show(rows)})"
            return True, f"{label}: 통과"
        finally:
            conn.rollback()


def judge_cases(conn, problem, pdir, from_dir):
    submissions = {}
    for key, rel in problem["submissions"].items():
        path = (from_dir / Path(rel).name) if from_dir else ROOT / rel
        sql, err = read_submission(path)
        if err:
            return False, [err]
        submissions[key] = sql
    lines = []
    for case in load_cases(pdir):
        ok, msg = run_case(conn, problem, case, submissions)
        lines.append(("  " + msg) if ok else msg)
        if not ok:
            return False, lines
    lines.append("맞았습니다!!")
    return True, lines


def judge_state(conn, problem):
    """현재 DB 상태를 확인 쿼리로 검사한다 (읽기만 함)."""
    lines = []
    with conn.cursor() as cur:
        for i, check in enumerate(problem["checks"], 1):
            cur.execute(check["sql"])
            rows = norm_rows(cur.fetchall())
            want = [tuple(norm(v) for v in r) for r in check["rows"]]
            if (rows if check.get("ordered") else sorted(rows)) != (want if check.get("ordered") else sorted(want)):
                lines.append(f"틀렸습니다 (확인 {i} {check['name']}: 기대 {show(want)} / 실제 {show(rows)})")
                return False, lines
            lines.append(f"  확인 {i} {check['name']}: 통과")
    conn.rollback()
    lines.append("맞았습니다!!")
    return True, lines


def judge_checklist(conn, problem):
    lines = ["체크리스트 문제예요. 아래 항목을 직접 확인하세요."]
    for item in problem["checklist"]:
        lines.append(f"  [ ] {item['item']}  → 성공 기준: {item['success']}")
    auto = problem.get("auto_checks", [])
    if auto:
        lines.append("자동으로 확인할 수 있는 항목:")
        with conn.cursor() as cur:
            for check in auto:
                cur.execute(check["sql"])
                got = norm_rows(cur.fetchall())
                want = [tuple(norm(v) for v in r) for r in check["rows"]]
                mark = "확인됨" if got == want else f"다름 (기대 {show(want)} / 실제 {show(got)})"
                lines.append(f"  {check['name']}: {mark}")
        conn.rollback()
    return None, lines


# ---------------------------------------------------------------------
def load_problem(number):
    pdir = PROBLEMS / f"{number:02d}"
    path = pdir / "problem.json"
    if not path.exists():
        raise SystemExit(f"{number}번 문제가 없습니다.")
    return json.loads(path.read_text(encoding="utf-8")), pdir


def judge(conn, number, from_dir):
    problem, pdir = load_problem(number)
    header = f"[{number}] {problem['title']}" + (" (초안)" if problem.get("draft") else "")
    kind = problem["type"]
    if kind == "checklist":
        ok, lines = judge_checklist(conn, problem)
    elif kind == "state":
        ok, lines = judge_state(conn, problem)
    else:
        ok, lines = judge_cases(conn, problem, pdir, from_dir)
    return header, ok, lines


def snapshot(conn):
    with conn.cursor() as cur:
        cur.execute(SNAPSHOT_SQL)
        value = cur.fetchone()[0]
    conn.rollback()
    return value


def main():
    parser = argparse.ArgumentParser(description="vuln_mgmt 문제 채점기")
    parser.add_argument("number", nargs="?", type=int, help="문제 번호")
    parser.add_argument("--all", action="store_true", help="모든 문제 채점")
    parser.add_argument("--list", action="store_true", help="문제 목록")
    parser.add_argument("--from", dest="from_dir", help="제출 파일을 이 폴더에서 읽기 (기본: 문제에 적힌 sql/ 경로)")
    args = parser.parse_args()

    numbers = sorted(int(p.name) for p in PROBLEMS.iterdir() if (p / "problem.json").exists())
    if args.list:
        for n in numbers:
            problem, _ = load_problem(n)
            print(f"{n:>2}  [{problem['type']}] {problem['title']}  (담당 {problem['owner']})")
        return 0
    if not args.all and args.number is None:
        parser.print_help()
        return 2

    from_dir = Path(args.from_dir).resolve() if args.from_dir else None
    try:
        conn = connect()
    except pymysql.MySQLError as e:
        print(f"DB에 연결할 수 없습니다: {e}")
        print(".env의 MYSQL_PORT/MYSQL_USER/MYSQL_PASSWORD와 docker compose ps를 확인하세요.")
        return 2

    before = snapshot(conn)
    results = []
    for n in (numbers if args.all else [args.number]):
        header, ok, lines = judge(conn, n, from_dir)
        print(header)
        for line in lines:
            print(line)
        print()
        results.append((n, ok))
    after = snapshot(conn)
    conn.close()

    if before == after:
        print("데이터 오염 검사: OK (채점 전후 행 수·상태 동일)")
    else:
        print("데이터 오염 검사: FAIL — 채점 전후 데이터가 다릅니다. 팀장에게 알려 주세요.")
        print(f"  전: {before}\n  후: {after}")

    graded = [(n, ok) for n, ok in results if ok is not None]
    if args.all:
        passed = sum(1 for _, ok in graded if ok)
        print(f"채점 문제 {len(graded)}개 중 {passed}개 맞았습니다.")
    return 0 if all(ok for _, ok in graded) and before == after else 1


if __name__ == "__main__":
    sys.exit(main())
