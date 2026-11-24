"""DB 연결과 쿼리 실행을 한곳에 모은 모듈. 화면 코드는 이 파일의 함수만 쓴다."""
import os
from pathlib import Path

import pandas as pd
import pymysql
from dotenv import load_dotenv

# 레포 루트의 .env를 읽는다 (app/db.py 기준 한 단계 위 폴더)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def get_connection():
    """새 DB 연결을 만든다. autocommit=False라서 변경은 commit()해야 반영된다."""
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3306")),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE", "vuln_mgmt"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,   # 결과 행을 {"컬럼명": 값} 형태로 받는다
        autocommit=False,
    )


def fetch_df(sql, params=None):
    """SELECT 결과를 pandas DataFrame으로 돌려준다.

    params에는 %s 자리에 들어갈 값을 튜플이나 리스트로 넘긴다.
    값은 PyMySQL이 따옴표 처리(escape)를 해서 넣어 주므로 SQL Injection이 생기지 않는다.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            columns = [c[0] for c in cur.description]
        return pd.DataFrame(rows, columns=columns)
    finally:
        conn.close()


def execute(sql, params=None):
    """INSERT/UPDATE/DELETE 한 문장을 실행하고 commit한다. 영향받은 행 수를 돌려준다."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            affected = cur.execute(sql, params)
        conn.commit()
        return affected
    except Exception:
        conn.rollback()   # 실패하면 이 연결에서 한 변경을 모두 취소
        raise
    finally:
        conn.close()