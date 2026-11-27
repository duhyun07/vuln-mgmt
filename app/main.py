"""대시보드 (첫 화면). 실행: streamlit run app/main.py"""
import streamlit as st

from db import fetch_df

st.set_page_config(page_title="취약점·패치 관리", layout="wide")
st.title("취약점·패치 관리 대시보드")


@st.cache_data(ttl=60)   # 60초 동안 같은 결과를 재사용 → 화면을 움직일 때마다 DB에 다시 묻지 않는다
def load_summary():
    return fetch_df("""
        SELECT
          (SELECT COUNT(*) FROM systems)                                 AS server_count,
          (SELECT COUNT(DISTINCT cve_id) FROM system_vulnerabilities)    AS cve_count,
          (SELECT COUNT(*) FROM v_open_risks)                            AS open_count,
          (SELECT COUNT(*) FROM v_open_risks WHERE cvss_score >= 7.0)    AS high_open_count,
          (SELECT COUNT(*) FROM v_open_risks WHERE is_overdue = 1)       AS overdue_count
    """).iloc[0]


@st.cache_data(ttl=60)
def load_patch_rate():
    return fetch_df("SELECT hostname, environment, total_count, patched_count, unresolved_count, "
                    "risk_accepted_count, patch_rate_pct FROM v_system_patch_rate ORDER BY patch_rate_pct")


summary = load_summary()
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("서버", int(summary["server_count"]))
c2.metric("취약점 (서로 다른 CVE)", int(summary["cve_count"]))
c3.metric("미해결 조치 건", int(summary["open_count"]))
c4.metric("고위험 미해결 (CVSS 7.0+)", int(summary["high_open_count"]))
c5.metric("기한 초과", int(summary["overdue_count"]))

st.subheader("서버별 패치 완료율")
rate = load_patch_rate()
st.dataframe(rate, hide_index=True, width="stretch")
st.bar_chart(rate.set_index("hostname")["patch_rate_pct"].astype(float))   # DECIMAL → float (차트용)
st.caption("완료율 = patched / 전체 조치 건 × 100. 조치 건이 없는 서버는 빈칸(NULL)으로 나와요.")