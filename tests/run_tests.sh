#!/usr/bin/env bash
# =====================================================================
# tests/integrity_tests.sql의 각 블록을 따로 실행하고 PASS/FAIL을 출력한다.
# 각 블록은 START TRANSACTION ... ROLLBACK 안에서 실행되어 데이터가 남지 않는다.
#
# 사용법 (저장소 루트에서):  ./tests/run_tests.sh [테스트파일]
# 전제: docker compose up -d 로 db 컨테이너가 실행 중이고 seed가 적재된 상태
# 종료 코드: 모두 PASS면 0, 하나라도 FAIL이면 1
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo ".env 파일이 없습니다. cp .env.example .env 후 다시 실행하세요." >&2
  exit 2
fi
set -a; . ./.env; set +a
DB="${MYSQL_DATABASE:-vuln_mgmt}"
TEST_FILE="${1:-tests/integrity_tests.sql}"

run_sql() {
  docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" db \
    mysql -uroot --default-character-set=utf8mb4 -N -B "$DB"
}

if ! echo "SELECT 1;" | run_sql >/dev/null 2>&1; then
  echo "DB에 연결할 수 없습니다. docker compose up -d 후 healthy 상태인지 확인하세요." >&2
  exit 2
fi

SNAPSHOT_SQL="SELECT CONCAT_WS(',',
  (SELECT COUNT(*) FROM vulnerabilities), (SELECT COUNT(*) FROM cve_package_status),
  (SELECT COUNT(*) FROM systems), (SELECT COUNT(*) FROM installed_software),
  (SELECT COUNT(*) FROM staff), (SELECT COUNT(*) FROM system_vulnerabilities),
  (SELECT COUNT(*) FROM patch_history),
  (SELECT GROUP_CONCAT(CONCAT(sv_id,':',status) ORDER BY sv_id) FROM system_vulnerabilities));"
snap_before="$(echo "$SNAPSHOT_SQL" | run_sql 2>&1)"

pass=0; fail=0; failed_ids=()
name=""; expect=""; body=""; in_block=0

run_block() {
  local out code last actual verdict detail
  out="$( { printf 'START TRANSACTION;\n%s\nROLLBACK;\n' "$body"; } | run_sql 2>&1 )"
  code=$?
  last="$(printf '%s\n' "$out" | grep -v '^$' | tail -n 1)"

  case "$expect" in
    error\ *)
      local want="${expect#error }"
      if [[ $code -ne 0 ]] && grep -q "ERROR ${want} " <<<"$out"; then
        verdict=PASS; detail="예상대로 실패 (ERROR ${want})"
      elif [[ $code -eq 0 ]]; then
        verdict=FAIL; detail="실패해야 하는데 성공함"
      else
        verdict=FAIL; detail="다른 오류로 실패: ${last}"
      fi ;;
    result\ *)
      local want="${expect#result }"
      if [[ $code -eq 0 && "$last" == "$want" ]]; then
        verdict=PASS; detail="성공, 결과 = ${last}"
      elif [[ $code -ne 0 ]]; then
        verdict=FAIL; detail="성공해야 하는데 실패함: ${last}"
      else
        verdict=FAIL; detail="결과 불일치 (예상 ${want}, 실제 ${last})"
      fi ;;
    *)
      verdict=FAIL; detail="알 수 없는 @expect: ${expect}" ;;
  esac

  if [[ $verdict == PASS ]]; then
    pass=$((pass + 1)); printf '\033[32m[PASS]\033[0m %s\n       %s\n' "$name" "$detail"
  else
    fail=$((fail + 1)); failed_ids+=("${name%% *}")
    printf '\033[31m[FAIL]\033[0m %s\n       %s\n' "$name" "$detail"
  fi
}

while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ $line =~ ^--\ @test:\ (.*)$ ]]; then
    name="${BASH_REMATCH[1]}"; expect=""; body=""; in_block=1
  elif [[ $in_block -eq 1 && $line =~ ^--\ @expect:\ (.*)$ ]]; then
    expect="${BASH_REMATCH[1]}"
  elif [[ $in_block -eq 1 && $line =~ ^--\ @end ]]; then
    run_block; in_block=0
  elif [[ $in_block -eq 1 ]]; then
    body+="$line"$'\n'
  fi
done < "$TEST_FILE"

snap_after="$(echo "$SNAPSHOT_SQL" | run_sql 2>&1)"
echo "----------------------------------------"
if [[ "$snap_before" == "$snap_after" ]]; then
  echo "데이터 오염 검사: OK (테스트 전후 행 수·상태 동일)"
else
  echo "데이터 오염 검사: FAIL"; echo "  전: $snap_before"; echo "  후: $snap_after"
  fail=$((fail + 1)); failed_ids+=("SNAPSHOT")
fi
echo "총 $((pass + fail))건: PASS ${pass}, FAIL ${fail}"
if [[ $fail -gt 0 ]]; then
  echo "실패: ${failed_ids[*]}"
  exit 1
fi
exit 0
