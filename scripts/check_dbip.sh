#!/usr/bin/env bash
#
# Is there a newer DB-IP IP-to-Country Lite than the one in the app bundle?
#
# DB-IP publishes one file per month at a completely predictable URL, so a HEAD
# request per month is all it takes -- we never pull the 4 MB body. The current
# month is not always up yet on the 1st, hence the look-back window.
#
# Prints KEY=value lines and, in Actions, appends the same to $GITHUB_OUTPUT:
#   latest        newest month that actually exists upstream (YYYY-MM)
#   shipped       month recorded in dbip-shipped.txt
#   needs_update  true when upstream is ahead of what we ship
#
# Exit 1 if not a single month answered 200 -- that means DB-IP moved the URL
# or the network is broken, and a silent green run would hide it for months.

set -euo pipefail

BASE_URL="${DBIP_BASE_URL:-https://download.db-ip.com/free}"
# 0 = only this month, 2 = this month and the two before it.
LOOKBACK="${DBIP_LOOKBACK:-2}"
SHIPPED_FILE="${DBIP_SHIPPED_FILE:-dbip-shipped.txt}"

url_for() { printf '%s/dbip-country-lite-%s.mmdb.gz' "$BASE_URL" "$1"; }

# --- what we ship today -------------------------------------------------------
if [ ! -f "$SHIPPED_FILE" ]; then
  echo "::error::$SHIPPED_FILE is missing -- nothing to compare against."
  exit 1
fi
shipped=$(grep -v '^[[:space:]]*#' "$SHIPPED_FILE" | tr -d '[:space:]' | grep -v '^$' | head -1 || true)
if ! printf '%s' "$shipped" | grep -Eq '^[0-9]{4}-[0-9]{2}$'; then
  echo "::error::$SHIPPED_FILE should hold one YYYY-MM line, got: '${shipped}'"
  exit 1
fi
echo "shipped in the app: ${shipped}"

# --- what upstream has --------------------------------------------------------
# Walk backwards from the current month and stop at the first hit; that first
# hit is by definition the newest one that exists.
# DBIP_NOW pins the starting month (YYYY-MM); it exists so the look-back can be
# tested without waiting for the calendar. Unset in CI, where we want today.
now="${DBIP_NOW:-$(date -u +%Y-%m)}"
if ! printf '%s' "$now" | grep -Eq '^[0-9]{4}-[0-9]{2}$'; then
  echo "::error::DBIP_NOW should look like YYYY-MM, got: '${now}'"
  exit 1
fi
year=$((10#${now%-*}))
month=$((10#${now#*-}))
latest=""
transport_error=0

for ((i = 0; i <= LOOKBACK; i++)); do
  y=$year
  m=$((month - i))
  while ((m < 1)); do
    m=$((m + 12))
    y=$((y - 1))
  done
  candidate=$(printf '%04d-%02d' "$y" "$m")
  url=$(url_for "$candidate")

  # --retry only covers transient transport errors, not a 404.
  # On a transport failure curl already writes 000; the fallback is for the
  # case where it dies before writing anything at all.
  code=$(curl -sS --head --max-time 30 --retry 2 --retry-delay 5 \
    -o /dev/null -w '%{http_code}' "$url") || code="000"

  case "$code" in
    200)
      echo "  ${candidate}: 200 -- published"
      latest="$candidate"
      break
      ;;
    404)
      echo "  ${candidate}: 404 -- not published yet"
      ;;
    *)
      echo "  ${candidate}: HTTP ${code} -- unexpected, treating as a probe failure"
      transport_error=1
      ;;
  esac
done

if [ -z "$latest" ]; then
  echo "::error::No DB-IP release found in the last $((LOOKBACK + 1)) months at ${BASE_URL}."
  if [ "$transport_error" -eq 1 ]; then
    echo "At least one probe failed at the transport level, so this is probably network trouble."
  else
    echo "Every probe came back 404 -- DB-IP most likely changed the URL pattern."
    echo "Check https://db-ip.com/db/download/ip-to-country-lite and fix url_for() here."
  fi
  exit 1
fi

# --- verdict ------------------------------------------------------------------
# YYYY-MM sorts lexicographically the same way it sorts chronologically.
needs_update=false
if [[ "$latest" > "$shipped" ]]; then
  needs_update=true
  echo "upstream ${latest} is newer than the shipped ${shipped}"
elif [[ "$latest" < "$shipped" ]]; then
  # Shouldn't happen, but if someone ships a month DB-IP later pulled, say so
  # rather than quietly claiming everything is fine.
  echo "::warning::The app ships ${shipped} but the newest upstream file is ${latest}."
else
  echo "already on the newest release (${shipped})"
fi

{
  echo "latest=${latest}"
  echo "shipped=${shipped}"
  echo "needs_update=${needs_update}"
} | tee -a "${GITHUB_OUTPUT:-/dev/null}"
