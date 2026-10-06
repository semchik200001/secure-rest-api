#!/usr/bin/env bash
# Обновляет локальное зеркало JSON-фидов NVD для Dependency-Check.
# Файлы качаются по одному с повторами, потому что при параллельной загрузке
# NVD часто отвечает ошибками. Годовой фид скачивается заново, только если
# изменилась его контрольная сумма в .meta, поэтому с кэшем это быстро.
set -euo pipefail

OUT_DIR="${1:-nvd-mirror}"
BASE_URL="https://nvd.nist.gov/feeds/json/cve/2.0"
mkdir -p "$OUT_DIR"

fetch() {
  curl -sSf --retry 8 --retry-all-errors --retry-delay 20 --connect-timeout 30 --max-time 300 \
    -o "$2" "$BASE_URL/$1"
}

for name in modified $(seq 2002 "$(date +%Y)"); do
  feed="nvdcve-2.0-$name"
  fetch "$feed.meta" "$OUT_DIR/$feed.meta.new"

  if [ -f "$OUT_DIR/$feed.json.gz" ] && [ -f "$OUT_DIR/$feed.meta" ] &&
     [ "$(grep sha256 "$OUT_DIR/$feed.meta")" = "$(grep sha256 "$OUT_DIR/$feed.meta.new")" ]; then
    echo "$feed: up to date"
  else
    fetch "$feed.json.gz" "$OUT_DIR/$feed.json.gz"
    echo "$feed: downloaded"
  fi
  mv "$OUT_DIR/$feed.meta.new" "$OUT_DIR/$feed.meta"
done
