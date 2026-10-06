#!/usr/bin/env bash
# Скачивает JSON-фиды NVD по одному файлу с повторами в локальную папку.
# Dependency-Check потом берёт их из этой папки через локальный HTTP-сервер,
# потому что при параллельной загрузке напрямую NVD часто отвечает 404.
set -euo pipefail

OUT_DIR="${1:-nvd-mirror}"
BASE_URL="https://nvd.nist.gov/feeds/json/cve/2.0"
mkdir -p "$OUT_DIR"

fetch() {
  curl -sSf --retry 10 --retry-all-errors --retry-delay 15 --max-time 600 \
    -o "$OUT_DIR/$1" "$BASE_URL/$1"
}

for name in modified $(seq 2002 "$(date +%Y)"); do
  fetch "nvdcve-2.0-$name.meta"
  fetch "nvdcve-2.0-$name.json.gz"
  echo "downloaded nvdcve-2.0-$name"
done
