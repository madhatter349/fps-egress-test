#!/bin/bash
# Probe fastpeoplesearch.com through Tor, rotating exits via NEWNYM.
# Usage: probe.sh <rounds> [newnym_wait]
set -u
ROUNDS="${1:-5}"
WAIT="${2:-8}"
SOCKS="--socks5-hostname 127.0.0.1:9050"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
DIR="/root/fps-tor-test"
mkdir -p "$DIR/shots"
OUT="$DIR/results.tsv"

title_of() { grep -oim1 '<title>[^<]*</title>' | sed -e 's/<[^>]*>//g' | tr -d '\r' | cut -c1-90; }

for i in $(seq 1 "$ROUNDS"); do
  if [ "$i" -gt 1 ]; then
    python3 "$DIR/torctl.py" newnym "$WAIT" >/dev/null 2>&1
  fi

  ip=$(curl -s --max-time 25 $SOCKS https://api.ipify.org || true)
  [ -z "$ip" ] && { echo -e "$i\tNO_IP\t-\t-\t-\t-\t-" >>"$OUT"; continue; }

  # ASN lookup done from the VPS itself (not through Tor)
  asn=$(python3 "$DIR/asn.py" "$ip" 2>/dev/null || echo "LOOKUP_FAIL|-|-|-")

  # Root page
  hdr=$(curl -s -o "$DIR/shots/root_$i.html" --max-time 40 $SOCKS -A "$UA" \
        -w '%{http_code}\t%{url_effective}\t%{size_download}\t%{time_total}' \
        https://www.fastpeoplesearch.com/ 2>/dev/null || echo "ERR\t-\t-\t-")
  rcode=$(echo "$hdr" | cut -f1); rurl=$(echo "$hdr" | cut -f2)
  rsize=$(echo "$hdr" | cut -f3); rtime=$(echo "$hdr" | cut -f4)
  rtitle=$(title_of < "$DIR/shots/root_$i.html")

  # Person page
  phdr=$(curl -s -o "$DIR/shots/person_$i.html" --max-time 40 $SOCKS -A "$UA" \
         -w '%{http_code}\t%{url_effective}\t%{size_download}\t%{time_total}' \
         https://www.fastpeoplesearch.com/212-862-9173 2>/dev/null || echo "ERR\t-\t-\t-")
  pcode=$(echo "$phdr" | cut -f1); purl=$(echo "$phdr" | cut -f2)
  psize=$(echo "$phdr" | cut -f3); ptime=$(echo "$phdr" | cut -f4)
  ptitle=$(title_of < "$DIR/shots/person_$i.html")

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$i" "$ip" "$asn" "$rcode" "$rurl" "$rsize" "$rtime" "$rtitle" \
    "$pcode" "$purl" "$psize" "$ptime" "$ptitle" >>"$OUT"
  printf 'round=%s ip=%s asn=%s root=%s size=%s t=%ss title=%s | person=%s size=%s title=%s\n' \
    "$i" "$ip" "$asn" "$rcode" "$rsize" "$rtime" "$rtitle" "$pcode" "$psize" "$ptitle"
done
