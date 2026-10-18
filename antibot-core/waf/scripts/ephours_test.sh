#!/bin/bash
# ephours_test.sh — oracle cho `ephours.sh`.
#
# Dau vao gia phu tung nhanh, TINH TAY ket qua, so, roi dot bien. Hai phep thu
# quan trong nhat la hai bay da LAM HONG output that ngay 18-10:
#   - cot ket thuc bang "ts=" (`sclients=1` -> epoch 1 -> gio rac 1970)
#   - sap xep theo chuoi tren `dd/Mon/yyyy`

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/ephours.sh"
W=$(mktemp -d) || exit 2

# Trap phai GIU LAI ma thoat: `trap 'rm -rf' EXIT` thi `rm` chay sau lenh cuoi
# va ma thoat cua no de len ma thoat that cua suite (xem p1stat_test.sh).
cleanup() {
    local rc=$?
    rm -rf "$W"
    exit $rc
}
trap cleanup EXIT

pass=0
fail=0
ck() { # ck <ten> <mong doi> <thuc te>
    if [ "$2" = "$3" ]; then
        echo "  OK   $1"
        pass=$((pass + 1))
    else
        echo "  LOI  $1: mong=[$2] thuc=[$3]"
        fail=$((fail + 1))
    fi
}

mkdir -p "$W/log"
L="$W/log/antibot.log"

# Dinh dang PHAI giong `logger.lua:968-974` tung byte.
LINE() { # LINE <epoch> <phan con lai>
    printf '[%s] [antibot] ts=%s domain=inachau.net class=navigation %s\n' \
        "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}

N=$(date +%s)
# Moc phai NEO VAO DAU GIO, khong phai tru mot so giay co dinh.
#
# Hai ban truoc deu chap chon theo dong ho:
#   - `H2 = N - 3600` nam DUNG tren bien cua so 1 gio -> lúc dat lúc truot tuy
#     vai tram mili-giay giua luc sinh fixture va luc awk goi `systime()`.
#   - `H1 = N - 5400` / `H2 = N - 2700` thi TRUNG GIO khi phut hien tai nam
#     trong khoang ~30-44: voi N = 12:30 thi N-5400 = 11:00 va N-2700 = 11:45,
#     CUNG gio 11. Hai gio gop thanh mot va 7 assert do. Do duoc 18-10 luc
#     16:45 (qua) va tai hien duoc o phut 30 (do).
#
# Neo vao dau gio thi khoang cach giua H1 va H2 luon la DUNG mot gio, khong
# phu thuoc phut hien tai.
HOUR0=$(( N - (N % 3600) ))   # dau gio hien tai
H1=$(( HOUR0 - 5400 ))        # giua gio truoc-truoc — NGOAI cua so 1h
H2=$(( HOUR0 - 1800 ))        # giua gio truoc        — cung NGOAI 1h nhung
                              # luon la MOT gio khac H1
# Mot moc TRONG gio hien tai, cho rieng phep thu "cua so 1h".
#
# `N - 60` KHONG dung: o phut 00 no roi ve gio TRUOC va trung voi H2 (kiem
# bang vong lap 60 phut, chi phut 00 trung). Neo vao dau gio + 1 giay thi no
# luon thuoc gio hien tai, va luon nam trong cua so 1h vi cutoff = N - 3600
# con HOUR0 >= N - 3599.
NOWH=$(( HOUR0 + 1 ))
OLD=$((N - 200 * 3600))

# TINH TAY, cua so 72h:
#   gio H1  : 3 dong | oembed 2 | openai 1 | anthropic 0 | operator 1 | block 1
#   gio H2  : 2 dong | oembed 0 | openai 2 | anthropic 1 | operator 2 | block 0
#   gio NOWH: 1 dong — chi de kiem cua so 1h
#   dong OLD bi loai; 3 dong BAY khong duoc tao gio nao
#   TONG CONG = 3 + 2 + 1 = 6
{
  LINE $H1 "ep=wp_oembed_embed xf_hits=1 action=allow"
  LINE $H1 "ep=wp_oembed_embed sclients=1 action=block"
  LINE $H1 "opnet=openai auttier=operator action=monitor"
  LINE $H2 "opnet=openai auttier=operator action=monitor"
  LINE $H2 "opnet=anthropic opnet=openai auttier=operator action=allow"
  LINE $NOWH "ep=wp_oembed_embed action=allow"
  LINE $OLD "ep=wp_oembed_embed action=allow"
  # BAY: cot ket thuc bang "ts=", KHONG co ts= that
  echo '[2026-10-18 09:00:00] [waf] rid=r exists=1 parts=1'
  echo '[2026-10-18 09:00:00] [antibot] sclients=1 xf_hits=1'
  echo '[2026-10-18 09:00:00] [waf-body] blen=10 parts=1'
} > "$L"

run() { LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" "${1:-72}" 2>&1; }

out=$(run 72); rc=$?
row1=$(printf '%s' "$out" | grep "$(date -d "@$H1" '+%Y-%m-%d %H')")
row2=$(printf '%s' "$out" | grep "$(date -d "@$H2" '+%Y-%m-%d %H')")

echo "── 1. bay 'cot ket thuc bang ts=' ───────────────────"
ck "rc=0" "0" "$rc"
ck "KHONG co gio 1970" "0" \
   "$(printf '%s' "$out" | grep -c '^1970-')"
ck "KHONG co gio rac ngoai ba gio that" "3" \
   "$(printf '%s' "$out" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2} ')"
ck "fixture co that 3 dong bay" "3" \
   "$(grep -cE 'exists=1|sclients=1 xf_hits=1|blen=10 parts=1' "$L")"

echo "── 2. dem dung tung cot ────────────────────────────"
ck "gio H1 TONG=3"      "3" "$(printf '%s' "$row1" | awk '{print $3}')"
ck "gio H1 OEMBED=2"    "2" "$(printf '%s' "$row1" | awk '{print $4}')"
ck "gio H1 OPENAI=1"    "1" "$(printf '%s' "$row1" | awk '{print $5}')"
ck "gio H1 OPERATOR=1"  "1" "$(printf '%s' "$row1" | awk '{print $7}')"
ck "gio H1 BLOCK=1"     "1" "$(printf '%s' "$row1" | awk '{print $8}')"
ck "gio H2 TONG=2"      "2" "$(printf '%s' "$row2" | awk '{print $3}')"
ck "gio H2 OEMBED=0"    "0" "$(printf '%s' "$row2" | awk '{print $4}')"
ck "gio H2 OPENAI=2"    "2" "$(printf '%s' "$row2" | awk '{print $5}')"
ck "gio H2 ANTHROP=1"   "1" "$(printf '%s' "$row2" | awk '{print $6}')"

echo "── 3. cua so thoi gian ──────────────────────────────"
ck "dong qua cu bi loai (TONG CONG=6)" "6" \
   "$(printf '%s' "$out" | awk '/^TONG CONG/{print $3}')"
out1h=$(run 1)
ck "cua so 1h chi con gio gan nhat" "1" \
   "$(printf '%s' "$out1h" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2} ')"

echo "── 4. thu tu gio tang dan ───────────────────────────"
ck "gio sap tang dan" "yes" \
   "$(printf '%s' "$out" | grep -E '^[0-9]{4}-' | awk '{print $1, $2}' \
      | { sort -c 2>/dev/null && echo yes || echo no; })"

echo "── 5. dau vao xau ───────────────────────────────────"
ck "so gio rac -> rc=2" "2" \
   "$(LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" abc >/dev/null 2>&1; echo $?)"
ck "so gio 0 -> rc=2" "2" \
   "$(LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" 0 >/dev/null 2>&1; echo $?)"
ck "khong co file -> rc=2" "2" \
   "$(LOGDIR="$W/khong-ton-tai" BASE=antibot.log bash "$SCRIPT" 72 >/dev/null 2>&1; echo $?)"

echo "── 6. log xoay vong ─────────────────────────────────"
gzip -c "$L" > "$W/log/antibot.log.1.gz"
: > "$L"
out_rot=$(run 72)
ck "doc duoc du lieu trong .gz" "6" \
   "$(printf '%s' "$out_rot" | awk '/^TONG CONG/{print $3}')"
ck "in ra ten file .gz" "yes" \
   "$(printf '%s' "$out_rot" | grep -q 'antibot.log.1.gz' && echo yes || echo no)"
rm -f "$W/log/antibot.log.1.gz"

echo "── 7. DOT BIEN: go guard thi phai SAI ───────────────"
# Day la phep thu quyet dinh: neu go `(^|[[:space:]])` ma ket qua KHONG doi
# thi fixture khong co bay that, va ca bo kiem nay vo nghia.
cp "$SCRIPT" "$W/mut.sh"
# Thay bieu thuc co guard bang ban khong guard. Dung awk voi chuoi co dinh
# (`index`/`substr`) chu KHONG dung `sed s///`: mau chua `[`, `]`, `(`, `|`,
# `^` nen moi lan escape cho sed la mot lan de sai — lan dau viet bo kiem nay
# sed bao `unknown option to 's'` va phep thu dot bien im lang thanh vo nghia
# (bao "mong=1 thuc=0" chi vi ban dot bien chua he duoc tao).
GUARD='(^|[[:space:]])ts=[0-9]+'
PLAIN='ts=[0-9]+'
awk -v g="$GUARD" -v p="$PLAIN" '
{
    i = index($0, g)
    if (i > 0) {
        $0 = substr($0, 1, i - 1) p substr($0, i + length(g))
        changed++
    }
    print
}
END { if (changed == 0) exit 9 }' "$SCRIPT" > "$W/mut.sh.tmp"
mut_rc=$?
if [ "$mut_rc" -ne 0 ]; then
    echo "  LOI  khong tao duoc ban dot bien (khong tim thay guard trong script)"
    fail=$((fail + 1))
else
    mv "$W/mut.sh.tmp" "$W/mut.sh"
fi
# Dung lai fixture co dong bay
{
  LINE $H1 "ep=wp_oembed_embed xf_hits=1 action=allow"
  echo '[2026-10-18 09:00:00] [antibot] sclients=1 xf_hits=1'
} > "$L"
# Phan biet dung cho nao. Voi cua so 72h, dong bay cho epoch 1 (nam 1970) nen
# bi chinh cutoff loai — ban dot bien va ban that TRONG GIONG NHAU o day. Phep
# thu phai do cai THAT SU khac: ban khong guard COI dong bay la mot dong hop le
# va DEM no; ban co guard thi bo qua tu dau.
#
# Do bang cua so du rong de epoch 1 nam trong pham vi. `systime()` ~1.79e9 giay
# nen can ~497.000 gio; dung 600000 cho chac.
HUGE=600000
mut_out=$(LOGDIR="$W/log" BASE=antibot.log bash "$W/mut.sh" "$HUGE" 2>&1)
ck "ban KHONG guard dem dong bay thanh gio 1970" "1" \
   "$(printf '%s' "$mut_out" | grep -c '^1970-')"
clean_out=$(LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" "$HUGE" 2>&1)
ck "ban CO guard khong sinh gio 1970" "0" \
   "$(printf '%s' "$clean_out" | grep -c '^1970-')"
# Fixture o buoc nay con MOT dong hop le (H1) ben canh dong bay, nen ban co
# guard phai in dung MOT gio — khong phai "khong co dong nao".
ck "ban CO guard chi dem dong hop le (1 gio)" "1" \
   "$(printf '%s' "$clean_out" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2} ')"
ck "ban KHONG guard dem THEM mot gio rac (2 gio)" "2" \
   "$(printf '%s' "$mut_out" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2} ')"

echo
echo "ephours_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
