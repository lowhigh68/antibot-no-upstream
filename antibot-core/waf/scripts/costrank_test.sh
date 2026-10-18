#!/bin/bash
# costrank_test.sh — oracle cho `costrank.sh`.
#
# Fixture dung dinh dang nginx access log THAT cua fleet, va phu dung ba bay:
# cot thoi gian KHONG o $NF, byte nhi phan, va timestamp phai doi sang epoch
# (khong so sanh chuoi).

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/costrank.sh"
W=$(mktemp -d) || exit 2

cleanup() {
    local rc=$?
    rm -rf "$W"
    exit $rc
}
trap cleanup EXIT

pass=0
fail=0
ck() {
    if [ "$2" = "$3" ]; then
        echo "  OK   $1"; pass=$((pass + 1))
    else
        echo "  LOI  $1: mong=[$2] thuc=[$3]"; fail=$((fail + 1))
    fi
}

mkdir -p "$W/domains"

# Dinh dang that (xem `nginx.conf` log_format): thoi gian o GIUA, UA o CUOI.
LINE() { # LINE <epoch> <uri> <status> <rt>
    printf '1.2.3.4 [%s] "GET %s HTTP/2.0" %s 1234 "-" %ss "Mozilla/5.0 Safari/537.36"\n' \
        "$(date -d "@$1" '+%d/%b/%Y:%H:%M:%S %z')" "$2" "$3" "$4"
}

N=$(date +%s)
T=$((N - 600))
OLD=$((N - 86400))

# TINH TAY, cua so 60 phut:
#   a.test: /slow  60.007 + 40.000 = 100.007s, 2 luot
#           /fast   0.050            =   0.050s, 1 luot
#   b.test: /mid   12.000 x 2       =  24.000s, 2 luot
#   tong = 124.057s tren 5 mau
#   >30s = 2 (60.007 va 40.000) ; 59-61s = 1 (60.007)
#   URI theo chi phi: /slow 100.007 > /mid 24.000 > /fast 0.050
{
  LINE $T /slow 200 60.007
  LINE $T /slow 499 40.000
  LINE $T /fast 200 0.050
  LINE $OLD /ngoaicuaso 200 99.999
} > "$W/domains/a.test.bytes"
{
  LINE $T /mid 200 12.000
  LINE $T /mid 200 12.000
  # BAY: byte nhi phan -> grep phai DOC duoc, khong bo ca file
  printf 'binary\x00junk\n'
} > "$W/domains/b.test.bytes"

# BAY query-string: oembed that luon co `?url=...` khac nhau tung luot. Khong
# cat query thi moi luot thanh MOT URI rieng va bang xep hang vo nghia — dung
# endpoint dat tien nhat se bi xe vun thanh hang nghin dong 1-luot.
# 3 luot x 5s = 15s, PHAI gom thanh MOT dong `/q`.
{
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-1%2F' 200 5.000
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-2%2F' 200 5.000
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-3%2F' 200 5.000
} > "$W/domains/c.test.bytes"

# `CR_KEEP=/duong/dan` giu output tho — de soi khi mot phep thu bao sai ma
# chua ro loi o script hay o chinh phep thu.
run() {
    local o
    o=$(LOGDIR="$W/domains" bash "$SCRIPT" "${1:-60}" 2>&1)
    [ -n "${CR_KEEP:-}" ] && printf '%s\n' "$o" >> "$CR_KEEP"
    printf '%s\n' "$o"
}

out=$(run 60); rc=$?

echo "── 1. doc nguon + loc cua so ────────────────────────"
ck "rc=0" "0" "$rc"
ck "thay 3 file" "3" \
   "$(printf '%s' "$out" | sed -n 's/.*(\([0-9]*\) file)/\1/p')"
ck "khong in 'binary file matches'" "0" \
   "$(printf '%s' "$out" | grep -c 'binary file matches')"
ck "mau = 8 (dong ngoai cua so bi loai)" "8" \
   "$(printf '%s' "$out" | sed -n 's/^  mau *: *//p')"
ck "dong ngoai cua so khong lot" "0" \
   "$(printf '%s' "$out" | grep -c 'ngoaicuaso')"

echo "── 2. tong chi phi, khong phai so luot ──────────────"
ck "tong giay-worker = 139" "139s" \
   "$(printf '%s' "$out" | sed -n 's/.*tong giay-worker *: *\([0-9]*s\).*/\1/p')"
ck "cham nhat 60.01s" "60.01s" \
   "$(printf '%s' "$out" | sed -n 's/.*cham nhat *: *\([0-9.]*s\).*/\1/p')"
ck ">30s dem 2" "2" \
   "$(printf '%s' "$out" | sed -n 's/^  >30s *: *\([0-9]*\) .*/\1/p')"
ck "nhan ra TREO 59-61s" "1" \
   "$(printf '%s' "$out" | sed -n 's/.*59-61s.*: *\([0-9]*\)$/\1/p')"

echo "── 3. xep hang theo CHI PHI, khong theo luot ────────"
# /slow chi 2 luot nhung dat nhat; /fast 1 luot re nhat.
# Neo vao TIEU DE bang URI roi lay dong ngay sau: mau "^ so so" cung khop
# bang DOMAIN o tren, nen khong neo thi lay nham a.test.
ck "/slow dung dau bang URI" "/slow" \
   "$(printf '%s' "$out" | awk '/  URI$/{getline; print $NF; exit}')"
ck "/slow chi phi 100" "100" \
   "$(printf '%s' "$out" | awk '$NF=="/slow"{print $1; exit}')"
ck "/slow chi 2 luot" "2" \
   "$(printf '%s' "$out" | awk '$NF=="/slow"{print $2; exit}')"
ck "/mid dat thu hai du nhieu luot bang /slow" "24" \
   "$(printf '%s' "$out" | awk '$NF=="/mid"{print $1; exit}')"
# Query-string phai bi cat: 3 luot x 5s PHAI gom thanh MOT dong `/q` = 15s.
# Khong cat thi thanh 3 dong rieng, moi dong 5s, va endpoint dat tien bi xe vun.
ck "query-string bi cat, gom thanh mot URI" "15" \
   "$(printf '%s' "$out" | awk '$NF=="/q"{print $1; exit}')"
ck "/q gom dung 3 luot" "3" \
   "$(printf '%s' "$out" | awk '$NF=="/q"{print $2; exit}')"
ck "khong con URI nao mang query-string" "0" \
   "$(printf '%s' "$out" | grep -c 'url=https')"
ck "a.test dat hon b.test" "a.test" \
   "$(printf '%s' "$out" | awk '/DOMAIN$/{getline; print $NF; exit}')"

echo "── 4. tap treo ──────────────────────────────────────"
ck "so luot >30s = 2" "2" \
   "$(printf '%s' "$out" | sed -n 's/^  so luot >30s: *//p')"
ck "tap treo deu la /slow" "2" \
   "$(printf '%s' "$out" | awk '/--- theo URI ---/{f=1;next} f&&/\/slow/{print $1;exit}')"
# Dung `f=0` khi gap muc ke tiep, neu khong no dem lan sang bang muc 5.
ck "tap treo co ca 200 va 499" "2" \
   "$(printf '%s' "$out" | awk '/--- theo ma HTTP ---/{f=1;next} /^===/{f=0} f&&/^ *[0-9]+ /{n++} END{print n+0}')"

echo "── 5. ma HTTP tren toan mau ─────────────────────────"
ck "200 co 7 luot" "7" \
   "$(printf '%s' "$out" | awk '/MA HTTP tren toan bo mau/{f=1} f&&/ 200$/{print $1; exit}')"

echo "── 6. dau vao xau ───────────────────────────────────"
ck "so phut rac -> rc=2" "2" \
   "$(LOGDIR="$W/domains" bash "$SCRIPT" abc >/dev/null 2>&1; echo $?)"
ck "so phut 0 -> rc=2" "2" \
   "$(LOGDIR="$W/domains" bash "$SCRIPT" 0 >/dev/null 2>&1; echo $?)"
ck "thu muc khong ton tai -> rc=2" "2" \
   "$(LOGDIR="$W/khong-co" bash "$SCRIPT" 60 >/dev/null 2>&1; echo $?)"
mkdir -p "$W/rong"
ck "thu muc rong -> rc=2" "2" \
   "$(LOGDIR="$W/rong" bash "$SCRIPT" 60 >/dev/null 2>&1; echo $?)"

echo "── 7. dan so 0 ──────────────────────────────────────"
mkdir -p "$W/cu"
LINE $OLD /x 200 1.0 > "$W/cu/z.test.bytes"
out_old=$(LOGDIR="$W/cu" bash "$SCRIPT" 60 2>&1); rc_old=$?
ck "toan dong cu -> rc=0, khong vo" "0" "$rc_old"
ck "noi ro khong co dong nao" "yes" \
   "$(printf '%s' "$out_old" | grep -q 'khong co dong nao' && echo yes || echo no)"
ck "khong in bang chi phi tren dan so 0" "0" \
   "$(printf '%s' "$out_old" | grep -c 'GIAY-WORKER')"

echo "── 8. cot thoi gian KHONG o \$NF ─────────────────────"
# Neu lay $NF thi se ra `Safari/537.36"` va khong parse duoc -> mau = 0.
# 6 dong co UA: 5 dong trong cua so + 1 dong ngoai cua so (/ngoaicuaso).
ck "fixture co UA o cuoi dong" "9" \
   "$(grep -ac 'Safari/537.36' "$W"/domains/*.bytes | awk -F: '{s+=$2} END{print s+0}')"
ck "van tim duoc cot thoi gian" "8" \
   "$(printf '%s' "$out" | sed -n 's/^co cot thoi gian: *//p')"

echo
echo "costrank_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
