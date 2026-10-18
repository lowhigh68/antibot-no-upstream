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

# Dinh dang THAT = `antibot_fmt`, copy tung truong tu `nginx/nginx.conf:162`:
#   $remote_addr [$time_local] "$request" $status score=.. action=.. fp=..
#   tls13=.. ja3_partial=.. ${request_time}s
# `$request_time` la token CUOI CUNG, khong phai o giua. Ban truoc cua fixture
# nay dat `%ss` TRUOC User-Agent va ghi chu thich "thoi gian o GIUA, UA o CUOI"
# — sai so voi nginx.conf, va vi sai nen 30 phep thu deu pass trong khi script
# that doc `*.bytes` (file khong he co cot thoi gian) va tra ve 0 tren may.
#
# `fp=200` co Y de o day: cot status phai tim theo token SO TRAN, khong duoc
# bat `fp=200`.
LINE() { # LINE <epoch> <uri> <status> <rt>
    printf '1.2.3.4 [%s] "GET %s HTTP/2.0" %s score=- action=- fp=200 tls13=- ja3_partial=- %ss\n' \
        "$(date -d "@$1" '+%d/%b/%Y:%H:%M:%S %z')" "$2" "$3" "$4"
}

# Dinh dang `bytes` (nginx.conf:164) — KET THUC o User-Agent, KHONG co
# `$request_time`. Day la file ma script da doc sai luc dau.
BLINE() { # BLINE <epoch> <uri> <status>
    printf '1.2.3.4 - - [%s] "GET %s HTTP/2.0" %s 1234 "-" "Mozilla/5.0 Safari/537.36"\n' \
        "$(date -d "@$1" '+%d/%b/%Y:%H:%M:%S %z')" "$2" "$3"
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
} > "$W/domains/a.test.log"
{
  LINE $T /mid 200 12.000
  LINE $T /mid 200 12.000
  # BAY: byte nhi phan -> grep phai DOC duoc, khong bo ca file
  printf 'binary\x00junk\n'
} > "$W/domains/b.test.log"

# BAY query-string: oembed that luon co `?url=...` khac nhau tung luot. Khong
# cat query thi moi luot thanh MOT URI rieng va bang xep hang vo nghia — dung
# endpoint dat tien nhat se bi xe vun thanh hang nghin dong 1-luot.
# 3 luot x 5s = 15s, PHAI gom thanh MOT dong `/q`.
{
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-1%2F' 200 5.000
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-2%2F' 200 5.000
  LINE $T '/q?url=https%3A%2F%2Fa.test%2Fbai-3%2F' 200 5.000
} > "$W/domains/c.test.log"

# `CR_KEEP=/duong/dan` giu output tho — xem ghi chu o duoi.
# Dat o thu muc RIENG de khong lam lech cac con so da tinh tay o a/b/c.test.
#
# BAY STATUS DO KHACH DIEU KHIEN: URI la chuoi do client gui, nen `/abc404`
# ket thuc bang ba chu so. Neu bieu thuc tim status thieu neo `^` thi
# `/abc404` duoc coi la ma HTTP — muc 4 va muc 5 bao mot "ma" la duong dan.
# Mot bot chi can gui `GET /x404` la lam sai lech ca hai bang.
# `fp=200` KHONG bat duoc loi nay vi status that (cot 8) den TRUOC `fp=`
# (cot 11) va vong lap `break` ngay, nen hai ban hanh xu giong nhau.
mkdir -p "$W/digiturl"
LINE $T /abc404 200 0.500 > "$W/digiturl/e.test.log"

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
   "$(printf '%s' "$out" | sed -n 's/.*(\([0-9]*\) file .*)/\1/p')"
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
LINE $OLD /x 200 1.0 > "$W/cu/z.test.log"
out_old=$(LOGDIR="$W/cu" bash "$SCRIPT" 60 2>&1); rc_old=$?
ck "toan dong cu -> rc=0, khong vo" "0" "$rc_old"
ck "noi ro khong co dong nao" "yes" \
   "$(printf '%s' "$out_old" | grep -q 'khong co dong nao' && echo yes || echo no)"
ck "khong in bang chi phi tren dan so 0" "0" \
   "$(printf '%s' "$out_old" | grep -c 'GIAY-WORKER')"

echo "── 8. DOC DUNG FILE: *.log chu khong *.bytes ────────"
# Day la loi da lam output that vo dung ngay 18-10: script doc `*.bytes`,
# in `co cot thoi gian: 0` tren 5.538 dong hop le. File `bytes` ket thuc o
# User-Agent (nginx.conf:164) nen KHONG BAO GIO co `$request_time`.
ck "van tim duoc cot thoi gian tren *.log" "8" \
   "$(printf '%s' "$out" | sed -n 's/^co cot thoi gian: *//p')"
ck "in ro dang doc glob nao" "yes" \
   "$(printf '%s' "$out" | grep -q 'file \*\.log' && echo yes || echo no)"

# Dung thu muc chi co `*.bytes` (dinh dang THAT cua file do, khong co rt).
mkdir -p "$W/bytesonly"
{ BLINE $T /x 200; BLINE $T /y 200; } > "$W/bytesonly/d.test.bytes"
ck "fixture bytes ket thuc o UA, khong co token rt" "0" \
   "$(grep -aoE '(^| )[0-9]+\.[0-9]+s$' "$W/bytesonly/d.test.bytes" | wc -l)"
# Khong co `*.log` -> phai rc=2 va noi khong thay file, KHONG lang le bao 0.
out_b=$(LOGDIR="$W/bytesonly" bash "$SCRIPT" 60 2>&1); rc_b=$?
ck "thu muc chi co .bytes -> rc=2" "2" "$rc_b"
ck "noi khong thay *.log" "yes" \
   "$(printf '%s' "$out_b" | grep -q 'khong thay file \*\.log' && echo yes || echo no)"

# Ep doc `*.bytes` qua GLOB: dong HOP LE qua duoc bo loc thoi gian nhung
# KHONG co cot thoi gian -> phai rc=3 va chi ro file nao can doc.
out_g=$(LOGDIR="$W/bytesonly" GLOB='*.bytes' bash "$SCRIPT" 60 2>&1); rc_g=$?
ck "ep doc .bytes -> rc=3 (khong phai 0)" "3" "$rc_g"
ck "van thay 2 dong hop le (bo loc thoi gian DUNG)" "2" \
   "$(printf '%s' "$out_g" | sed -n 's/^dong *: *//p')"
ck "chi ro can doc *.log" "yes" \
   "$(printf '%s' "$out_g" | grep -q 'can doc.*\*\.log' && echo yes || echo no)"
ck "chi ro dung doc *.bytes" "yes" \
   "$(printf '%s' "$out_g" | grep -q 'KHONG.*\*\.bytes' && echo yes || echo no)"

echo "── 9. status: chi token SO TRAN, khong lay tu URI ───"
# Fixture dat `fp=200` tren MOI dong, status that la 200/499.
ck "muc 5 co ma 499" "yes" \
   "$(printf '%s' "$out" | grep -qE '^ +1 luot .* 499$' && echo yes || echo no)"
# Ca quyet dinh: URI `/abc404` ket thuc bang ba chu so. Thieu neo `^` thi
# muc 5 bao "ma HTTP" la `/abc404`.
out_d=$(LOGDIR="$W/digiturl" bash "$SCRIPT" 60 2>&1)
ck "URI het bang 3 chu so -> status van la 200" "yes" \
   "$(printf '%s' "$out_d" | grep -qE '^ +1 luot .* 200$' && echo yes || echo no)"
# Chi soi MUC 5. O muc 3 thi `/abc404` xuat hien HOP LE — no la URI that.
ck "muc 5 KHONG coi duong dan la ma HTTP" "0" \
   "$(printf '%s' "$out_d" | sed -n '/^5\. MA HTTP/,$p' | grep -c '/abc404$')"

echo
echo "costrank_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
