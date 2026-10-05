#!/bin/bash
# postdeploy_test.sh — kiem CHINH BAO CAO bang log GIA co dap an biet truoc.
#
# VI SAO CAN: `postdeploy.sh` la mot lenh DO, va mot lenh do hong khong bao loi —
# no tra ve so trong-co-ly. Ho loi do da xay ra bay lan trong mot buoi (memory
# `feedback_read_log_schema_first`), va lan nay no xay ra NGAY TRONG chinh bao cao
# nay: dong `rid` in "phai > 0" cho mot truong hop 0 la dung, va muc 7 ghep
# `antibot.log` bang mot chuoi LIEN (`ts=N domain=X`) — dung voi thu tu cot that
# (`async/logger.lua:605`) nhung khong ai tung kiem.
#
# Nen bo nay sinh log gia phu MOI nhom, roi doi chieu voi dap an tinh TAY.
#
# CHAY:  bash waf/scripts/postdeploy_test.sh
# Ma thoat: 0 = moi con so khop, 1 = co lech.
set -u
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(mktemp -d /var/tmp/pdtest.XXXXXX)
trap 'rm -rf "$R"' EXIT
mkdir -p "$R/A" "$R/L" "$R/E"
ln -s "$HERE/.." "$R/A/waf"

T=$(date -d '-25 hour' '+%Y-%m-%d %H:%M:%S')
N=$(date -d '-2 hour' '+%Y-%m-%d %H:%M:%S')
OLD=$(date -d '-30 hour' '+%Y-%m-%d %H:%M:%S')
printf 'deployed=%s\nsha=testsha\n' "$T" > "$R/A/VERSION"
printf '%s [error] 1#1: [waf-v2] config loi cu\n' "$(date -d '-30 hour' '+%Y/%m/%d %H:%M:%S')" > "$R/E/error.log"
printf '%s [error] 1#1: [waf-v2] config bi tu choi\n' "$(date -d '-3 hour' '+%Y/%m/%d %H:%M:%S')" >> "$R/E/error.log"

# MOT `ts=` tren moi dong: bo tach truong lay gia tri CUOI, nen mot truong trung ten
# lam doi khoa ghep trong im lang (da mac loi nay khi viet bo kiem nay).
B='id=- ip=1.2.3.4 method=POST cl=900 te=- proto=2.0 blen=500 spill=0 nargs=- richness=- vfy=0'
{
# ── DONG TRUOC MOC DEPLOY: phai bi loai khoi moi muc ──
echo "[$OLD] [waf-body] ts=1 $B rid=old1 domain=old.test uri=/old ct=multipart class=navigation scan=spill_thread fntr=spill_thread nf=- fl=- fn=- uprule=- pf=- pnf=- pfl=- parts=- qh=9 qw=99 qhk=1 qwk=1 qms=9999 php=- smp=1"

# ── Muc 3: luat tham so theo VUNG. smp=20 -> nhan 20 ──
echo "[$N] [waf-body] ts=1 $B rid=r01 domain=a.test uri=/p1 ct=multipart class=navigation scan=ok fntr=0 nf=arg_traversal fl=- fn=- uprule=- pf=ok pnf=0 pfl=0 parts=1:0:0 php=0 smp=20"
echo "[$N] [waf-body] ts=1 $B rid=r02 domain=a.test uri=/p2 ct=multipart class=navigation scan=ok fntr=0 nf=- fl=arg_php_wrapper,arg_traversal fn=- uprule=- pf=ok pnf=0 pfl=0 parts=1:0:0 php=0 smp=1"

# ── Muc 4: multipart chung minh duoc / khong ──
echo "[$N] [waf-body] ts=1 $B rid=r03 domain=b.test uri=/p3 ct=multipart class=navigation scan=ok fntr=hdr nf=- fl=- fn=- uprule=- pf=hdr pnf=0 pfl=0 parts=- php=0 smp=1"

# ── Muc 5 + 8: than KHONG soi duoc (multipart -> B1) ──
echo "[$N] [waf-body] ts=1 $B rid=r04 domain=c.test uri=/up ct=multipart class=interaction scan=spill_thread fntr=spill_thread nf=- fl=- fn=- uprule=- pf=- pnf=- pfl=- parts=- php=- qh=3 qw=131 qhk=900 qwk=90000 qms=12 smp=1"
# B1 qua kenh ten tep (fntr=n) nhung DA soi (scan=ok)
echo "[$N] [waf-body] ts=1 $B rid=r05 domain=c.test uri=/up ct=multipart class=interaction scan=ok fntr=n nf=- fl=- fn=- uprule=- pf=n pnf=0 pfl=0 parts=- php=0 smp=1"
# fntr=len KHONG thuoc FN_INCOMPLETE -> muc 8 phai BO QUA
echo "[$N] [waf-body] ts=1 $B rid=r06 domain=c.test uri=/up ct=multipart class=interaction scan=ok fntr=len nf=- fl=- fn=- uprule=- pf=ok pnf=0 pfl=0 parts=1:0:0 php=0 smp=1"
# urlencoded khong soi duoc: muc 5 CO, muc 8 KHONG (khong phai multipart)
echo "[$N] [waf-body] ts=1 $B rid=r07 domain=c.test uri=/x ct=urlencoded class=api_callback scan=spill_big fntr=- nf=- fl=- fn=- uprule=- pf=- pnf=- pfl=- parts=- php=- smp=1"

# ── Muc 9: hang doi. 4 luot qua pool, qw lon nhat 131, qms lon nhat 240 ──
echo "[$N] [waf-body] ts=1 $B rid=r08 domain=d.test uri=/u ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=0 pfl=1 parts=1:0:php_tag php=1 qh=2 qw=5 qhk=100 qwk=500 qms=240 smp=1"
echo "[$N] [waf-body] ts=1 $B rid=r09 domain=d.test uri=/u ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=1 pfl=0 parts=1:0:0 php=1 qh=1 qw=2 qhk=10 qwk=20 qms=5 smp=1"

# ── Muc 10 + 11: V8 ──
# cung part: shell.php chua <?php
echo "[$N] [waf-body] ts=1 $B rid=r10 domain=e.test uri=/wp-admin/async-upload.php ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_php_ext pf=ok pnf=0 pfl=1 parts=1:upload_php_ext:php_tag php=1 smp=1"
# hai part KHAC nhau
echo "[$N] [waf-body] ts=1 $B rid=r11 domain=e.test uri=/up ct=multipart class=navigation scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_php_ext pf=ok pnf=0 pfl=1 parts=1:upload_php_ext:0;3:0:php_tag php=1 smp=1"
# .htaccess doi handler (php MU)
echo "[$N] [waf-body] ts=1 $B rid=r12 domain=e.test uri=/up ct=multipart class=navigation scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_apache_config pf=ok pnf=0 pfl=0 parts=1:upload_apache_config:handler php=0 smp=1"
# .user.ini nap ma
echo "[$N] [waf-body] ts=1 $B rid=r13 domain=e.test uri=/up ct=multipart class=navigation scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_user_ini pf=ok pnf=0 pfl=0 parts=1:upload_user_ini:autoload php=0 smp=1"
# tep cau hinh soi KHONG HET
echo "[$N] [waf-body] ts=1 $B rid=r14 domain=e.test uri=/up ct=multipart class=navigation scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_user_ini pf=ok pnf=0 pfl=0 parts=1:upload_user_ini:0:config_trunc php=0 smp=1"
# anh lon co <?= trong byte tep, ten sach -> nhom FP da do 26-09
echo "[$N] [waf-body] ts=1 $B rid=r15 domain=f.test uri=/media ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=0 pfl=1 parts=1:0:php_tag php=1 smp=1"
# the PHP o FORM FIELD, khong trong tep
echo "[$N] [waf-body] ts=1 $B rid=r16 domain=f.test uri=/form ct=multipart class=navigation scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=1 pfl=0 parts=1:0:0 php=1 smp=20"

# ── Muc 12: duoi vs byte dau (muc 7 cua roadmap) ──
# TEN SACH + ca hai co: nhom ma ca kenh ten lan find_php_tag deu MU.
echo "[$N] [waf-body] ts=1 $B rid=r17 domain=i.test uri=/up ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=0 pfl=0 parts=1:0:magic_exec,magic_mismatch php=0 smp=1"
# TEN SACH + CHI mismatch, smp=20 -> phai nhan 20
echo "[$N] [waf-body] ts=1 $B rid=r18 domain=i.test uri=/up ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=- pf=ok pnf=0 pfl=0 parts=1:0:magic_mismatch php=0 smp=20"
# TEN DA NGHI + exec: phai vao nhom `ten da nghi`, KHONG vao `ten sach`
echo "[$N] [waf-body] ts=1 $B rid=r19 domain=i.test uri=/up ct=multipart class=interaction scan=ok fntr=0 nf=- fl=- fn=- uprule=upload_php_ext pf=ok pnf=0 pfl=0 parts=1:upload_php_ext:magic_exec php=0 smp=1"

# ── Muc 6: phien co cookie WP dang nhap ──
echo "[$N] [waf] ts=2 rid=r20 id=u1 domain=g.test ip=9.9.9.9 rule=wp_plugin_direct target=URI sev=notice pl=0 matched=/wp-content/plugins/x/a.php score=12.50 action=signal class=navigation richness=0.80 wpauth=1 vfy=0 status=200 exists=1 final=monitor fim=0 mode=enforce exc=- wact=allow would=allow wscore=12.50 pver=2.0"
echo "[$N] [waf] ts=3 rid=r21 id=u2 domain=g.test ip=9.9.9.9 rule=wp_root_unknown target=URI sev=notice pl=0 matched=/get.php score=25.00 action=signal class=navigation richness=0.80 wpauth=1 vfy=0 status=200 exists=1 final=challenge fim=0 mode=enforce exc=- wact=allow would=allow wscore=25.00 pver=2.0"

# ── Muc 7: luat duong dan tren file CO THAT bi chan ──
echo "[$N] [waf] ts=4 rid=r22 id=- domain=h.test ip=8.8.8.8 rule=wp_theme_direct target=URI sev=notice pl=0 matched=/wp-content/themes/t/b.php score=12.50 action=signal class=navigation richness=- wpauth=0 vfy=0 status=200 exists=1 final=block fim=0 mode=enforce exc=- wact=allow would=allow wscore=12.50 pver=2.0"
# exists=0 -> muc 7 KHONG dem
echo "[$N] [waf] ts=5 rid=r23 id=- domain=h.test ip=8.8.8.8 rule=wp_root_unknown target=URI sev=notice pl=0 matched=/none.php score=25.00 action=signal class=navigation richness=- wpauth=0 vfy=0 status=404 exists=0 final=block fim=0 mode=enforce exc=- wact=allow would=allow wscore=25.00 pver=2.0"
# MOT request vua co than VUA khop luat -> rid trung
echo "[$N] [waf] ts=6 rid=r10 id=- domain=e.test ip=1.2.3.4 rule=upload_php_executable_content target=MULTIPART_PART sev=notice pl=0 matched=slot=1_upload_php_ext+php_tag score=100.00 action=block class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=monitor fim=0 mode=shadow exc=- wact=allow would=block wscore=50.00 pver=2.0"

# ── Muc 13: tep cau hinh vua bi sua (muc 8 cua roadmap) ──
# `matched` la TEN TEP CAU HINH (hang so trong ma), khong phai duong dan.
echo "[$N] [waf] ts=7 rid=r24 id=- domain=j.test ip=7.7.7.7 rule=fim_config_active target=URI sev=notice pl=0 matched=.htaccess score=0.00 action=observe class=navigation richness=- wpauth=0 vfy=0 status=200 exists=1 final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0"
# smp=20 -> phai nhan 20
echo "[$N] [waf] ts=8 rid=r25 id=- domain=j.test ip=7.7.7.7 rule=fim_config_active target=URI sev=notice pl=0 matched=.user.ini score=0.00 action=observe class=navigation richness=- wpauth=0 vfy=0 status=200 exists=1 final=monitor fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=20"

# ── Muc 14: hop dong endpoint (muc 5 cua roadmap) ──
# `matched` la TEN ROUTE (khoa bang CONTRACTS), khong phai URI tho.
echo "[$N] [waf] ts=9 rid=r26 id=- domain=k.test ip=6.6.6.6 rule=route_upload target=URI sev=notice pl=0 matched=/wp-cron.php score=0.00 action=observe class=navigation richness=- wpauth=0 vfy=0 status=200 exists=1 final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0"
# smp=20 -> phai nhan 20
echo "[$N] [waf] ts=10 rid=r27 id=- domain=k.test ip=6.6.6.6 rule=route_ct target=URI sev=notice pl=0 matched=/xmlrpc.php score=0.00 action=observe class=api_callback richness=- wpauth=0 vfy=0 status=200 exists=1 final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=20"
echo "[$N] [waf] ts=11 rid=r28 id=- domain=k.test ip=6.6.6.6 rule=route_method target=URI sev=notice pl=0 matched=/wp-login.php score=0.00 action=observe class=auth_endpoint richness=- wpauth=0 vfy=0 status=200 exists=1 final=monitor fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0"

# ── Muc 14 (bo sung): route_multipart do RIENG ──
# Ban truoc coi MOI multipart la `route_upload`; nay `route_upload` doi PARSER
# chung minh co part tep, va `route_multipart` do rieng phan con lai.
echo "[$N] [waf] ts=12 rid=r29 id=- domain=k.test ip=6.6.6.6 rule=route_multipart target=URI sev=notice pl=0 matched=/wp-cron.php score=0.00 action=observe class=navigation richness=- wpauth=0 vfy=0 status=200 exists=1 final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0"

# ── Muc 15: tep cau hinh soi KHONG HET (duong bypass) ──
# `matched` = "slot=N <ly do>". smp=5 -> phai nhan 5.
echo "[$N] [waf] ts=13 rid=r30 id=- domain=l.test ip=5.5.5.5 rule=upload_config_scan_incomplete target=MULTIPART_PART sev=notice pl=0 matched=slot=1_config_trunc score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=5"
echo "[$N] [waf] ts=13 rid=r40 id=- domain=m.test ip=6.6.6.6 rule=body_ct_missing target=BODY sev=notice pl=0 matched=cl=100 score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=1"
echo "[$N] [waf] ts=13 rid=r41 id=- domain=m.test ip=6.6.6.6 rule=body_ct_missing target=BODY sev=notice pl=0 matched=cl=200 score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=2"
echo "[$N] [waf] ts=13 rid=r42 id=- domain=n.test ip=7.7.7.7 rule=body_ct_missing target=BODY sev=notice pl=0 matched=cl=1000 score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=1"
# ── BON NHOM vung mu Content-Type ────────────────────────────────────
# Ba dong duoi mang TEN NHOM chu khong `cl=<so>`: ban truoc lam `v + 0` tren ca
# `matched` nen mot `te_chunked` cong 0 vao tong va keo trung binh xuong. Dap an
# tinh BANG TAY: tong luot 4+1+3+1 = 9, domain 3, IP 3; nhung `cl_positive` PHAI
# giu nguyen 4 luot / max 1000 / tb 375 — do la chinh dieu phep tach bao dam.
echo "[$N] [waf] ts=13 rid=r43 id=- domain=m.test ip=6.6.6.6 rule=body_ct_missing target=BODY sev=notice pl=0 matched=te_chunked score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=1"
echo "[$N] [waf] ts=13 rid=r44 id=- domain=p.test ip=8.8.8.8 rule=body_ct_missing target=BODY sev=notice pl=0 matched=cl_absent score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=3"
echo "[$N] [waf] ts=13 rid=r45 id=- domain=p.test ip=8.8.8.8 rule=body_ct_missing target=BODY sev=notice pl=0 matched=cl_zero score=0.00 action=observe class=interaction richness=- wpauth=0 vfy=0 status=200 exists=- final=allow fim=0 mode=enforce exc=- wact=allow would=allow wscore=0.00 pver=2.0 smp=1"
} > "$R/L/waf.log"
{
echo "[$N] [antibot] ts=4 domain=h.test class=navigation id=- ip=8.8.8.8 action=block top=waf_wp_path=39% reason=score"
# ── Muc 21: static MISS theo domain ──────────────────────────────────
# DAP AN TINH BANG TAY tu bay dong duoi (KHONG lay tu output):
#   mig.test  : 3 dong ractual=false, IP 11.0.0.1 / 11.0.0.2 / 11.0.0.3
#               -> miss=3  ip-miss=3  429=0      (hinh dang KHACH THAT 404 anh)
#   bot.test  : 2 dong ractual=false, CUNG IP 12.0.0.9, mot dong throttled
#               -> miss=2  ip-miss=1  429=1      (hinh dang MOT bot quet)
#   ok.test   : 1 dong ractual=true                      -> hit=1
#   nd.test   : 1 dong ractual=-                         -> khong-do=1
# Dong `navigation` o tren KHONG co cot ractual= nen phai bi BO QUA hoan toan;
# neu no bi dem thi h.test xuat hien trong bang (da thu dot bien, bao gia).
echo "[$N] [antibot] ts=21 domain=mig.test class=resource id=- ip=11.0.0.1 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=dynamic adm_route=4 backend=- rcand=true ractual=false"
echo "[$N] [antibot] ts=21 domain=mig.test class=resource id=- ip=11.0.0.2 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=dynamic adm_route=4 backend=- rcand=true ractual=false"
echo "[$N] [antibot] ts=21 domain=mig.test class=resource id=- ip=11.0.0.3 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=dynamic adm_route=9 backend=- rcand=true ractual=false"
echo "[$N] [antibot] ts=21 domain=bot.test class=resource id=- ip=12.0.0.9 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=dynamic adm_route=2 backend=- rcand=true ractual=false"
echo "[$N] [antibot] ts=21 domain=bot.test class=resource id=- ip=12.0.0.9 action=throttled reason=l7_admission:ip_resource adm=ip_resource adm_n=251 adm_lim=250 adm_win=1 adm_grp=dynamic adm_route=2 backend=- rcand=true ractual=false"
echo "[$N] [antibot] ts=21 domain=ok.test class=resource id=- ip=13.0.0.1 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=resource adm_route=1 backend=- rcand=true ractual=true"
echo "[$N] [antibot] ts=21 domain=nd.test class=resource id=- ip=14.0.0.1 action=allow reason=- adm=- adm_n=- adm_lim=- adm_win=- adm_grp=resource adm_route=1 backend=- rcand=true ractual=-"
} > "$R/L/antibot.log"
WEBP=/home/u1/domains/s.test/public_html

# ── Muc 17: bo dem so lan doi ───────────────────────────────────────
# Dap an tinh BANG TAY tu fixture duoi:
#   uploads/sucuri/  3 tep, 4+3+2 = 9 lan
#   uploads/         2 tep, 1+1   = 2 lan
#   tong 5 duong dan, 3 dat nguong (>=2)
# `hot` KHONG co tep bo dem -> phai in dong "chua co", khong duoc im.
mkdir -p "$R/FS"
NOW=$(date +%s)
{
    printf '4|%d|%s/wp-content/uploads/sucuri/sucuri-hookdata.php\n'  "$NOW" "$WEBP"
    printf '3|%d|%s/wp-content/uploads/sucuri/sucuri-settings.php\n'  "$NOW" "$WEBP"
    printf '2|%d|%s/wp-content/uploads/sucuri/sucuri-lastlogins.php\n' "$((NOW - 3600))" "$WEBP"
    printf '1|%d|%s/wp-content/uploads/a.php\n' "$((NOW - 86400 * 5))" "$WEBP"
    printf '1|%d|%s/wp-content/uploads/b.php\n' "$((NOW - 86400 * 5))" "$WEBP"
} > "$R/FS/chgcount.full.txt"
OUT=$(A="$R/A" L="$R/L" E="$R/E/error.log" FS="$R/FS" bash "$HERE/postdeploy.sh" 2>&1)
pass=0; fail=0
# `want` doi mot DONG khop mau; `nwant` doi KHONG dong nao khop.
want()  { if printf '%s\n' "$OUT" | grep -qE "$2"; then pass=$((pass+1));
          else fail=$((fail+1)); printf 'HONG  %s\n      khong thay mau: %s\n' "$1" "$2"; fi }
nwant() { if printf '%s\n' "$OUT" | grep -qE "$2"; then
            fail=$((fail+1)); printf 'HONG  %s\n      KHONG duoc co mau: %s\n' "$1" "$2";
          else pass=$((pass+1)); fi }

echo "postdeploy_test: doi chieu voi dap an tinh tay"

# ── Muc 0: cua so, va dong TRUOC moc deploy phai bi loai ───────────────────
want  "0 so dong"              'dong \[waf\] 18   dong \[waf-body\] 19'
want  "0 rid tren >1 dong"     'rid tren >1 dong: 1   request co CA dong luat lan dong than: 1'
nwant "0 loai dong truoc moc"  'old\.test'

# ── Muc 1: chi dem dong SAU moc ────────────────────────────────────────────
want  "1 cau hinh bi tu choi"  'cau hinh bi tu choi : 1'
want  "1 registry lech"        'registry lech       : 0'

# ── Muc 3: luat theo VUNG, da nhan smp ─────────────────────────────────────
want  "3 nf nhan smp=20"       'nf  arg_traversal  pf=ok +20 +1'
want  "3 fl wrapper"           'fl  arg_php_wrapper  pf=ok +1 +1'
want  "3 fl traversal"         'fl  arg_traversal  pf=ok +1 +1'

# ── Muc 4: 16 dong multipart, tong smp 54 ──────────────────────────────────
# 15 dong multipart (r07 la urlencoded nen KHONG tinh), tong smp 53.
want  "4 tong multipart"       'tong multipart: 75'
want  "4 pf=hdr"               'pf=hdr  fntr=hdr +1'

# ── Muc 5: KHONG soi duoc, ke ca urlencoded ────────────────────────────────
want  "5 spill_thread"         'scan=spill_thread +1'
want  "5 spill_big"            'scan=spill_big +1'

# ── Muc 8 (B1): CHI multipart, va CHI ma trong FN_INCOMPLETE ───────────────
want  "8 tong"                 'tong 3\.'
want  "8 spill_thread"         'spill_thread +1'
want  "8 fntr_n"               'fntr_n +1'
want  "8 fntr_hdr"             'fntr_hdr +1'

# `nwant` quet TOAN BO output, nen khong dung duoc cho `spill_big`: muc 5 in chuoi do
# mot cach HOP LE (than urlencoded khong soi duoc). Phai kiem TRONG PHAM VI muc 8.
sect() { printf '%s\n' "$OUT" | sed -n "/=== $1\./,/=== $2\./p"; }
if sect 8 9 | grep -qE 'spill_big|fntr_len'; then
    fail=$((fail+1)); printf 'HONG  8 chi multipart va chi ma FN_INCOMPLETE\n      muc 8 KHONG duoc chua spill_big (urlencoded) hay fntr_len\n'
else pass=$((pass+1)); fi
# Va muc 5 PHAI co no: hai muc tra loi hai cau khac nhau tren cung mot dong log.
if sect 5 6 | grep -qE 'scan=spill_big'; then pass=$((pass+1));
else fail=$((fail+1)); printf 'HONG  5 phai co spill_big cua than urlencoded\n'; fi

# ── Muc 9 (B3): hang doi ───────────────────────────────────────────────────
want  "9 so luot qua pool"     '3 luot qua pool'
want  "9 qw lon nhat"          'qw \(ca worker\) lon nhat 131'
want  "9 qh lon nhat"          'qh \(mot server block\) lon nhat 3'
want  "9 duong cong K"         'K=1:2  K=2:1  K=4:0  K=8:0  K=16:0'
want  "9 qms lon nhat"         'qms lon nhat 240 ms'

# ── Muc 10 (V8): the PHP theo vung ─────────────────────────────────────────
want  "10 chi trong tep"       'CHI trong tep: 4\.  Co ngoai tep: 21'
want  "10 nhom pnf=1"          'php=1  pnf=1  pfl=0  pf=ok +21'

# ── Muc 11 (V8): part record ───────────────────────────────────────────────
want  "11 tong than co part"   'tong than co part tep: 72'
want  "11 cung part"           'CUNG part \(ten nguy hiem \+ noi dung nguy hiem\): 4'
want  "11 hai part khac nhau"  'hai part KHAC nhau .*: 1'
want  "11 chi ten / chi noi dung" 'chi ten nguy hiem: 1    chi noi dung nguy hiem: 23'
want  "11 apache handler"      'cung part: upload_apache_config  \+  handler'
want  "11 php_ext php_tag"     'cung part: upload_php_ext  \+  php_tag'
want  "11 php_config autoload" 'cung part: upload_user_ini  \+  autoload'
want  "11 config_trunc"        'tep cau hinh soi KHONG HET: 1 part'

# ── Muc 6, 7: phien dang nhap va ghep antibot.log ──────────────────────────
want  "6 canh bao phien"       '1 luot CHAN/THU THACH phien dang nhap: GUI NGAY'
want  "7 exists=1 dem dung"    '4 luot luat duong dan, 2 tren file co that'
nwant "7 exists=0 KHONG dem"   'none\.php'
want  "7 ghep antibot.log"     'antibot.log cung ts\+ip\+domain: 1 dong'
want  "7 ly do engine chan"    'block  reason=score  waf_wp_path=39%'


# ── Muc 12 (roadmap muc 7): duoi vs byte dau ───────────────────────────────
# Dap an tinh TAY, dem part x smp:
#   r01 20, r02/r06/r09 3, r08/r15 2, r10 1, r11 2 (hai record), r12/r13/r14 3,
#   r16 20  = 51; cong r17 1 + r18 20 + r19 1 = 73.
#   magic_exec: r17(1) + r19(1) = 2   (ten sach 1, ten da nghi 1)
#   magic_mismatch: r17(1) + r18(20) = 21   (ten sach 21, ten da nghi 0)
#   ca hai tren cung part: r17 = 1
want  "12 tong part tep"       'tong part tep: 73'
want  "12 magic_exec"          'magic_exec .*: +2 +ten sach: +1 +ten da nghi: +1'
want  "12 magic_mismatch"      'magic_mismatch .*: +21 +ten sach: +21 +ten da nghi: +0'
want  "12 ca hai cung part"    'ca hai co tren cung mot part: +1'
# Muc 11 va muc 12 phai NHAT QUAN tren cung mot dong log: r19 (`upload_php_ext` +
# `magic_exec`) la mot part "ten da nghi" o muc 12, va cung part do o muc 11.
want  "12 nhat quan voi muc 11" 'cung part: upload_php_ext  \+  magic_exec'

# ── Muc 13 (roadmap muc 8): tep cau hinh bi sua ────────────────────────────
# Dap an tinh TAY: r24 smp=1 + r25 smp=20 = 21.
want  "13 tong luot"           'tong: 21 luot'
want  "13 htaccess"            'tep cau hinh: \.htaccess +1'
want  "13 user.ini nhan smp"   'tep cau hinh: \.user\.ini +20'
want  "13 domain"              'domain: j\.test +21'
want  "13 final monitor"       'phan quyet THAT cua engine: monitor +20'


# ── Muc 14 (roadmap muc 5): hop dong endpoint ──────────────────────────────
# Dap an tinh TAY: r26(1) + r27(20) + r28(1) = 22.
want  "14 tong luot"           'tong: 23 luot'
want  "14 route_multipart"     'route_multipart +1'
want  "14 route_upload"        'route_upload +1'
want  "14 route_ct nhan smp"   'route_ct +20'
want  "14 route_method"        'route_method +1'
want  "14 theo route cron"     '/wp-cron\.php +1'
want  "14 theo route xmlrpc"   '/xmlrpc\.php +20'
want  "14 domain"              'domain: k\.test +23'

# ── Muc 15: tep cau hinh soi KHONG HET ─────────────────────────────────────
# Dap an tinh TAY: r30 smp=5 = 5.
# LY DO phai la `config_trunc` NGUYEN VEN: `scrub` (waf_logger.lua:43) doi khoang
# trang thanh `_`, nen tren log that `matched` la `slot=1_config_trunc`. Mot phep
# tach theo `_` roi lay truong 2 se cho `config` — dung mot nua, tuc nhan SAI.
want  "15 tong luot"           'tong: 5 luot'
want  "15 ly do nguyen ven"    'ly do: config_trunc +5'
nwant "15 KHONG cat nham nhan" 'ly do: config +'
want  "15 domain"              'domain: l\.test +5'

# ── Muc 16: than co du lieu ma thieu Content-Type ──────────────────────────
# Dap an tinh TAY tu ba dong r40/r41/r42:
#   n   = smp 1 + 2 + 1            = 4
#   tot = 100*1 + 200*2 + 1000*1   = 1.500 B
#   mx  = 1.000 B  ;  tb = 1500/4  = 375 B
#   domain: m.test 3, n.test 1     ;  IP rieng biet = 2
#
# `smp` PHAI duoc nhan vao ca `n` VA `tot`: mot dong mau dai dien nhieu request, va
# neu chi nhan vao `n` thi Content-Length trung binh bi chia sai.
want  "16 tong luot"          '9 luot, 3 domain, 3 IP'
want  "16 cl_positive byte"   'cl_positive: Content-Length lon nhat 1000 B, trung binh 375 B'
# `m.test` = `cl=100` (smp 1) + `cl=200` (smp 2) + `te_chunked` (smp 1) = 4.
want  "16 domain m.test"      'm\.test +4'
want  "16 domain n.test"      'n\.test +1'
want  "16 domain p.test"      'p\.test +4'
# BON NHOM phai hien RIENG. Dap an tinh bang tay tu `smp` cua tung dong.
want  "16 nhom cl_positive"   'cl_positive +4'
want  "16 nhom te_chunked"    'te_chunked +1'
want  "16 nhom cl_absent"     'cl_absent +3'
want  "16 nhom cl_zero"       'cl_zero +1'
want  "16 nhom+domain"        'cl_absent +@ p\.test +3'
# CACH DOC phai doi khi co nhom khong mang do dai: gioi han byte bang header
# KHONG con du.
want  "16 cach doc chunked"   'header KHONG noi do dai'

# ── Muc 17: dap an tinh BANG TAY tu fixture ─────────────────────────
#   uploads/sucuri/  3 tep, 4+3+2 = 9 lan  -> thu muc dung dau
#   uploads/         2 tep, 1+1   = 2 lan
#   tong 5 duong dan, 3 dat nguong (>=2)
want  "17 tong duong dan"     '5 duong dan dang theo doi, 3 da dat nguong'
want  "17 thu muc sucuri"     '9 lan / +3 tep .*uploads/sucuri'
want  "17 thu muc uploads"    '2 lan / +2 tep .*uploads$'
# `hot` khong co tep bo dem -> PHAI in dong "chua co", khong duoc im lang: mot muc do
# im lang thi nguoi doc khong phan biet duoc "khong co du lieu" voi "muc bi hong".
want  "17 hot chua co bo dem" '\[hot\] chua co bo dem'
want  "17 co CACH DOC"        'mot thu muc chiem da so'

# ── Muc 21: static MISS theo DOMAIN ─────────────────────────────────
#
# Phep do ban dau duoc de nghi la `grep -o 'ractual=[^ ]*' | uniq -c`, chi tra
# hai dong TONG. Nguoi dung bat dung: no khong biet domain nao, nen khong tra
# loi duoc chinh cau hoi can tra loi. Cac want() duoi doi chieu voi dap an tinh
# BANG TAY o khoi log gia (xem chu thich tai do), khong lay tu output.
#
# `ip-miss` la cot QUYET DINH chu khong phai `miss`: cung 3 luot miss, 3 IP
# khac nhau la khach that 404 anh hang loat (FP capacity), con 1 IP la bot quet.
want  "21 mig 3 miss / 3 ip"  'mig\.test +3 +0 +0 +3 +0'
want  "21 bot 2 miss / 1 ip"  'bot\.test +2 +0 +0 +1 +1'
want  "21 ok.test chi hit"    'ok\.test +0 +1 +0 +0 +0'
want  "21 nd.test khong do"   'nd\.test +0 +0 +1 +0 +0'
# Dong `navigation` khong co cot ractual= PHAI bi bo qua hoan toan.
if printf '%s\n' "$OUT" | sed -n '/=== 21\./,/CACH DOC (cot ip-miss/p' | grep -q 'h\.test'; then
    fail=$((fail+1)); printf 'HONG  %s\n' "21 dong khong co ractual= bi dem (h.test lot vao bang)"
else
    pass=$((pass+1))
fi
want  "21 co CACH DOC"        'cot ip-miss quyet dinh'

printf '\npostdeploy_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
