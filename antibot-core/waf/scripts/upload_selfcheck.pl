#!/usr/bin/perl
# upload_selfcheck.pl — bat XUNG DOT giua cac muc trong `upload_test.lua`.
#
# DUNG: perl antibot-core/waf/scripts/upload_selfcheck.pl \
#           antibot-core/waf/scripts/upload_test.lua
# MA THOAT: 0 = khop het   1 = co xung dot
#
# ── VI SAO TON TAI ──────────────────────────────────────────────────
#
# 19-09-2026 mot ban bi cong [3b] chan voi:
#     SAI  .HTACCESS  cho=upload_apache_config  duoc=upload_config_case
# Toi them nhan `upload_config_case` o muc [8] nhung DE NGUYEN assertion cu o
# muc [5] — hai muc trong CUNG MOT FILE khang dinh hai gia tri khac nhau cho
# cung mot dau vao. Khong phai loi logic; loi QUET SOT.
#
# May dev khong co Lua, nen `upload_test.lua` chi chay duoc tren may that. File
# nay chay TAI CHO va bat dung lop loi do, theo hai cach:
#   1. Moi `eq(...)` phai khop ban mo phong cua `check_filename`.
#   2. Hai dong khang dinh KHAC NHAU tren cung dau vao -> bao ngay.
#
# ── GIOI HAN PHAI BIET, va no NANG ──────────────────────────────────
#
# Day la BAN MO PHONG bang perl cua logic Lua, khong phai chinh logic do. Neu
# `upload.lua` doi ma file nay khong doi, no se bao XANH tren code SAI — dung
# kieu that bai da got ba lop kiem cua `luacheck` hom qua.
#
# Nen quy tac dung no: **doi `upload.lua` thi phai doi ca file nay**, va
# `upload_test.lua` chay bang `resty` o cong [3b] VAN la thuoc do that. File nay
# chi cat ngan vong lap "day len roi phat hien", khong thay the cong do.
#
# Neu hai ban lech nhau thi file nay vo dung — do la ly do no nam CANH
# `upload_test.lua` chu khong o cho khac, va ly do co doan nay.
my %PHP  = map {$_=>1} qw(php php5 phtml inc);
my %LEG  = map {$_=>1} qw(php3 php4 php6 php7 php8 pht phtm phps phar);
my %APC  = ('.htaccess'=>1);
my %PHPC = ('.user.ini'=>1,'php.ini'=>1);
my %FRN  = ('web.config'=>1,'.htpasswd'=>1);

sub basename { my $s=shift; my $last=0;
  for my $i (1..length $s){ my $c=substr($s,$i-1,1); $last=$i if $c eq '/' or $c eq "\\" }
  return substr($s,$last) }
sub strip_tail { my $o=shift;
  my $a=index($o,'::'); $o=substr($o,0,$a) if $a>=0;
  my $n=index($o,"\0");  $o=substr($o,0,$n) if $n>=0;
  while(length $o){ my $c=substr($o,-1);
    if($c eq '.' or $c eq ' ' or $c eq "\t" or $c eq "\r" or $c eq "\n"){$o=substr($o,0,-1)} else {last} }
  return $o }
sub extensions { my $name=shift; my @e; my $last=length($name)+1;
  for (my $i=length($name); $i>=1; $i--) {
    if (substr($name,$i-1,1) eq '.') {
      my $e = lc substr($name, $i, $last-$i-1);
      push @e,$e if $e ne '';
      $last = $i } }
  return @e }
sub classify { my $name=shift; my $l=lc $name;
  return 'upload_config_case' if $name ne $l and ($APC{$l} or $PHPC{$l} or $FRN{$l});
  return 'upload_apache_config'  if $APC{$l};
  return 'upload_php_config'     if $PHPC{$l};
  return 'upload_foreign_config' if $FRN{$l};
  my @e = extensions($name); return undef if !@e;
  return 'upload_php_ext' if $PHP{$e[0]};
  for my $i (1..$#e){ return 'upload_php_double' if $PHP{$e[$i]} }
  for my $i (0..$#e){ return 'upload_php_legacy_ext' if $LEG{$e[$i]} }
  return undef }
sub check { my $raw=shift; return undef if !defined $raw or $raw eq '';
  for my $c (strip_tail(basename(strip_tail($raw))), strip_tail(basename($raw)), strip_tail($raw)) {
    next if !defined $c or $c eq '';
    my $r = classify($c); return $r if $r }
  return undef }

# Doc cac dong `eq("...", "...")` / `eq("...", nil)` tu file test.
open(my $h,'<',$ARGV[0]) or die "open: $!";
my ($ln,$bad,$ok,%seen) = (0,0,0);
while (my $line = <$h>) {
  $ln++;
  next unless $line =~ /^eq\("((?:[^"\\]|\\.)*)",\s*(?:"([a-z_]+)"|nil)/;
  my ($in,$want) = ($1,$2);
  # giai escape Lua toi thieu ma test dung
  my $real = $in;
  $real =~ s/\\0/\0/g; $real =~ s/\\t/\t/g; $real =~ s/\\\\/\\/g;
  my $got = check($real);
  my ($g,$w) = (defined $got ? $got : 'nil', defined $want ? $want : 'nil');
  if ($g ne $w) {
    $bad++;
    printf "  XUNG DOT dong %-4d %-28s test cho=%-22s logic cho=%s\n",
           $ln, "\"$in\"", $w, $g;
  } else { $ok++ }
  # bat hai muc khang dinh KHAC NHAU tren cung dau vao
  if (exists $seen{$real} and $seen{$real} ne $w) {
    printf "  HAI MUC NGUOC NHAU: %-24s dong truoc cho=%s, dong %d cho=%s\n",
           "\"$in\"", $seen{$real}, $ln, $w;
    $bad++;
  }
  $seen{$real} = $w;
}
close $h;
printf "\nverify: %d khop, %d xung dot\n", $ok, $bad;
exit($bad ? 1 : 0);
