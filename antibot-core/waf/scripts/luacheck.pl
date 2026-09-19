#!/usr/bin/perl
# luacheck.pl — kiem tinh cho Lua ma KHONG can luajit.
#
# VI SAO TON TAI. May dev khong co luajit/lua/node/python, nen cong cu phap duy
# nhat la `deploy.sh` buoc [2] (`luajit -b`) tren may that. Ngay 19-09-2026 mot
# ban va bi cong [3b] chan vi BON duong dan `slurp()` sai — loi ma toi da "thu
# bang perl tu goc repo" va thay dung, vi perl chay voi cwd khac han runtime
# that. Truoc khi day code len, can mot phep kiem chay duoc TAI CHO.
#
# BA LOP KIEM, xep theo do tin cay:
#
#   [1] CAN BANG KHOI  — do tin cay CAO. Dem khoi mo/dong sau khi da tach chuoi
#       va comment. Mot `end` thieu la loi khach quan.
#
#   [2] GOI HAM CUA MODULE DA REQUIRE — do tin cay TRUNG BINH. Neu file lam
#       `local m = require "antibot.x.y"` roi goi `m.foo()`, thi `x/y.lua` phai
#       co `function _M.foo` hoac `_M.foo =`. Bat duoc loi goi ten sai.
#       BO QUA khi module tra ve bang dung `setmetatable` hay gan dong.
#
#   [3] ESCAPE SEQUENCE TRONG CHUOI — do tin cay CAO. Them 19-09 sau khi cong
#       [2] cua deploy.sh chan mot ban voi `upload_test.lua:82: invalid escape
#       sequence`. Xem chu thich tai ham `check_escapes`.
#
#       CHI kiem chuoi nhay don/nhay doi. Long-bracket `[[...]]` KHONG xu ly
#       escape, nen `[[\.(?:sql)$]]` la HOP LE va la dung y (PCRE can `\.`).
#       Ban dau gop hai loai vao mot mang => bao sai 3 lan tren `exposed.lua` va
#       `wp_paths.lua`, tuc code DANG CHAY production. Da tach.
#
# HAI LOP DA GO, ghi lai de khong ai dung lai:
#   — "duong dan trong chuoi phai ton tai": BAO XANH cho dung loi no sinh ra de
#     bat (chay tu goc repo thi duong dan tuong doi TON TAI). Bat bien do nay
#     duoc gac o `contract_test` [26], pham vi hep hon nhung khong bao sai.
#   — "ngx API ngoai danh sach": danh sach khong bao gio day du nen chi sinh
#     nhieu WARN, va mot canh bao luon sang la mot canh bao day nguoi ta bo qua.
#
# GIOI HAN PHAI BIET: day KHONG phai parser. Khong bat duoc sai kieu, bien nil
# luc chay, logic sai, hay cosocket goi trong log phase. `deploy.sh` buoc [2] va
# [3b] van la cong that. File nay chi cat ngan vong lap "day len roi phat hien".
#
# DUNG:
#   perl antibot-core/waf/scripts/luacheck.pl <file.lua> [<file.lua> ...]
#   perl antibot-core/waf/scripts/luacheck.pl --all antibot-core
#
# MA THOAT: 0 = khong loi   1 = co loi   2 = khong chay duoc

use strict;
use warnings;

my @argv = @ARGV;
my $ALL  = 0;
my $ROOT = "";
if (@argv and $argv[0] eq "--all") {
    $ALL  = 1;
    shift @argv;
    $ROOT = shift(@argv) || "antibot-core";
}

my @files;
if ($ALL) {
    if (!-d $ROOT) { print "khong thay thu muc $ROOT\n"; exit 2 }
    my @stack = ($ROOT);
    while (@stack) {
        my $d = pop @stack;
        opendir(my $dh, $d) or next;
        for my $e (readdir $dh) {
            next if $e eq "." or $e eq "..";
            my $p = "$d/$e";
            if    (-d $p)            { push @stack, $p }
            elsif ($e =~ /\.lua$/)   { push @files, $p }
        }
        closedir $dh;
    }
    @files = sort @files;
} else {
    @files = @argv;
}

if (!@files) { print "khong co file nao de kiem\n"; exit 2 }

# Goc cay nguon, de giai duong dan trong chuoi. Suy ra tu duong dan file dau
# tien: .../antibot-core/... => goc la .../antibot-core/
my $SRCROOT = "";
if ($files[0] =~ m{^(.*antibot-core)/}) { $SRCROOT = "$1/" }
elsif ($ROOT ne "")                     { $SRCROOT = "$ROOT/" }

# ── Tach chuoi va comment ────────────────────────────────────────────────
# Tra ve (code_da_lam_sach, [danh sach chuoi]). Phai tach TRUOC khi tokenize:
# `admin/init.lua` va `enforcement/challenge/init.lua` nhung ca trang HTML+JS
# vao long-string, va trong do day chu `end`/`if`/`function`.
sub strip {
    my $src = shift;
    my $out = "";
    my @strs;
    my @longs;
    my $i = 0;
    my $n = length($src);
    my $DQ = chr(34);
    my $SQ = chr(39);
    while ($i < $n) {
        my $rest = substr($src, $i);
        # comment dai --[[ ]] / --[=[ ]=]
        if ($rest =~ /^--\[(=*)\[/) {
            my $close = "]" . $1 . "]";
            my $j = index($src, $close, $i);
            $i = $j < 0 ? $n : $j + length($close);
            $out .= " "; next;
        }
        # comment dong
        if (substr($src, $i, 2) eq "--") {
            my $j = index($src, "\n", $i);
            $i = $j < 0 ? $n : $j;
            next;
        }
        # long-string [[ ]] / [=[ ]=]
        if ($rest =~ /^\[(=*)\[/) {
            my $close = "]" . $1 . "]";
            my $j = index($src, $close, $i);
            my $body = $j < 0 ? substr($src, $i) : substr($src, $i, $j - $i);
            # KHONG day vao @strs. Long-bracket string KHONG xu ly escape —
            # trong `[[.(?:sql)$]]` thi `.` la HAI ky tu literal va la dung y
            # (PCRE can `.`). Gop chung vao mot mang lam lop [3] bao sai 3 lan
            # tren `exposed.lua`/`wp_paths.lua` — code DANG CHAY production. Do
            # dung la ho loi da got ba lop kiem hom qua: mot lop bao sai se bi
            # tat di, va luc do con te hon khong co.
            push @longs, $body;
            $i = $j < 0 ? $n : $j + length($close);
            $out .= " "; next;
        }
        my $c = substr($src, $i, 1);
        if ($c eq $DQ or $c eq $SQ) {
            my $q = $c;
            my $buf = "";
            $i++;
            while ($i < $n and substr($src, $i, 1) ne $q) {
                if (substr($src, $i, 1) eq "\\") { $buf .= substr($src, $i, 2); $i += 2; next }
                $buf .= substr($src, $i, 1);
                $i++;
            }
            $i++;
            push @strs, $buf;
            $out .= " "; next;
        }
        $out .= $c;
        $i++;
    }
    return ($out, \@strs, \@longs);
}

# ── [1] Can bang khoi ────────────────────────────────────────────────────
sub check_blocks {
    my ($code, $file) = @_;
    my @toks = $code =~ /\b(function|if|elseif|for|while|do|end|repeat|until)\b/g;
    my $depth = 0;
    my @stack;
    for my $t (@toks) {
        if    ($t eq "function")             { $depth++; push @stack, "function" }
        elsif ($t eq "if")                   { $depth++; push @stack, "if" }
        elsif ($t eq "elseif")               { }
        elsif ($t eq "for" or $t eq "while") { $depth++; push @stack, $t }
        elsif ($t eq "do") {
            # `do` sau for/while thuoc chinh cau do, khong mo khoi moi
            if (@stack and ($stack[-1] eq "for" or $stack[-1] eq "while")) { }
            else { $depth++; push @stack, "do" }
        }
        elsif ($t eq "repeat")               { $depth++; push @stack, "repeat" }
        # `repeat ... until` dong bang `until`, KHONG bang `end`
        elsif ($t eq "until")                { $depth--; pop @stack }
        elsif ($t eq "end")                  { $depth--; pop @stack }
    }
    return () if $depth == 0;
    return (sprintf("khoi KHONG can bang: depth=%d (con treo: %s)",
                    $depth, (@stack ? join(",", @stack) : "?")));
}

# ── [2] Goi ham cua module da require ────────────────────────────────────
sub exports_of {
    my $path = shift;
    return undef unless -r $path;
    open(my $fh, "<", $path) or return undef;
    local $/;
    my $s = <$fh>;
    close $fh;
    # Module dung setmetatable / gan dong thi khong doan duoc — bo qua.
    return undef if $s =~ /setmetatable\s*\(\s*_M/;
    my %ex;
    while ($s =~ /function\s+_M[.:]([\w_]+)/g)   { $ex{$1} = 1 }
    while ($s =~ /_M\.([\w_]+)\s*=/g)            { $ex{$1} = 1 }
    while ($s =~ /\b_M\s*=\s*\{([^}]*)\}/g) {
        my $b = $1;
        while ($b =~ /([\w_]+)\s*=/g) { $ex{$1} = 1 }
    }
    return \%ex;
}

sub check_calls {
    my ($code, $file) = @_;
    my @errs;
    my %mod;
    while ($code =~ /local\s+([\w_]+)\s*=\s*require\s*$/gm) { }
    # `require` voi chuoi da bi tach => phai doc lai tu nguon goc
    return @errs;
}


# ── [3] Escape sequence trong chuoi ──────────────────────────────────
#
# VI SAO LOP NAY TON TAI, va vi sao no la lop THU BA chu khong phai thu nhat:
# ngay 19-09-2026 mot ban P1 bi cong [2] cua deploy.sh chan voi
#
#     upload_test.lua:82: invalid escape sequence near '"..'
#
# Nguyen nhan KHONG phai loi Lua — la loi ONG DAN: toi viet `"..\..\x"` trong
# mot heredoc bash, bash an mot lop `\`, nen file nhan `"..\..\x"` va `\.` khong
# phai escape hop le trong Lua. `luabal.pl` dem khoi nen mu hoan toan voi chuyen
# nay; `check_blocks` cung mu vi `strip()` da bo chuoi di TRUOC khi tokenize.
#
# Do la vung mu co cau truc: hai lop kiem dau tien deu lam viec tren CODE da bo
# chuoi, nen khong lop nao nhin vao BEN TRONG chuoi. Lop nay kiem dung cho do.
#
# Lua cho: \a \b \f \n \r \t \v \ \" \' \ddd (0-255) \xHH \z \<newline>
# Bat ky \<ky tu khac> la loi cu phap.
my %ESC_OK = map { $_ => 1 } split //, 'abfnrtv\\"\'xz';

sub check_escapes {
    my ($strs, $file) = @_;
    my @errs;
    for my $s (@$strs) {
        my $i = 0;
        while (($i = index($s, "\\", $i)) >= 0) {
            my $c = substr($s, $i + 1, 1);
            if ($c eq "" or (!$ESC_OK{$c} and $c !~ /[0-9\n]/)) {
                push @errs, sprintf("escape khong hop le `\%s` trong chuoi",
                                    ($c eq "" ? "<het chuoi>" : $c));
            }
            $i += 2;
        }
    }
    return @errs;
}

# ── Chay ─────────────────────────────────────────────────────────────────
my $nerr = 0;
my $nfile = 0;
my $nwarn = 0;

for my $f (@files) {
    open(my $fh, "<", $f) or do { print "  LOI  khong doc duoc $f\n"; $nerr++; next };
    local $/;
    my $raw = <$fh>;
    close $fh;
    $nfile++;

    my ($code, $strs, $longs) = strip($raw);
    my @errs;
    my @warns;

    push @errs, check_blocks($code, $f);
    push @errs, check_escapes($strs, $f);

    # [2] goi ham module — doc tu nguon goc de lay ca ten module trong chuoi
    my %alias;
    while ($raw =~ /local\s+([\w_]+)\s*=\s*require\s*[("]+\s*["']?antibot\.([\w.]+)["']?\s*\)?/g) {
        my ($v, $m) = ($1, $2);
        $m =~ s/\./\//g;
        $alias{$v} = "$m.lua";
    }
    for my $v (sort keys %alias) {
        my $modpath = $SRCROOT . $alias{$v};
        # module la thu muc co init.lua
        $modpath = $SRCROOT . $alias{$v} =~ s/\.lua$/\/init.lua/r if !-r $modpath;
        my $ex = exports_of($modpath);
        next unless $ex;                 # khong doan duoc thi bo qua
        next unless %$ex;
        while ($code =~ /\b\Q$v\E\.([\w_]+)\s*\(/g) {
            my $fn = $1;
            next if $ex->{$fn};
            push @errs, "goi `$v.$fn()` nhung " . $alias{$v} . " khong xuat ten do";
        }
    }

    # ── [3] DA GO: "duong dan tuong doi khong neo vao goc cay" ───────────────
    #
    # Lop nay da duoc viet HAI LAN va SAI CA HAI LAN. Ghi lai day de khong ai
    # (ke ca toi) dung lai no ma khong doc muc nay truoc.
    #
    # Y dinh: bat loi 19-09 — bon `slurp("antibot-core/x/y.lua")` thay vi
    # `slurp(SRC .. "x/y.lua")`. Duong dan tuong doi phu thuoc cwd, ma `run.sh`
    # dat cwd khac `deploy.sh`, con toi thu tu goc repo — cung mot chuoi, ba
    # ket qua khac nhau.
    #
    # Ban 1 kiem "file co ton tai khong" => BAO XANH cho dung loi can bat, vi
    #   chay tu goc repo thi `antibot-core/x/y.lua` TON TAI.
    # Ban 2 kiem "chuoi co duoc ghep voi bieu thuc neo khong" => 18 FALSE
    #   POSITIVE: `contract_test.lua` giu duong dan trong BANG DU LIEU roi moi
    #   ghep `SRC .. $f` luc dung. Muon phan biet thi phai theo vet BIEN qua
    #   bang va vong lap — do la cong viec cua mot parser, khong phai regex.
    #
    # Mot lop kiem hay bao sai se bi tat di, va luc do no con te hon khong co.
    # Hai lop [1] va [2] con lai deu da thu pha va bat duoc that.
    #
    # Bat bien nay VAN DUNG va van dang gia, nen no duoc gac o CHO KHAC, bang
    # cach re hon: `contract_test.lua` muc [26] doi moi `slurp(` trong chinh
    # file test do phai co `SRC ..` ngay sau. Pham vi hep hon nhung khong bao
    # sai — va do dung la file duy nhat da mac loi nay.
    if (@errs) {
        printf "%s\n", $f;
        printf "  LOI  %s\n", $_ for @errs;
        $nerr += scalar @errs;
    }
    if (@warns) {
        printf "%s\n", $f unless @errs;
        printf "  WARN %s\n", $_ for @warns;
        $nwarn += scalar @warns;
    }
}

printf "\n%d file kiem, %d loi, %d canh bao\n", $nfile, $nerr, $nwarn;
exit($nerr == 0 ? 0 : 1);
