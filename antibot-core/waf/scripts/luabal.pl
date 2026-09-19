#!/usr/bin/perl
# luabal.pl — kiem can bang khoi Lua ma KHONG can luajit.
#
# VI SAO TON TAI. May dev khong co luajit/lua/node/python, nen cong cu phap duy
# nhat la `deploy.sh` buoc [3] tren may that. Truoc khi day code len do, can mot
# phep kiem chay duoc tai cho.
#
# VI SAO KHONG DUNG grep/awk DEM TU KHOA. Da thu ba lan trong phien 19-09-2026
# va ca ba lan cho ket qua SAI:
#   - `if ... then ... end` mot dong: dem +1 -1 dung, nhung
#   - `elseif` KHONG mo khoi moi ma chua chu `if` => dem thua
#   - `for x in y do` co CA `for` lan `do` => dem thua mot
#   - chu "end"/"if"/"do" nam trong CHUOI hoac COMMENT => dem lung tung
# Ket qua: cung mot file cho ra +2 roi -2 tuy cach xu ly `elseif`. Mot bo kiem
# lac nhu vay te hon khong co bo kiem, vi no tao niem tin sai.
#
# Bo nay tach chuoi va comment TRUOC khi tokenize, va xu ly `do` theo ngu canh
# (`do` sau `for`/`while` thuoc chinh cau do, khong mo khoi moi).
#
# CHI kiem CAN BANG KHOI. Khong phai parser: khong bat duoc sai kieu, sai ten
# bien, hay logic sai. `deploy.sh` buoc [3] van la cong cu phap that.
#
#   perl antibot-core/waf/scripts/luabal.pl <file.lua>
#   for f in $(find antibot-core -name '*.lua'); do perl .../luabal.pl "$f"; done

my $p = shift or die "usage: luabal.pl <file.lua>\n";
open my $h, "<", $p or die "$p: $!";
local $/; my $src = <$h>; close $h;

my $out = ""; my $i = 0; my $n = length($src);
my $DQ = chr(34); my $SQ = chr(39);

while ($i < $n) {
    my $rest = substr($src, $i);

    # comment dai:  --[[ ... ]]  /  --[=[ ... ]=]  (moi muc dau `=`)
    if ($rest =~ /^--\[(=*)\[/) {
        my $close = "]" . $1 . "]";
        my $j = index($src, $close, $i);
        $i = $j < 0 ? $n : $j + length($close);
        $out .= " "; next;
    }
    # comment dong
    if (substr($src, $i, 2) eq "--") {
        my $j = index($src, "\n", $i);
        $i = $j < 0 ? $n : $j; next;
    }
    # chuoi dai:  [[ ... ]]  /  [=[ ... ]=]
    # admin/init.lua va enforcement/challenge/init.lua nhung CA TRANG HTML+JS
    # vao day, va trong do day chu `end`/`if`/`function`. Khong tach ra thi bo
    # kiem bao LECH 45 tren mot file hoan toan dung.
    if ($rest =~ /^\[(=*)\[/) {
        my $close = "]" . $1 . "]";
        my $j = index($src, $close, $i);
        $i = $j < 0 ? $n : $j + length($close);
        $out .= " "; next;
    }
    # chuoi thuong
    my $c = substr($src, $i, 1);
    if ($c eq $DQ or $c eq $SQ) {
        my $q = $c; $i++;
        while ($i < $n and substr($src, $i, 1) ne $q) {
            $i += 1 if substr($src, $i, 1) eq "\\";
            $i++;
        }
        $i++; $out .= " "; next;
    }
    $out .= $c; $i++;
}

my @toks = $out =~ /\b(function|if|elseif|for|while|do|end|repeat|until)\b/g;
my $depth = 0; my @stack;
for my $t (@toks) {
    if    ($t eq "function")             { $depth++; push @stack, "function" }
    elsif ($t eq "if")                   { $depth++; push @stack, "if" }
    elsif ($t eq "elseif")               { }   # khong mo khoi moi
    elsif ($t eq "for" or $t eq "while") { $depth++; push @stack, $t }
    elsif ($t eq "do") {
        # `do` sau for/while thuoc chinh cau do, khong mo khoi moi
        if (@stack and ($stack[-1] eq "for" or $stack[-1] eq "while")) { }
        else { $depth++; push @stack, "do" }
    }
    elsif ($t eq "repeat")               { $depth++; push @stack, "repeat" }
    # `repeat ... until` dong bang `until`, KHONG bang `end`. Thieu nhanh nay thi
    # `async/memory_guard.lua` — mot file hoan toan dung — bao LECH depth=1.
    elsif ($t eq "until")                { $depth--; pop @stack }
    elsif ($t eq "end")                  { $depth--; pop @stack }
}

printf "%-52s depth=%-3d %s\n", $p, $depth, ($depth == 0 ? "CAN BANG" : "LECH");
printf "  stack con lai: %s\n", join(",", @stack) if $depth != 0 and @stack;
exit($depth == 0 ? 0 : 1);
