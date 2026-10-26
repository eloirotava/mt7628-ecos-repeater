#!/bin/sh
# Gera include/autoconf.h a partir do .config sem o Menuconfig interativo
# (o modo "save" dele tem um teste quebrado e cai no menu).
# Variaveis "hex" do config.in ficam sem 0x no .config; o prefixo e posto aqui.
cd "$(dirname "$0")/.."
HEX=$(find . -name '*.in' -exec grep -hoE "^[[:space:]]*hex[[:space:]]+'[^']*'[[:space:]]+CONFIG_[A-Za-z0-9_]+" {} + | awk '{print $NF}' | sort -u | tr '\n' ' ')
awk -v hex="$HEX" '
BEGIN {
	n = split(hex, h, " "); for (i = 1; i <= n; i++) ishex[h[i]] = 1
	print "/* Automatically generated from .config by scripts/mkautoconf.sh */"
	print "#define AUTOCONF_INCLUDED"
}
/^# CONFIG_[A-Za-z0-9_]+ is not set$/ { print "#undef " $2; next }
/^CONFIG_[A-Za-z0-9_]+=/ {
	k = substr($0, 1, index($0, "=") - 1); v = substr($0, index($0, "=") + 1)
	if (v == "y")                    print "#define " k " 1"
	else if (v == "m")               print "#define " k "_MODULE 1"
	else if (v ~ /^"/)               print "#define " k " " v
	else if (v ~ /^0[xX]/)           print "#define " k " " v
	else if (k in ishex)             print "#define " k " 0x" v
	else                             print "#define " k " (" v ")"
}' .config > include/autoconf.h
