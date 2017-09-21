#!/bin/bash

# Script to find out private IPs and other stuff from BIGIP F5 LB
# Detection based on the URLs mentioned and on private experiences over the years.
# The only known project which detects all flavors of F5 cookies. If something
# is missing, pls send me a mail or file an issue at github.
#
# License: copyleft GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
# Author:  Dirk Wetter (echo "qvex@grfgffy.fu" | tr a-zA-Z n-za-mN-ZA-M)
# Updates via github: https://github.com/drwetter/F5-BIGIP-Decoder

SIDEBYSIDE=${SIDEBYSIDE:-true}
DEBUG=${DEBUG:-false}
TEST=${TEST:-false}
[ "$1" == "TEST" ] && TEST=true

PS4='|${LINENO}> \011${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

bold="$(tput bold)"
underline="$(tput sgr 0 1)"
off="$(tput sgr0)"


### parse cmdline

if "$TEST"; then
	# this is just for internal testing....
     HEADER=$(cat <<EOF
Set-Cookie: BIGipServer_foo=2263487148.3013.0000; path=/foo
Set-Cookie: BIGipServer_bar=185903296.21520.0000; path=/
Set-Cookie: dr_who=375537930.544.0000; path=/
Set-Cookie: BIGipServer~lv-us_pub=rd20o00000000000000000000ffff0ea40041o8080
Set-Cookie: BIGipServer_ipv4r=rd5o00000000000000000000ffffc0000201o80
Set-Cookie: BIGipServer_ipv6=vi20010112000000000000000000000011.20480
Set-Cookie: drwho_bar6=rd3o20010221000000000000000000000022o80
Set-Cookie: foobar_LB=!VPyexJn/769hVyb9FVTnmPYOSADbxpddXoz+VcGjdpv7+MdiHxdFdc7OgVGeKLfKY/RlKPU7JJYcHwA=; path=/; Httponly; Secure
EOF
)
elif [ -z "$1" ]; then
	echo "I need input ..."
	exit 1
elif grep -q '=' <<< "$1"; then
	# just one cookie supplied as key=value, so we mimick the header:
	HEADER=$(cat <<EOF
Set-Cookie: "$1"
EOF
)
elif grep -Ewq '^http|^https|com$|org$|net$|sh$|de$' <<< "$1"; then
	# URL supplied
	HEADER="$(wget -q --no-check-certificate --max-redirect=0 --tries=1 --timeout=15 -S -O /dev/null 2>&1 $1)"
	if [ $? -ne 0 ] ; then
		http_code=$(echo "$HEADER" | head -1 | awk '{ print $2 }')
		case $http_code in
			301|302|307)
				;;
			*)   echo -e "\ntimed out other error (~40x) connecting to \"$1\", full header:\n"
				echo "$HEADER"
				exit 1
				;;
		esac
	fi
elif grep -q '[0-9.ordvia-f]' <<< "$1"; then
	# probably just the cookie, except the encrypted one, we mimick the header:
	HEADER=$(cat <<EOF
Set-Cookie: BIGipServer=$1
EOF
)
else
	echo "don't understand the command line arg1 \"$1\"" 1>&2
	exit 2
fi

# put all cookies into $allcookies
allcookies="$(awk '/Set-Cookie:/ { print $2 }' <<< "$HEADER")"
"$DEBUG" && echo "$allcookies"


# arg1: IP:port,   arg2: what kind of cookie,   arg3: cookiename or whole line
output() {
	if "$SIDEBYSIDE"; then
          	printf "%-48s %-38s %-0s%-0s\n" "   $1" "| $2" "| ${3}=" "$4"
	else
          	printf "%-48s %-38s %-0s\n"     "   $1" "| $2" "| \"$3\""
	fi
}


# first some conversion functions, see
# 	description: https://github.com/dnkolegov/bigipsecurity
#	meta code: https://support.f5.com/csp/article/K6917
#    code: https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/f5_bigip_cookie_disclosure.rb
#    code: http://penturalabs.wordpress.com/2011/03/29/how-to-decode-big-ip-f5-persistence-cookie-values/

hex2ip() {
	"$DEBUG" && echo "$1"
	echo $((16#${1:0:2})).$((16#${1:2:2})).$((16#${1:4:2})).$((16#${1:6:2}))
}
hex2ip6() {
	"$DEBUG" && echo "$1"
	echo "[${1:0:4}:${1:4:4}:${1:8:4}:${1:12:4}.${1:16:4}:${1:20:4}:${1:24:4}:${1:28:4}]"
}

determine_routeddomain() {
	local tmp

	"$DEBUG" && echo "len is ${#1}"
	tmp="${1%%o*}"
	"$DEBUG" && echo "${tmp/rd/}" 1>&2
	echo "${tmp/rd/}"
}

ip_oldstyle() {
	local tmp
	local a b c d

	tmp="${1/%.*}"					# until first dot
	tmp="$(printf "%x8" "$tmp")"		# convert the whole thing to hex, now back to ip (reversed notation:
	tmp="$(hex2ip $tmp)"			# transform to ip with reversed notation
	IFS="." read -r a b c d <<< "$tmp" # reverse it
	echo $d.$c.$b.$a
}

port_decode() {
	local tmp

	tmp="${1/.0000/}"				# to be sure remove trailing zeros with a dot
	tmp="${tmp#*.}"				# get the port
	tmp="$(printf "%04x" "${tmp}")"	# to hex
	if [ ${#tmp} -eq 4 ] ; then
		:
	elif [ ${#tmp} -eq 3 ]; then		# fill it up with leading zeros if needed
		tmp=0{$tmp}
	elif [ ${#tmp} -eq 2 ]; then
		tmp=00{$tmp}
	fi
	echo $((16#${tmp:2:2}${tmp:0:2}))  # reverse order and convert it from hex to dec
}

### now get NON-encrypted cookies
#
# general info: https://www.owasp.org/index.php/SCG_D_BIGIP#Description
# fix:          https://support.f5.com/csp/article/K7784?sr=14607726
#
# naming of cookies according to https://github.com/dnkolegov/bigipsecurity
#    1. IPv4 pool members - "BIGipServerWEB=2263487148.3013.0000",
#    2. IPv4 pool members in non-default routed domains - "BIGipServerWEB=rd5o00000000000000000000ffffc0000201o80",
#    3. IPv6 pool members - "BIGipServerWEB=vi20010112000000000000000000000030.20480",
#    4. IPv6 pool members in non-default route domains - "BIGipServerWEB=rd3o20010112000000000000000000000030o80"
#
# here: non-default routed domains --> routed domains

echo
echo "${underline}Standard / non-encrypted cookies${off}"
echo

i=0
savedcookies=""
while true; do IFS='=' read cookiename cookie
     [[ -z "$cookie" ]] && break
     cookie=${cookie/;/}
     "$DEBUG" && echo $cookiename : $cookie
     grep -q -E '[0-9]{9,10}\.[0-9]{3,5}\.0000' <<< "$cookie" && \
		ip="$(ip_oldstyle "$cookie")" && \
		port="$(port_decode $cookie)" &&  \
		output "${ip}:${port}" "default IPv4 pool members" "$cookiename" "$cookie" && \
		savedcookies="${savedcookies}    ${cookiename}=${cookie}\n" && \
          i=$((i +1)) && \
          continue
     grep -q -E '^rd[0-9]{1,2}o0{20}f{4}[a-f0-9]{8}o[0-9]{1,5}' <<< "$cookie" && \
		routed_domain="$(determine_routeddomain "$cookie")" && \
		offset=$(( 2 + ${#routed_domain} + 1 + 24))  && \
		port="${cookie##*o}" && \
		ip="$(hex2ip "${cookie:$offset:8}")" && \
          output "${ip}:${port}" "IPv4 pool members in routed domain $routed_domain" "$cookiename" "$cookie" && \
		savedcookies="${savedcookies}    ${cookiename}=${cookie}\n" && \
          i=$((i +1)) && \
          continue
     grep -q -E '^vi[a-f0-9]{32}\.[0-9]{1,5}' <<< "$cookie" && \
		ip="$(hex2ip6 ${cookie:2:32})" && \
		port="${cookie##*.}" && \
		port=$(port_decode "$port") && \
		output "${ip}:${port}" "IPv6 pool members" "$cookiename" "$cookie" && \
		savedcookies="${savedcookies}    ${cookiename}=${cookie}\n" && \
          i=$((i +1)) && \
          continue
     grep -q -E '^rd[0-9]{1,2}o[a-f0-9]{32}o[0-9]{1,5}' <<< "$cookie" && \
		routed_domain="$(determine_routeddomain "$cookie")" && \
		offset=$(( 2 + ${#routed_domain} + 1 ))  && \
		port="${cookie##*o}" && \
		ip="$(hex2ip6 ${cookie:$offset:32})" && \
          output "${ip}:${port}" "IPv6 pool members in routed domain $routed_domain" "$cookiename" "$cookie" && \
		savedcookies="${savedcookies}    ${cookiename}=${cookie}\n" && \
          i=$((i +1)) && \
          continue
done <<< "$allcookies"

if [ $i -ne 0 ]; then
	echo
	if $SIDEBYSIDE; then
		echo "A total of ${i}x non-encrypted cookies found"
		echo
	else
		echo "${i}x non-encrypted cookies found:"
		echo -e "$savedcookies"
	fi
else
	echo "No non-encrypted cookies w IP found"
fi
echo


### now the ENCRYPTED cookies

echo "${underline}AES encrypted Cookies${off}"
echo

# AES encrypted f5 cookie, scheme:   'Set-Cookie: <cookiename>=!<base64str>='
enc_f5lines="$(grep 'Set-Cookie: .*=\!' <<< "$HEADER")"
enc_f5lines="$(awk '/Set-Cookie:/ { print $2 }' <<< "$enc_f5lines")"

j=0
savedcookies=""
while true; do IFS='=' read cookiename cookie
     [[ -z "$cookie" ]] && break
	cookie=${cookie/;/}
	"$DEBUG" && echo $cookiename : $cookie
	output "<IP address and port cannot be determined>" "<pool info cannot be determined>" "$cookiename" "$cookie"
	savedcookies="${savedcookies}     ${cookiename}=${cookie:1:79}"
     [[ "${#cookie}" -eq 81 ]] && j=$((j +1))
done <<< "$enc_f5lines"

if [ $j -ne 0 ]; then
	echo
	if $SIDEBYSIDE; then
		echo "A total of ${j}x AES encrypted cookies found"
	else
		echo "${j}x AES encrypted cookies found:"
		echo "$savedcookies"
	fi
else
	echo "No AES encrypted cookies found"
fi
echo


### bottom line output
nr_cookies=$(grep -ci 'Set-Cookie' <<< "$HEADER")
named_bigip=$(grep -ci 'BIGipServer' <<< "$allcookies")
if [ -n $named_bigip ] ; then
	echo
	echo "In total:"
	echo "$nr_cookies cookies -- $((i+j)) F5 BIG IP cookie(s) of which $named_bigip cookie(s) named \"BIGipServer\""
	echo
fi

#  $Id: f5_bigip_decoder.sh,v 1.19 2017/09/21 08:10:03 dirkw Exp $
#  vim:ts=5:sw=5
