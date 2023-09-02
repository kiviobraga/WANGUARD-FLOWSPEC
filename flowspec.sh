#!/bin/bash
# kiviobraga@gmail.com

# PARAMETROS
if [ $# -lt 3 ]
 then
     echo
     echo " Usage: $0 <IP> <DECODER> <RATE> <ANOMALY_ID> <GROUP>"
     echo
     echo " <DECORDER> = decoder=UDP | decoder=ICMP | decoder=NTP | decoder=SNMP | decoder=SSDP | decoder=CLDAP | decoder=INVALID | decoder=FRAGMENT | decoder=OTHER"
     echo " <RATE> = 1000000"
     echo " <ANOMALY_ID> = id=43"
     echo " <GROUP> = group=WANGUARD"
     echo " <DIRECTION> = direction=incoming | direction=outgoing"
     echo
     echo " Exemplo_0: $0 <REDE>/24 decoder=UDP rate=1000000 direction=incoming"
     echo " Exemplo_1: $0 <IP>/32 decoder=ICMP rate=1000000 direction=incoming"
     echo " Exemplo_2: $0 <IP>/32 decoder=NTP rate=1000000 direction=incoming"
     echo " Exemplo_3: $0 <IP>/32 decoder=SNMP rate=2000000 direction=outgoing"
     echo " Exemplo_4: $0 <REDE>/24 decoder=FRAGMENT rate=1000000 direction=outgoing"
     echo " Exemplo_5: $0 <REDE>/24 decoder=OTHER rate=1000000 direction=outgoing"
  exit 2
fi

IP="$1"
DECODER=$(echo $2 | cut -d= -f2)
RATE=$(echo $3 | cut -d= -f2 | sed s/.$//)
MBPS=$(echo "$(( ${RATE} / 100000))M")
UNIT=$(echo $4 | cut -d= -f2)
ANOMALY_ID=$(echo $5 | cut -d= -f2)
GROUP=$(echo $6 | cut -d= -f2)
DIRECTION=$(echo $7 | cut -d= -f2)
TIMER_WITHDRAW="86400"
USER_API="wanguard_api"
SECRET_API="wanguard_api"


URL="-X POST http://127.0.0.1/wanguard-api/v1/bgp_announcements --user $USER_API:$SECRET_API"
CONNECTOR_ID="2"
LOG="/var/log/flowspec.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

if [ ! -f "$LOG" ]; then
touch $LOG
chown andrisoft:andrisoft $LOG
fi


# CHECK_UNIT
if [ "$UNIT" = "pkts/s" ]
then
echo "$DATE - FLOWSPEC_FAILED: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP] - nao e possivel criar regras pkts/s !" | stdbuf -oL tee -a $LOG
exit 0
fi

# CHECK_DIRECTION
if [ "$DIRECTION" = "incoming" ]
then
DIRECTION="destination_prefix"
elif [ "$DIRECTION" = "outgoing" ]
then
DIRECTION="source_prefix"
else
echo "$DATE - FLOWSPEC_FAILED: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP] | DIRECTION=[$DIRECTION] - falta de parametro!" | stdbuf -oL tee -a $LOG
exit 0
fi

# CHECK_PORT
if [ "$DECODER" = "DNS" ]
then
PORT="53"
elif [ "$DECODER" = "SNMP" ]
then
PORT="161"
elif [ "$DECODER" = "NTP" ]
then
PORT="123"
elif [ "$DECODER" = "SSDP" ]
then
PORT="1900"
elif [ "$DECODER" = "CLDAP" ]
then
PORT="389"
elif [ "$DECODER" = "CHARGEN" ]
then
PORT="19"
elif [ "$DECODER" = "MEMCACHED" ]
then
PORT="11211"
elif [ "$DECODER" = "INVALID" ]
then
PORT="0"
elif [ "$DECODER" = "OTHER" ]
then
PROTOCOL="\"IP-in-IP\",\"EGP\",\"GRE\",\"ESP\",\"EIGRP\",\"VRRP\""
fi


if [ "$DECODER" = "ICMP" ]; then

generate_icmp_ratelimit()
{
cat << EOF
{
     "flowspec announcement":	{
			"bgp_connector_id":"$CONNECTOR_ID",
			"ip_protocol(s)":["ICMP"],
			"${DIRECTION}":"$IP",
			"action":"Rate Limit",
			"rate_limit":"$RATE",
			"anomaly_id":"$ANOMALY_ID",
			"withdraw_after":"$TIMER_WITHDRAW",
			"comments":"${GROUP} | ${DECODER} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_icmp_ratelimit)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG

exit 0

elif [ "$DECODER" = "DNS" ] || [ "$DECODER" = "NTP" ] || [ "$DECODER" = "SNMP" ] || [ "$DECODER" = "CHARGEN" ] || [ "$DECODER" = "MEMCACHED" ] || [ "$DECODER" = "SSDP" ] || [ "$DECODER" = "CLDAP" ]; then

generate_ratelimit()
{
cat << EOF
{
     "flowspec announcement":	{
			"bgp_connector_id":"$CONNECTOR_ID",
			"ip_protocol(s)":["UDP"],
			"${DIRECTION}":"$IP",
			"port(s)":"$PORT",
			"action":"Rate Limit",
			"rate_limit":"$RATE",
			"anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
			"comments":"${GROUP} | ${DECODER} | PORT_${PORT} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

elif [ "$DECODER" = "TCP-NULL" ] || [ "$DECODER" = "TCP-ALL" ] || [ "$DECODER" = "TCP+SYN" ] || [ "$DECODER" = "TCP+ACK" ] || [ "$DECODER" = "TCP+SYNACK" ] || [ "$DECODER" = "TCP+RST" ]; then

generate_ratelimit_tcp_flags()
{
cat << EOF
{
     "flowspec announcement":	{
			"bgp_connector_id":"$CONNECTOR_ID",
			"ip_protocol(s)":["TCP"],
			"${DIRECTION}":"$IP",
                        "tcp_flag(s)":[$TCP_FLAGS],
			"action":"Rate Limit",
			"rate_limit":"$RATE",
			"anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
			"comments":"${GROUP} | ${DECODER} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_tcp_flaps)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

elif [ "$DECODER" = "INVALID" ]; then

generate_ratelimit_invalid()
{
cat << EOF
{
     "flowspec announcement":   {
                        "bgp_connector_id":"$CONNECTOR_ID",
                        "ip_protocol(s)":["UDP"],
                        "${DIRECTION}":"$IP",
                        "port(s)":"$PORT",
                        "action":"Rate Limit",
                        "rate_limit":"$RATE",
                        "anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
                        "comments":"${GROUP} | ${DECODER} | PORT_${PORT} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_invalid)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

elif [ "$DECODER" = "FRAGMENT" ]; then

generate_ratelimit_fragment()
{
cat << EOF
{
     "flowspec announcement":   {
                        "bgp_connector_id":"$CONNECTOR_ID",
                        "ip_protocol(s)":["UDP"],
			"ip_fragment(s)":["true"],
                        "${DIRECTION}":"$IP",
                        "action":"Rate Limit",
                        "rate_limit":"$RATE",
                        "anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
                        "comments":"${GROUP} | ${DECODER} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_fragment)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

elif [ "$DECODER" = "UDP" ]; then

generate_ratelimit_udp()
{
cat << EOF
{
     "flowspec announcement":   {
                        "bgp_connector_id":"$CONNECTOR_ID",
                        "ip_protocol(s)":["UDP"],
                        "${DIRECTION}":"$IP",
                        "action":"Rate Limit",
                        "rate_limit":"$RATE",
                        "anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
                        "comments":"${GROUP} | ${DECODER} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_udp)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

elif [ "$DECODER" = "OTHER" ]; then

generate_ratelimit_other()
{
cat << EOF
{
     "flowspec announcement":   {
                        "bgp_connector_id":"$CONNECTOR_ID",
                        "ip_protocol(s)":[$PROTOCOL],
                        "${DIRECTION}":"$IP",
                        "action":"Rate Limit",
                        "rate_limit":"$RATE",
                        "anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
                        "comments":"${GROUP} | ${DECODER} | RATE_${MBPS}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_other)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

else # PARAMETROS INCORRETOS

	echo "$DATE - ERROR: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$IP] | DECODER=[$DECODER] | RATE=[$RATE] | UNIT=[$UNIT] | GROUP=[$GROUP] - Parametros incorretos !" | stdbuf -oL tee -a $LOG
    	exit 0

fi
