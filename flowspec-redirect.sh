#!/bin/bash
# kiviobraga@gmail.com


# PARAMETROS
if [ $# -lt 6 ]
 then
     echo
     echo " Usage: $0 <PREFIX> <DECODER> <ANOMALY_ID> <GROUP> <DIRECTION> <TIMER_WITHDRAW>"
     echo
     echo " <PREFIX> = prefix=200.200.0.0/24"
     echo " <DECORDER> = decoder=IP"
     echo " <ANOMALY_ID> = id=1000"
     echo " <GROUP> = group=WANGUARD"
     echo " <DIRECTION> = direction=incoming"
     echo " <TIMER_WITHDRAW> = timer_withdraw=3600"
     echo
     echo " Exemplo_0: $0 prefix=200.200.200.0/24 decoder=IP id=1000 group=WANGUARD direction=incoming timer_withdraw=3600"
     echo " Exemplo_1: $0 prefix=200.200.200.0/32 decoder=IP id=1000 group=WANGUARD direction=incoming timer_withdraw=3600"
  exit 2
fi

PREFIX=$(echo $1 | cut -d= -f2)
DECODER=$(echo $2 | cut -d= -f2)
ANOMALY_ID=$(echo $3 | cut -d= -f2)
GROUP=$(echo $4 | cut -d= -f2)
DIRECTION=$(echo $5 | cut -d= -f2)
TIMER_WITHDRAW=$(echo $6 | cut -d= -f2)
USER_API="wanguard_api"
SECRET_API=$(cat /opt/andrisoft/etc/dbpass.conf)


URL="-X POST http://127.0.0.1/wanguard-api/v1/bgp_announcements --user $USER_API:$SECRET_API"
CONNECTOR_ID=$(cat /opt/andrisoft/etc/flowspec-redirect_id.conf)
LOG="/var/log/flowspec-redirect.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")
[ ! -e "$LOG" ] && touch $LOG && chown andrisoft:andrisoft $LOG


# CHECK_DIRECTION
if [ "$DIRECTION" != "incoming" ]
then
	echo "$DATE - FLOWSPEC_FAILED: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$PREFIX] | DECODER=[$DECODER] | GROUP=[$GROUP] | DIRECTION=[$DIRECTION] - paramentro DIRECTION=[$DIRECTION] incorreto !" | stdbuf -oL tee -a $LOG
	exit 0
fi


if [ "$DECODER" = "IP" ]; then

generate_ratelimit_ip()
{
cat << EOF
{
     "flowspec announcement":   {
                        "bgp_connector_id":"$CONNECTOR_ID",
                        "ip_protocol(s)":[],
                        "destination_prefix":"$PREFIX",
                        "action":"Redirect",
                        "anomaly_id":"$ANOMALY_ID",
                        "withdraw_after":"$TIMER_WITHDRAW",
                        "comments":"REDIRECT-APPLIANCE - ${GROUP}"
     }
}
EOF
}

curl $URL -H "Content-Type:application/json" -H "Accept:application/json" --data-binary "$(generate_ratelimit_ip)"
echo "$DATE - FLOWSPEC_ADD: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$PREFIX] | DECODER=[$DECODER] | GROUP=[$GROUP]" | stdbuf -oL tee -a $LOG
exit 0

else # PARAMETROS INCORRETOS

	echo "$DATE - ERROR: ANOMALIA=[$ANOMALY_ID] | PREFIX=[$PREFIX] | DECODER=[$DECODER] | GROUP=[$GROUP] - Parametros incorretos !" | stdbuf -oL tee -a $LOG
    	exit 0

fi
