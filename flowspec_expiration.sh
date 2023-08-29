#!/bin/bash
# kiviobraga@gmail.com

# PARAMETROS
if [ $# -lt 1 ]
 then
     echo
     echo " Usage: $0 <ANOMALY_ID>"
     echo
     echo " Exemplo: $0 id=43"
  exit 2
fi

ANOMALY_ID=$(echo $1 | cut -d= -f2)

CONNECTOR_ID="2"
USER_API="wanguard_api"
SECRET_API="wanguard_api"
LOG="/var/log/flowspec.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

if [ ! -f "$LOG" ]; then
touch $LOG
chown andrisoft:andrisoft $LOG
fi


URL_ID=$(curl -s -X GET "http://127.0.0.1/wanguard-api/v1/bgp_announcements?status=Active&anomaly_id=${ANOMALY_ID}&bgp_connector_id=${CONNECTOR_ID}" -H "Accept:application/json" --user "$USER_API:$SECRET_API" | jq -r ".[] | .href" | cut -d/ -f5)

if [ ! -z "$URL_ID" ]; then

curl -s -X PUT -H "Content-Type:application/json" -H "Accept:application/json" --user "$USER_API:$SECRET_API" "http://127.0.0.1/wanguard-api/v1/bgp_announcements/${URL_ID}/status?status=Finished"

echo "$DATE - FLOWSPEC_DEL: ANOMALIA=[${ANOMALY_ID}] | REGRA=[${URL_ID}]" | stdbuf -oL tee -a $LOG
exit 0

else

echo "$DATE - FLOWSPEC_FAILED: NAO FOI ENCONTRADO REGRA DE FLOWSPEC, ANOMALY_ID=${ANOMALY_ID}" | stdbuf -oL tee -a $LOG
exit 0

fi
