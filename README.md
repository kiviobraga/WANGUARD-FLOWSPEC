# WANGUARD-FLOWSPEC
Flowspec integration plugin in wanguard tool

1 - RS-FLOWSPEC
1.1 - FLOWSPEC_ADD
ANOMALY_SCRIPT: sudo -u andrisoft /opt/andrisoft/bin/flowspec.sh {prefix} decoder={decoder} rate={rule_value} unit={unit} id={anomaly_id} group={ip_group} direction={direction}

2.2 - FLOWSPEC_DEL
EXPIRES_SCRIPT: sudo -u andrisoft /opt/andrisoft/bin/flowspec_expiration.sh id={anomaly_id}
