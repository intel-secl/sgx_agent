#!/bin/bash

CURL_OPTS="-s -k"
CONTENT_TYPE="Content-Type: application/json"
ACCEPT="Accept: application/jwt"

mkdir -p /tmp/sgx_agent
tmpdir=$(mktemp -d -p /tmp/sgx_agent)

#Get the CSP Admin JWT Token
ADMIN_TOKEN=`curl $CURL_OPTS -H "$CONTENT_TYPE" -H "$ACCEPT" -X POST $AAS_BASE_URL/token -d \{\"username\":\"$CSP_ADMIN_USERNAME\",\"password\":\"$CSP_ADMIN_PASSWORD\"\}`
if [ $? -ne 0 ]; then
        echo "failed to get csp admin token"
        exit 1
fi

HW_UUID=`dmidecode -s system-uuid`

cat > $tmpdir/request_data.json << EOF
{
    "subject": "$HW_UUID",
    "validity_seconds": 2592000,
    "claims": {
        "roles": [{
            "service": "SCS",
            "name": "HostDataUpdater"
        },
        {
            "service": "SCS",
            "name": "HostDataReader"
        },
        {
            "service": "SHVS",
            "name": "HostDataUpdater"
        }]
    }
}
EOF

LONG_LIVED_TOKEN=`curl $CURL_OPTS -H "$CONTENT_TYPE" -H "$ACCEPT" -H "Authorization: Bearer $ADMIN_TOKEN" -X POST $AAS_BASE_URL/custom-claims-token -d @$tmpdir/request_data.json`
if [ $? -ne 0 ]; then
        echo "failed to get long-lived token"
        exit 1
fi
echo $LONG_LIVED_TOKEN