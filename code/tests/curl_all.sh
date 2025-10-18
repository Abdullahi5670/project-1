#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"

echo "# register"
curl -s -X POST "$BASE/auth/register" -H "Content-Type: application/json" \
  -d '{"name":"Ada","email":"ada@example.com","password":"P@ssw0rd"}' | jq

echo "# login"
LOGIN=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"P@ssw0rd"}')
echo "$LOGIN" | jq
TOKEN=$(echo "$LOGIN" | php -r '$i=json_decode(stream_get_contents(STDIN),true); echo $i["token"]??"";')

echo "# list users (public)"
curl -s "$BASE/users" | jq

echo "# get me (bearer)"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/users/me" | jq
