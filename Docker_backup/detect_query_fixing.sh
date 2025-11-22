#!/bin/bash

echo "-------------------------------------------"
echo "- This is an automation script 0x53746577 -"
echo "-          Auth: --Stew - Vulpes356--     -"
echo "-------------------------------------------"
echo ""



# === Webhook Settings ===
WEBHOOK_URL="https://bizflow.vn/webhook/a512093f-32a3-4128-9c6f-babea5b8cd221231s"

# === General Settings ===
LOG_FILE="/var/lib/docker/volumes/dbs_project_mysql-data/_data/general.log"
KEYWORDS=("delete" "drop" "update")
FULL_DATASET="mypool/docker/mysql-data"
SNAPSHOT_PREFIX=("Auto-" "Manual-")
line2="line"


# === Alert via Webhook ===
send_webhook() {
  local message="$1"
  local event_type="$2"
  local now=$(date +'%Y-%m-%d %H:%M:%S')

  curl -s -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "event": "'"$event_type"'",
      "message": "'"$message"'",
      "time": "'"$now"'"
    }' > /dev/null
}


send_text_file() {
  local file_path="$1"
  local comment="$2"

  curl -s -X POST "$WEBHOOK_URL" \
    -F "payload_json={\"content\": \"$comment\"}" \
    -F "file=@${file_path};type=text/plain" > /dev/null
}



# === Rollback Recent Snapshot ===
rollback_to_latest_snapshot() {
    local detected_line="$1"
    latest_snapshot=$(zfs list -t snapshot -o name -s creation | grep "${FULL_DATASET}@" | grep -E "(Auto|Manual)-" | tail -n 1)

    if [[ -n "$latest_snapshot" ]]; then
        send_webhook "Rollback initiated to snapshot: $latest_snapshot" "rollback_start"
        echo "[+] Stopping container..."
        sudo docker-compose down
        echo "[+] Rolling back to $latest_snapshot..."
        sudo zfs rollback -r "$latest_snapshot"
        echo "[+] Starting container..."
        sudo docker-compose up -d
        send_webhook "Rollback to snapshot completed: $latest_snapshot" "rollback_done"
    else
        send_webhook "No snapshot found to rollback!" "rollback_failed"
    fi
}




# === Trigger Blacklist Query ===
trigger_blacklist_query() {
echo -e "[*] Monitoring MySQL log at:  \n$LOG_FILE"
while true; do
        sudo tail -n0 -F "$LOG_FILE" | while read -r line; do
                lower_line=$(echo "$line" | tr '[:upper:]' '[:lower:]')
                for keyword in "${KEYWORDS[@]}"; do
                        if [[ "$lower_line" == *"$keyword"* ]]; then
                                echo -e "[!] Detected suspicious query: \n$line"
                                echo -e "4\n\n6\n\n" | python3 Menu.py
                                echo "$line" > /home/ubuntuserver/suspicious_query.txt
                                
                                # === Data extraction ===
                                timestamp=$(echo "$line" | awk '{print $1}')
				timestamp=$(TZ=UTC date -d "${timestamp}" +"%Y-%m-%d %H:%M:%S")

				event_type=$(echo "$line" | sed 's/.*Query\s*\([a-zA-Z]*\).*/\1/' | tr '[:lower:]' '[:upper:]')
				jq --arg timestamp "$timestamp" --arg event_type "$event_type" '  map(select(.timestamp == $timestamp and (.event_type | test($event_type))))' /var/www/html/binlog_summary.json > /home/ubuntuserver/sus_query_data.json
				
				# wanna change format?
                                
                                
                                send_webhook "[ALERT] Suspicious SQL detected: " "alert"
                                send_text_file /home/ubuntuserver/suspicious_query.txt "file"
                                
                                send_webhook "[ALERT] Suspicious SQL query: " "alert"
                                send_text_file /home/ubuntuserver/sus_query_data.json "file"
                                
                                rollback_to_latest_snapshot
                                break 2
                        fi
                done
        done
        echo "[*] Restarting tail after rollback..."
        sleep 2
done
}


# === Running Background ===
if [[ "$1" == "internal" ]]; then
    trigger_blacklist_query
else
    nohup bash "$0" internal > detect.log 2>&1 &
    echo "[+] check_echo.sh is now running in background."
    exit 0
fi