# Authors: PJFox - Stew

import os 
import time
import re
import json
import html
import subprocess
from datetime import datetime
import pandas as pd

#Dataset
IP = "http://localhost"
POOL_NAME="mypool"
DATASET="docker/mysql-data"
CLONE="snapshot"
FULL_DATASET=f"{POOL_NAME}/{DATASET}"
CLONE_PATH=f"{POOL_NAME}/{CLONE}"
ROLLBACK_LOG = "/var/log/sql_detected.log"
JSON_FILE = "/var/www/html/binlog_summary.json"
HTML_FILE = "/var/www/html/binlog_summary.html"
BINLOG_PATH = "/var/lib/docker/volumes/mysql-data/_data/mysql-bin.000001"
DIFF_OUTPUT = "/var/www/html/diff_table.html"
# for all information, change to --all-databases
DATABASE_COMPARATION = "breach_test"

# zfs create mypool/snapshot

def cmd_run(cmd):
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = process.communicate()
    return (out + err).strip()  

def clear_snapshot(snapshot_path):
    cmd_run(f"sudo zfs destroy {snapshot_path}")

def rollback_snapshots():
    # Get snapshot list
    output = cmd_run("zfs list -t snapshot -o name -s creation")
    lines = [line for line in output.splitlines() if line.startswith(FULL_DATASET)]

    if not lines:
        print("\nNo snapshots found for dataset.")
        input("Press Enter to return...")
        return

    print("\n==== Snapshot list ====\n")
    labeled_snapshots = []

    for idx, line in enumerate(lines, start=1):
        if "@auto-" in line.lower():
            label = "Auto"
        elif "@manual-" in line.lower():
            label = "Manual"
        else:
            label = "Unknown"
        labeled_snapshots.append((label, line))
        print(f"{idx}. [{label}] {line}")

    try:
        choice = int(input("\nSelect snapshot (0 to cancel): "))
    except ValueError:
        print("Invalid.")
        return

    if choice == 0:
        print("Cancel Rollback.")
        return

    if 1 <= choice <= len(labeled_snapshots):
        label, selected_snap = labeled_snapshots[choice - 1]
        confirm = input(f"\nConfirm rollback to snapshot [{label}]:\n{selected_snap}\n(Type 'yes' to confirm): ").strip()
        if confirm.lower() == "yes":
            print("\nStopping Container...")
            cmd_run("sudo docker-compose down")

            print(f"\nRollback: {selected_snap}")
            msgs = cmd_run(f"sudo zfs rollback -r {selected_snap}")

            if "clones of previous snapshots exist" in msgs:
                clone_names = [msg.strip() for msg in msgs if msg.strip().startswith(f'{CLONE_PATH}')]
                for clone_name in clone_names:
                    clear_snapshot(clone_name)
                msgs = cmd_run(f"sudo zfs rollback -r {selected_snap}")
            
            print("\nStarting container...")
            cmd_run("sudo docker-compose up -d")

            print("\nRollback successful!")
        else:
            print("Cancel Rollback.")
    else:
        print("Wrong option.")

    input("\nPress Enter to return to menu...")


def create_manual_snapshot():
    timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
    snapshot_name = f"{FULL_DATASET}@Manual-{timestamp}"
    cmd_run(f"sudo zfs snapshot {snapshot_name}")
    print(f"=================New Snapshot=================")
    print(f"=    Snapshot {snapshot_name} has been created.   =")
    print(f"==============================================")
    input("********* Press Enter to return to menu *********")

def view_rollback_log():
    print("Rollback & Alert Log:\n")
    try:
        with open(ROLLBACK_LOG, 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print(f"Log file not found: {ROLLBACK_LOG}")
    input("********* Press Enter to return to menu *********")

def extract_binlog():
    
    timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
    snapshot_name = f"{FULL_DATASET}@Manual-{timestamp}"
    cmd_run(f"sudo zfs snapshot {snapshot_name}")

    current_path = f"{CLONE_PATH}/{int(datetime.now().timestamp() * 1_000_000)}"
    cmd_run(f"zfs clone {snapshot_name} {current_path}")
    
    bin_list = cmd_run(f"ls /{current_path}/mysql-bin.[0-9][0-9][0-9][0-9][0-9][0-9] | sort").split("\n")
    
    events = []

    for binl in bin_list:
            
        logs = cmd_run(f"mysqlbinlog --base64-output=DECODE-ROWS -v {binl}").splitlines()
        
        timestamp = None
        database = None
        table = None
        event_type = None
        old_value = ''
        new_value = ''
        i = 0

        while i < (len(logs)):
            try:
                append_log = []
                log_pos = int(re.search(r"end_log_pos\s+(\d+)", logs[i]).group(1))
                
                temp_i = i
                while temp_i < len(logs) and not logs[temp_i].startswith('### ') and not logs[temp_i].startswith('DROP '):
                    if 'TIMESTAMP' in logs[temp_i] and logs[temp_i].startswith('SET TIMESTAMP='):
                        timestamp = datetime.fromtimestamp(int((logs[temp_i].split("=")[1]).split('/')[0].strip()))
                        break
                    temp_i += 1
                
                i+=1

                # filter
                while (str(log_pos) not in logs[i]) and ('# End of log file' not in logs[i]) and not logs[i].startswith('COMMIT') and not logs[i].startswith('Xid =') and (i < len(logs)):
                    if 'TIMESTAMP' in logs[i] and logs[i].startswith('SET TIMESTAMP='):
                        timestamp = datetime.fromtimestamp(int((logs[i].split("=")[1]).split('/')[0].strip()))
                        i+=1
                        continue
                    if (logs[i].startswith('### DELETE') or logs[i].startswith('### INSERT') or 
                        logs[i].startswith('### UPDATE') or logs[i].startswith('DROP TABLE') or 
                        logs[i].startswith('DROP DATABASE')) and len(append_log) > 0:
                        break
                    if logs[i].startswith('use') or logs[i].startswith('USE'):
                        database = logs[i].split()[1].replace('`', '').replace('/*!*/;', '')
                    if  logs[i].startswith('### ') or logs[i].startswith('DROP '):
                        append_log.append(logs[i].replace('###', '').replace('\n','').replace('`', '').replace('/*!*/','').replace('/* generated by server */',''))
                    i+=1
                log_str = ''.join(append_log)
                
                # event_type
                if 'DELETE' in log_str:
                    event_type = 'DELETE'
                    database, table = (log_str.split(' ')[3]).split('.')
                    old_value = (log_str.split('WHERE')[1])
                    
                elif 'INSERT' in log_str:
                    event_type = 'INSERT'
                    database, table = (log_str.split(' ')[3]).split('.')
                    new_value = (log_str.split('SET')[1])
                    
                elif 'UPDATE' in log_str:
                    event_type = 'UPDATE'
                    database, table = (log_str.split(' ')[2]).split('.')
                    old_value = (log_str.split('WHERE')[1]).split('SET')[0]
                    new_value = log_str.split('SET')[1]
                    
                elif 'DROP' in log_str:
                    event_type = 'DROP'
                    query = log_str.split(' ')
                    if query[1] == 'TABLE':
                        table = query[2]
                        if database is None:
                            if '.' in log_str:
                                database = log_str.split('.')[0].split()[-1]
                    elif query[1] == 'DATABASE':
                        database = query[2]
                    
                
                if (timestamp is not None) and (event_type is not None) and (table is not None) :
                
                    events.append({
                        'timestamp': timestamp,
                        'database': database,
                        'table': table,
                        'event_type': event_type,
                        'old_value': old_value.strip(),
                        'new_value': new_value.strip()
                    })
                    
                    
                    
                    timestamp = None
                    database = None
                    table = None
                    event_type = None
                    old_value = ''
                    new_value = ''
                
            except:
                None
            i+=1
    
    # delete snapshot
    clear_snapshot(current_path)
    
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            try:
                old_events = json.load(f)
                if isinstance(old_events, dict):
                    old_events = list(old_events.values())
            except Exception:
                old_events = []
    else:
        old_events = []

    def event_key(event):
        return (
            str(event['timestamp']),
            event.get('database', ''),
            event.get('table', ''),
            event.get('event_type', ''),
            event.get('old_value', ''),
            event.get('new_value', '')
        )

    old_event_keys = set(event_key(e) for e in old_events)
    unique_events = old_events.copy()
    for e in events:
        if event_key(e) not in old_event_keys:
            unique_events.append(e)
            old_event_keys.add(event_key(e))

    json_output = json.dumps(unique_events, indent=2, default=str)
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        f.write(json_output)
    
    df = pd.DataFrame(unique_events)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values(by='timestamp', ascending=False)

        table_style = """
        <style>
        body { font-family: Arial, sans-serif; background: #f7f7f7; }
        h2 { text-align: center; }
        table { border-collapse: collapse; margin: 20px auto; min-width: 900px; background: #fff; box-shadow: 0 2px 8px #ccc; }
        th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: center}
        th { background: #0074D9; color: #fff; }
        tr:nth-child(even) { background: #f2f2f2; }
        tr:hover { background: #e6f7ff; }
        </style>
        """

        html = table_style
        html += "<h2>Binlog summary:</h2>"
        html += df.to_html(index=False, escape=False)

        with open(HTML_FILE, "w", encoding="utf-8") as f:
            f.write(html)
        # clear_clone()
        print(f"Finishing!!! Accessing to {IP}/binlog_summary.html to see the result")
    else:
        print("No events were recorded.")

    
    input("\nPress Enter to return to menu...")

def dump_database(filename, database):
    cmd_run(f"sudo docker exec -it mysql-forensics "
        f"mysqldump -uroot -prootpass {database} > {filename}")

def rollback_snapshot(snapshot_name):
    print("[+] Rolling back snapshot...")
    cmd_run("sudo docker-compose down")
    msgs = cmd_run(f"sudo zfs rollback -r {snapshot_name}")
    if "clones of previous snapshots exist" in msgs:
                clone_names = [msg.strip() for msg in msgs if msg.strip().startswith(f'{CLONE_PATH}')]
                for clone_name in clone_names:
                    clear_snapshot(clone_name)
                msgs = cmd_run(f"sudo zfs rollback -r {snapshot_name}")
    
    cmd_run("sudo docker-compose up -d")
    print("[✓] Waiting for MySQL container to restart...")
    time.sleep(2)

def generate_diff_html(before_file, after_file, output_file):
    with open(before_file) as bf, open(after_file) as af:
        before_lines = bf.readlines()
        after_lines = af.readlines()

    max_len = max(len(before_lines), len(after_lines))
    html_lines = [
        "<html><head><meta charset='utf-8'><style>",
        "table { border-collapse: collapse; width: 100%; font-family: monospace; }",
        "td, th { border: 1px solid #ccc; padding: 4px; }",
        "tr.diff td { background-color: #ffe6e6; }",
        "tr.same td { background-color: #f9f9f9; }",
        "</style></head><body><h2>MySQL Dump Comparison</h2><table>",
        "<tr><th>Line</th><th>before.sql</th><th>after.sql</th></tr>"
    ]

    for i in range(max_len):
        b_line = before_lines[i].rstrip("\n") if i < len(before_lines) else ""
        a_line = after_lines[i].rstrip("\n") if i < len(after_lines) else ""
        b_html = html.escape(b_line)
        a_html = html.escape(a_line)
        cls = "same" if b_line == a_line else "diff"
        html_lines.append(
            f"<tr class='{cls}'><td>{i+1}</td><td>{b_html}</td><td>{a_html}</td></tr>"
        )

    html_lines.append("</table></body></html>")
    with open(output_file, "w") as f:
        f.write("\n".join(html_lines))
    print("Checking your browser to view result.")

def compare_snapshots():
    print("==[ Step 1: Dumping current DB ]==\n")
    cmd_run(f"sudo docker exec -it mysql-forensics mysqldump -uroot -prootpass {DATABASE_COMPARATION} > after.sql 2>/dev/null")
    # cleaner output for comapration
    cmd_run("sed -i '1d' after.sql")

    print("\n==[ Step 2: Choose snapshot to compare ]==")
    output = cmd_run("zfs list -t snapshot -o name -s creation")
    lines = [line for line in output.splitlines() if line.startswith(FULL_DATASET)]

    if not lines:
        print("\nNo dataset found to compare.")
        input("Press Enter to return...")
        return

    print("\n==== Snapshot list ====\n")
    labeled_snapshots = []

    for idx, line in enumerate(lines, start=1):
        if "@auto-" in line.lower():
            label = "Auto"
        elif "@manual-" in line.lower():
            label = "Manual"
        else:
            label = "Unknown"
        labeled_snapshots.append((label, line))
        print(f"{idx}. [{label}] {line}")

    try:
        choice = int(input("\nSelect snapshot (0 to cancel): "))
    except ValueError:
        print("Invalid.")
        return

    if choice == 0:
        print("Cancel comparing.")
        return

    if 1 <= choice <= len(labeled_snapshots):
        label, selected_snap = labeled_snapshots[choice - 1]
        clone_path = f"{CLONE_PATH}/{int(datetime.now().timestamp() * 1_000_000)}"
        cmd_run(f"sudo zfs clone {selected_snap} {clone_path}")
        
        cmd_run(f"docker run -d --name mysql-temp -v /{clone_path}:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=toilanguoi2k3 mysql:8")
        # make time lost to deploy 
        time.sleep(5)
        cmd_run(f"docker exec mysql-temp mysqldump -uroot -prootpass {DATABASE_COMPARATION} > before.sql ")
        
    else:
        print("Wrong option.")

    print("\n==[ Step 3: Generate diff HTML ]==")
    generate_diff_html("before.sql", "after.sql", DIFF_OUTPUT)
    
    # stop and delete clone_container 
    cmd_run("docker stop mysql-temp")
    cmd_run("docker rm mysql-temp")
    cmd_run(f"sudo zfs destroy {clone_path}")

    print(f"Finishing!!! Accessing to {IP}/diff_table.html to see the result")
    input("\nPress Enter to return to menu...")

def main_menu():
    while True:
        os.system("clear")
        print("==== Forensics Snapshot CLI ====")
        print("[1] Rollback Snapshots")
        print("[2] Create manual snapshot")
        print("[3] View rollback log & alerts")
        print("[4] Extract binlog")
        print("[5] Compare 2 snapshots")
        print("[6] Exit")
        choice = input("\nSelect action: ").strip()

        match choice:
            case "1": 
                rollback_snapshots()
            case "2":
                create_manual_snapshot()
            case "3":
                view_rollback_log()
            case "4":
                extract_binlog()
            case "5":
                compare_snapshots()
            case "6":
                print("Exiting program.")
                break
            case _:
                print("Invalid choice.")
                time.sleep(1)

if __name__ == "__main__":
    main_menu() 