#!/bin/bash
# Auto Watcher — runs organizer + analyzer automatically

LOG_DIR="/home/cowrie/HoneypotLogs"
SCRIPTS="/home/cowrie/scripts"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

echo "[$TIMESTAMP] Running auto watcher..." >> $LOG_DIR/watcher.log

# Run log organizer
python3 $SCRIPTS/log_organizer.py >> $LOG_DIR/watcher.log 2>&1

# Run JSON analyzer
python3 $SCRIPTS/json_analyzer.py >> $LOG_DIR/watcher.log 2>&1

# Sync to desktop
cp -r $LOG_DIR/* /home/aviral/Desktop/HoneypotLogs/ 2>/dev/null

echo "[$TIMESTAMP] Done." >> $LOG_DIR/watcher.log