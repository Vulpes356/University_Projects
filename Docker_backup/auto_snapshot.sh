#!/bin/bash

#Dataset
POOL_NAME="mypool"
DATASET="docker/mysql-data"
FULL_DATASET="$POOL_NAME/$DATASET"
SNAPSHOT_NAME="Auto-$(date +%d-%m-%Y-%S:%M:%H)"

#Kiem tra dataset trong host

if  zfs list "$FULL_DATASET" > /dev/null 2>&1; then
        echo "Exist dataset: $FULL_DATASET"
        echo "Creating snapshot: $FULL_DATASET@$SNAPSHOT_NAME"
        sudo zfs snapshot "$FULL_DATASET@$SNAPSHOT_NAME"
        echo "Tao snapshot thanh cong!"
else
        echo "Dataset not exist: $FULL_DATASET"
        exit 1
fi