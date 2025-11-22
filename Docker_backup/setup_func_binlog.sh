#!/bin/bash

echo "Updating..."
sudo apt update

echo "Python library..."
sudo apt install -y python3-pip mysql-client
sudo pip3 install pandas tabulate --break-system-packages

echo "ZFS check and download..."
sudo zfs list mypool/clone > /dev/null 2>&1
if [ $? -ne 0 ]; then
    sudo zfs create mypool/clone
    echo "Dataset mypool/clone created successfully."
else
    echo "Dataset mypool/clone already exist."
fi

echo "Create summaryweb..."
sudo mkdir -p /var/www/html
sudo touch /var/www/html/binlog_summary.html
sudo touch /var/www/html/binlog_summary.json
sudo chmod 666 /var/www/html/binlog_summary.*

echo "Finish!!!"

