#!/bin/bash
#
#
#
######################################

# Testing if root...
if [ $UID -ne 0 ]
then
    RED "You must run this script as root!" && echo
    exit
fi


chown root:root /etc/motd
chmod 644 /etc/motd
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
  
chown root:root /etc/issue
chmod 644 /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
  
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
