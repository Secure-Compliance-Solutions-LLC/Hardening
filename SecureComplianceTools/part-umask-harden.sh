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

# set users umask
sed -i "s/UMASK.*022/UMASK   077/" /etc/login.defs

# set root umask
sed -i "s/#.*umask.*022/umask 077/" /root/.bashrc
