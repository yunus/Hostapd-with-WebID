#!/bin/bash


# DNSMASQ settings. Copy the lines below to /etc/dnsmasq.conf
#----------------------
# disables dnsmasq reading any other files like /etc/resolv.conf for nameservers
#no-resolv
# Interface to bind to
#interface=wlan0
# Specify starting_range,end_range,lease_time
#dhcp-range=10.0.0.3,10.0.0.20,12h
# dns addresses to send to the clients
#server=8.8.8.8
#server=8.8.4.4
#------------------

nmcli nm wifi off
rfkill unblock wlan

#Initial wifi interface configuration
ifconfig $1 up 10.0.0.1 netmask 255.255.255.0
sleep 2
 
###########Start dnsmasq, modify if required##########
if [ -z "$(ps -e | grep dnsmasq)" ]
then
 dnsmasq
fi
###########
 
#Enable NAT
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables --table nat --append POSTROUTING --out-interface $2 -j MASQUERADE
iptables --append FORWARD --in-interface $1 -j ACCEPT
 
#Thanks to lorenzo
#Uncomment the line below if facing problems while sharing PPPoE, see lorenzo's comment for more details
iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
 
sysctl -w net.ipv4.ip_forward=1

 
#start hostapd
./hostapd/hostapd -dt ./hostapd/myhostapd.conf 1> hostapd.log
killall dnsmasq
