#!/bin/bash
##############################################
#					     #
#	Template - Firewall Iptables         #
#					     #
##############################################

function clean_tables(){
iptables -Z 
iptables -F 
iptables -t nat -Z
iptables -t nat -F
iptables -t mangle -Z
iptables -t mangle -F
iptables -t raw -Z
iptables -t raw -F
iptables -t security -Z
iptables -t security -F
}

function set_variables(){
INT_WAN="eth0"
INT_LAN="eth1"
REDE_LAN="10.0.0.0/24"
}

function start(){
#### CHAMADA DE FUNÇÕES####
clean_tables
set_variables
#######################################

#### COMPARTILHAMENTO DE INTERNET (NAT/MASQUERADE) ####
echo "1" > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o $INT_WAN -s $REDE_LAN -j MASQUERADE
#######################################

#### AUMENTA O LIMITE DE CONSULTAS DNS ####
echo 1024 > /proc/sys/net/ipv4/neigh/default/gc_thresh1
echo 2048 > /proc/sys/net/ipv4/neigh/default/gc_thresh2
echo 4096 > /proc/sys/net/ipv4/neigh/default/gc_thresh3
#######################################

#### POLÍTICAS PADRÃO ####
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
#######################################

#### REGRAS DE ESTADO DE CONEXÕES #####
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

#### REGRAS DE LOOPBACK ####
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
#######################################

#### REGRAS DE ENTRADA/SAÍDA NO FIREWALL (FILTER) #####
################ SSH ##################
iptables -A INPUT -i $INT_WAN -s 192.168.0.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i $INT_LAN -s $REDE_LAN -p tcp --dport 22 -j ACCEPT
#######################################
############### ICMP ##################
iptables -A INPUT -i $INT_WAN -s 192.168.0.0/24 -d 192.168.0.200 -p icmp -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -i $INT_LAN -s $REDE_LAN -d 10.0.0.1 -p icmp -m limit --limit 1/s -j ACCEPT
iptables -A OUTPUT -p icmp -m limit --limit 1/s -j ACCEPT
#######################################
############### DNS ###################
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
#######################################
### LIBERA ATUALIZAÇÃO DO REPO APT ####
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d ftp.br.debian.org -p tcp --dport 21 -j ACCEPT
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d ftp.br.debian.org -p tcp --dport 20 -j ACCEPT
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d ftp.br.debian.org -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d security.debian.org -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d security-cdn.debian.org -p tcp --dport 80 -j ACCEPT
######################################
####### LIBERA PUSH NO GITHUB ########
iptables -A OUTPUT -o $INT_WAN -s 192.168.0.200 -d github.com -p tcp --dport 443 -j ACCEPT
######################################

#### REGRAS DE ENCAMINHAMENTO LAN/INTERNET (FORWARD) ####
####### LIBERA NAVEGAÇÃO NA WEB #######
iptables -A FORWARD -p tcp -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d 0/0 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d 0/0 --dport 443 -j ACCEPT
#######################################
############### ICMP ##################
iptables -A FORWARD -p icmp -m limit --limit 1/s -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d 0/0 -j ACCEPT
#######################################
############### DNS ###################
iptables -A FORWARD -p udp -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d 8.8.8.8 -j ACCEPT
iptables -A FORWARD -p udp -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d 192.168.0.254 -j ACCEPT
#######################################
############ FTP PASSIVO ##############
iptables -A FORWARD -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d ftp.howtoonline.com.br -p tcp --dport 21 -j ACCEPT
iptables -A FORWARD -i $INT_LAN -o $INT_WAN -s $REDE_LAN -d ftp.howtoonline.com.br -p tcp --sport 1024: -j ACCEPT
}

function stop(){
clean_tables
set_variables
iptables -t nat -A POSTROUTING -o $INT_WAN -s $REDE_LAN -j MASQUERADE
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
}

case $1 in
start)
start
;;

stop)
stop
;;

restart)
stop
sleep 1
start
;;

*)
echo "Insira um dos parâmetros seguintes:  'start | stop | restart'"
exit 0
;;
  
esac
