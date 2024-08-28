#!/bin/bash
# -------------------------------------------------------
# -------------------------------------------------------
# Inicia a configuração
# -------------------------------------------------------
# Ativa modulos no Kernel
# -------------------------------------------------------
modprobe iptable_nat
modprobe iptable_filter
modprobe ip_tables
modprobe ip_conntrack
modprobe ip_conntrack_ftp
modprobe ip_nat_ftp
#modprobe ip_nat_pptp
modprobe ipt_MASQUERADE
modprobe ipt_LOG
#modprobe ip_queue
modprobe ipt_MARK
#modprobe ipt_MIRROR
modprobe ipt_REDIRECT
modprobe ipt_REJECT
modprobe ipt_TCPMSS
modprobe ipt_TOS
modprobe ipt_limit
modprobe ipt_mac
modprobe ipt_mark
modprobe ipt_multiport
modprobe ipt_owner
modprobe ipt_state
modprobe ipt_tcpmss
modprobe ipt_tos
#modprobe ipt_unclean
modprobe iptable_mangle
#modprobe ipt_layer7 #requer compilacao do kernel


# Ativando o Roteamento no kernel
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/ip_forward

# Ativando Proteção contra Alteração de Rotas
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects

# Ativando Protecao contra IP spoofing
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter

# Ativando outros recursos de Seguranca
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/ip_dynaddr
echo "30" > /proc/sys/net/ipv4/tcp_fin_timeout
echo "1800" > /proc/sys/net/ipv4/tcp_keepalive_intvl

# Ativando Proteção contra Responses Bogus
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Ativando Proteção contra Syn-flood
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/tcp_syncookies

# Ativando Proteção contra TraceRoute
# -------------------------------------------------------
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route

# Ativando Protecao contra IP spoofing
# -------------------------------------------------------
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
echo "1800" > /proc/sys/net/ipv4/tcp_keepalive_intvl

# Zera regras do IPTables
iptables -F
iptables -X
iptables -F -t nat
iptables -X -t nat
iptables -F -t mangle
iptables -X -t mangle

ip6tables -F
ip6tables -X
ip6tables -F -t nat
ip6tables -X -t nat
ip6tables -F -t mangle
ip6tables -X -t mangle


# Define endereço de rede interna
LOCALNET=192.168.0.0/24


#--------------------------------------#
# Conclua a configuração #
#--------------------------------------#

# Definir regra padrão (regra aplicada quando nenhuma das seguintes regras corresponder)
IPTABLES_CONFIG=`mktemp`
echo "*filter" >> $IPTABLES_CONFIG
echo ":INPUT DROP [0:0]" >> $IPTABLES_CONFIG       # Elimina todas as entradas
echo ":FORWARD DROP [0:0]" >> $IPTABLES_CONFIG     # Descarta todas as passagens
echo ":OUTPUT ACCEPT [0:0]" >> $IPTABLES_CONFIG    # Permite todas as transmissões
echo ":ACCEPT_COUNTRY - [0:0]" >> $IPTABLES_CONFIG # Permite acesso de países especificados
echo ":DROP_COUNTRY - [0:0]" >> $IPTABLES_CONFIG   # Descarta o acesso do país especificado
echo ":LOG_PINGDEATH - [0:0]" >> $IPTABLES_CONFIG  # Os ataques Ping of Death são registrados e descartados

ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT

# Permite todo o acesso do próprio host
echo "-A INPUT -i lo -j ACCEPT" >> $IPTABLES_CONFIG
ip6tables -A INPUT -i lo -j ACCEPT

# Permite todos os acessos internos
echo "-A INPUT -s $LOCALNET -j ACCEPT" >> $IPTABLES_CONFIG
#ip6tables -A INPUT -s $LOCALNET -j ACCEPT
ip6tables -A INPUT -s fe80::/10 -p ipv6-icmp -j ACCEPT

# Permite DHCPv6
ip6tables -A INPUT -s fe80::/10 -p udp --dport 546 -m conntrack --ctstate NEW -j ACCEPT

# Permite acesso de resposta de fora para acesso feito de dentro
echo "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" >> $IPTABLES_CONFIG
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Ativar cookies SYN
# *TCP SYN Contramedidas de ataque Flood
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

# Não responda a pings para endereço de broadcast
# * Contra-medidas de ataque Smurf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf

# Negar pacotes de redirecionamento ICMP
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done

# Nega pacotes roteados de origem
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done

# Registra e descarta pacotes fragmentados
echo "-A INPUT -f -j LOG --log-prefix \"[IPTABLES FRAGMENT] : \"" >> $IPTABLES_CONFIG
echo "-A INPUT -f -j DROP" >> $IPTABLES_CONFIG
#ip6tables -A INPUT -f -j LOG --log-prefix '[IP6TABLES FRAGMENT] : '
#ip6tables -A INPUT -f -j DROP

# Proteção contra ataques
#echo "-A INPUT -m state --state INVALID -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT -m conntrack --ctstate INVALID -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Protege Contra Pacotes Que Pode Procurar e Obter Informações Internas
# -----------------------------------------------------------------------------------------------------------
#echo "-A FORWARD --protocol tcp --tcp-flags ALL SYN,ACK -j DROP" >> $IPTABLES_CONFIG

# Proteção contra port Scanners Ocultos
# -----------------------------------------------------------------------------------------------------------
#echo "-A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT" >> $IPTABLES_CONFIG
echo "-N port-scanning" >> $IPTABLES_CONFIG
echo "-A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN" >> $IPTABLES_CONFIG
echo "-A port-scanning -j DROP" >> $IPTABLES_CONFIG

# Protecao contra port scanners V2
#echo "-N SCANNER" >> $IPTABLES_CONFIG
#echo "-A SCANNER -m limit --limit 15/m -j LOG --log-level 6 --log-prefix \"[IPTABLES PORT SCANNER] : \"" >> $IPTABLES_CONFIG
#echo "-A SCANNER -j DROP" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags ALL NONE -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags ALL ALL -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags ALL FIN,SYN -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG
#echo "-A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -s $LOCALNET -j SCANNER" >> $IPTABLES_CONFIG

# Os acessos relacionados ao NetBIOS com o exterior são descartados sem gravação de logs
# * Evite gravação de log desnecessária
echo "-A INPUT ! -s $LOCALNET -p tcp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT ! -s $LOCALNET -p udp -m multiport --dports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A OUTPUT ! -d $LOCALNET -p tcp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG
echo "-A OUTPUT ! -d $LOCALNET -p udp -m multiport --sports 135,137,138,139,445 -j DROP" >> $IPTABLES_CONFIG


# Registra e descarta pings superiores a 4 vezes por segundo
# * Contramedidas do ataque Ping da Morte
echo "-A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A LOG_PINGDEATH -j LOG --log-prefix \"[IPTABLES PINGDEATH] : \"" >> $IPTABLES_CONFIG
echo "-A LOG_PINGDEATH -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT -p icmp --icmp-type echo-request -j LOG_PINGDEATH" >> $IPTABLES_CONFIG

ip6tables -N LOG_PINGDEATH
ip6tables -A LOG_PINGDEATH -m limit --limit 1/s --limit-burst 4 -j ACCEPT
ip6tables -A LOG_PINGDEATH -j LOG --log-prefix '[IP6TABLES PINGDEATH] : '
ip6tables -A LOG_PINGDEATH -j DROP
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j LOG_PINGDEATH

# Descarte pacotes endereçados a todos os hosts (endereço de broadcast, endereço de multicast) sem registro de logs
# * Evite gravação de log desnecessária
echo "-A INPUT -d 255.255.255.255 -j DROP" >> $IPTABLES_CONFIG
echo "-A INPUT -d 224.0.0.1 -j DROP" >> $IPTABLES_CONFIG

# Nega resposta ao acesso à porta 113 (IDENT)
# *Prevenção de queda na resposta do servidor de correio, etc.
echo "-A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset

# Definição da função ACCEPT_COUNTRY_MAKE
# Crie uma cadeia definida pelo usuário que permite o acesso de endereços IP em países especificados
ACCEPT_COUNTRY_MAKE(){
    for addr in `cat /root/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A ACCEPT_COUNTRY -s $addr -j ACCEPT" >> $IPTABLES_CONFIG
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# Definição da função DROP_COUNTRY_MAKE
# Crie uma cadeia definida pelo usuário que descarta o acesso de endereços IP no país especificado
DROP_COUNTRY_MAKE(){
    for addr in `cat /root/cidr.txt|grep ^$1|awk '{print $2}'`
    do
        echo "-A DROP_COUNTRY -s $addr -j DROP" >> $IPTABLES_CONFIG
    done
    grep ^$1 $IP_LIST >> $CHK_IP_LIST
}

# Obtém a lista de endereços IP
IP_LIST=/root/cidr.txt
CHK_IP_LIST=/root/IPLIST
if [ ! -f $IP_LIST ]; then
    wget -q https://github.com/lobo360/iptables-ubuntu/raw/main/cidr.txt.gz
    gunzip -c cidr.txt.gz > $IP_LIST
    rm -f cidr.txt.gz
fi
rm -f $CHK_IP_LIST

# Crie uma cadeia definida pelo usuário ACCEPT_COUNTRY que permite o acesso do Brasil
ACCEPT_COUNTRY_MAKE BR
# A partir de agora, se você quiser permitir o acesso apenas do Brasil, especifique ACCEPT_COUNTRY em vez de ACCEPT

# Registrar e descartar acessos dos 5 principais países (excluindo Brasil e Estados Unidos) que atacam instalações policiais do Japão
# Lista de códigos de países https://ja.wikipedia.org/wiki/ISO_3166-1#%E7%95%A5%E5%8F%B7%E4%B8%80%E8%A6%A7
DROP_COUNTRY_MAKE RU
DROP_COUNTRY_MAKE CN
DROP_COUNTRY_MAKE KR
DROP_COUNTRY_MAKE IN
DROP_COUNTRY_MAKE ID
echo "-A INPUT -j DROP_COUNTRY" >> $IPTABLES_CONFIG

# Regras de segurança na internet
echo "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT" >> $IPTABLES_CONFIG
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

#------------------------------------------------- ----------#
# Configurações para publicar vários serviços a partir daqui #
#------------------------------------------------- ----------#

# Permitir acesso à porta TCP 22 (SSH) com fail2ban
# *Vai logar se errar no logon
echo "-N fail2ban-ssh" >> $IPTABLES_CONFIG
echo "-A fail2ban-ssh -j RETURN" >> $IPTABLES_CONFIG
echo "-I INPUT -p tcp --dport ssh -j fail2ban-ssh" >> $IPTABLES_CONFIG
ip6tables -N fail2ban-ssh
ip6tables -A fail2ban-ssh -j RETURN
ip6tables -I INPUT -p tcp --dport ssh -j fail2ban-ssh

# Permitir acesso à porta TCP 22 (SSH) de fora apenas do Japão
# *Somente se você quiser publicar o servidor SSH
#echo "-A INPUT -p tcp --dport 22 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir acesso à porta TCP 21 (FTPS) de fora apenas do Japão
# *Somente se você quiser publicar o servidor FTP
# For SSL you might add following rule somewhere
#echo "-A INPUT -p tcp --dport 21 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m conntrack --ctstate NEW -m tcp -m multiport --dports 40110:40210 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 21 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 40110:40210 -j ACCEPT


# Permite acesso externo à porta TCP/UDP 53 (DNS)
# *Apenas ao operar um servidor DNS externo
#echo "-A INPUT -p tcp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT -p udp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG
#ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT
#ip6tables -A INPUT -p udp --dport 53 -j ACCEPT

#Caso essas regras de dns não funcione no seu linux, comente essas e ative as de cima:
echo " -A INPUT -p udp --dport 53 -m string --from 40 --algo bm --hex-string '|0000FF0001|' -m recent --set --name dnsanyquery" >> $IPTABLES_CONFIG
echo " -A INPUT -p udp --dport 53 -m string --from 40 --algo bm --hex-string '|0000FF0001|' -m recent --name dnsanyquery --rcheck --seconds 60 --hitcount 3 -j DROP" >> $IPTABLES_CONFIG
echo " -A INPUT -p tcp --dport 53 -m string --from 52 --algo bm --hex-string '|0000FF0001|' -m recent --set --name dnsanyquery" >> $IPTABLES_CONFIG
echo " -A INPUT -p tcp --dport 53 -m string --from 52 --algo bm --hex-string '|0000FF0001|' -m recent --name dnsanyquery --rcheck --seconds 60 --hitcount 3 -j DROP" >> $IPTABLES_CONFIG

echo " -N DNSAMPLY" >> $IPTABLES_CONFIG
echo " -A DNSAMPLY -p udp -m state --state NEW -m udp --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG
echo " -A DNSAMPLY -p udp -m hashlimit --hashlimit-srcmask 24 --hashlimit-mode srcip --hashlimit-upto 30/m --hashlimit-burst 10 --hashlimit-name DNSTHROTTLE --dport 53 -j ACCEPT" >> $IPTABLES_CONFIG
echo " -A DNSAMPLY -p udp -m udp --dport 53 -j DROP" >> $IPTABLES_CONFIG

ip6tables -N DNSAMPLY
ip6tables -A DNSAMPLY -p udp -m state --state NEW -m udp --dport 53 -j ACCEPT
ip6tables -A DNSAMPLY -p udp -m hashlimit --hashlimit-srcmask 24 --hashlimit-mode srcip --hashlimit-upto 30/m --hashlimit-burst 10 --hashlimit-name DNSTHROTTLE --dport 53 -j ACCEPT
ip6tables -A DNSAMPLY -p udp -m udp --dport 53 -j DROP

# Permite acesso externo à porta TCP 80 (HTTP)
# *Apenas quando você publica o servidor web
# *Aceitar o pacote SYN, SYN/ACK, ACK da porta 80 para permitir o handshake e descartar o restante dos pacotes
#echo "-A INPUT -p tcp --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags SYN ACK --dport 80 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags FIN RST URG PSH --dport 80 -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT

# Permite acesso externo à porta TCP443 (HTTPS)
# *Apenas quando você publica o servidor web
# *Aceitar o pacote SYN, SYN/ACK, ACK da porta 443 para permitir o handshake e descartar o restante dos pacotes
#echo "-A INPUT -p tcp --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags SYN ACK --dport 443 -j ACCEPT" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags FIN RST URG PSH --dport 443 -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT

# Permite acesso externo à porta TCP 25 (SMTP)
# *Somente quando você publica o servidor SMTP
#echo "-A INPUT -p tcp --dport 25 -j ACCEPT" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp --dport 25 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 25 -j ACCEPT


# Permitir acesso à porta TCP587 (SUBMISSION) de fora somente do Brasil
# *Somente quando você publica o servidor SMTP
# *Não é necessário se o servidor SMTPS (porta TCP465) estiver aberto ao público
#echo "-A INPUT -p tcp --dport 587 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# Permitir acesso à porta TCP465 (SMTPS) de fora apenas do Brasil
# *Somente quando você publica o servidor SMTPS
echo "-A INPUT -p tcp --dport 465 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 465 -j ACCEPT

# Permitir acesso à porta TCP 110 (POP3) de fora apenas do Brasil
# *Apenas ao publicar um servidor POP3
echo "-A INPUT -p tcp --dport 110 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 110 -j ACCEPT

# Permitir acesso à porta TCP 995 (POP3S) de fora apenas do Brasil
# *Apenas ao publicar um servidor POP3S
echo "-A INPUT -p tcp --dport 995 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 995 -j ACCEPT

# Permitir acesso à porta TCP 143 (IMAP) de fora apenas do Brasil
# *Apenas ao publicar um servidor IMAP
echo "-A INPUT -p tcp --dport 143 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 143 -j ACCEPT

# Permitir acesso à porta TCP 993 (IMAPS) de fora apenas do Brasil
# *Apenas ao publicar o servidor IMAPS
echo "-A INPUT -p tcp --dport 993 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 993 -j ACCEPT

# Permitir acesso externo a UDP500 e UDP4500 (L2TP sobre IPsec) somente do Brasil
# *Apenas ao abrir SoftEther VPN Server
echo "-A INPUT -p udp --dport 500 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p udp --dport 4500 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p udp --dport 1194 -j ACCEPT

# Permitir acesso à porta TCP20000 (Usermin) de fora somente do Brasil
# *Somente quando você publica o servidor Usermin
echo "-A INPUT -p tcp --dport 20000 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG

# Permitir acesso externo à porta TCP4040 (Subsonic)
# *Apenas ao publicar Subsonic
echo "-A INPUT -p tcp --dport 4040 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 4040 -j ACCEPT

# Permitir acesso externo à porta TCP8080 (ISPConfig)
# *Apenas ao publicar ISPConfig
#aceitar o pacote SYN, SYN/ACK, ACK da porta 8080 para permitir o handshake e descartar o restante dos pacotes
#echo "-A INPUT -p tcp --dport 8080 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags SYN ACK --dport 8080 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 8080 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags FIN RST URG PSH --dport 8080 -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Permitir acesso externo à porta TCP8081 (ISPConfig apps)
# *Apenas ao publicar ISPConfig apps
#aceitar o pacote SYN, SYN/ACK, ACK da porta 8081 para permitir o handshake e descartar o restante dos pacotes
#echo "-A INPUT -p tcp --dport 8081 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags SYN ACK --dport 8081 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport 8081 -j ACCEPT_COUNTRY" >> $IPTABLES_CONFIG
#echo "-A INPUT --protocol tcp --tcp-flags FIN RST URG PSH --dport 8081 -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -p tcp --dport 8081 -j ACCEPT


#------------------------------------------------- ----------#
# Configurações para publicar vários serviços (até agora)    #
#------------------------------------------------- ----------#

# Descartar acessos de endereços IP negados sem gravar logs
# *Descreva o endereço IP negado em /root/deny_ip para cada linha
# (Não faça nada se /root/deny_ip não existir)
if [ -s /root/deny_ip.txt ]; then
    for ip in `cat /root/deny_ip.txt`
    do
        echo "-I INPUT -s $ip -j DROP" >> $IPTABLES_CONFIG
    done
fi

# Acessos que não atendem as regras acima são registrados e descartados
#*Como a quantidade de logs aumenta, a gravação do log é realizada conforme necessário.
echo "-A INPUT -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES INPUT] : \"" >> $IPTABLES_CONFIG
echo "-A INPUT -j DROP" >> $IPTABLES_CONFIG
echo "-A FORWARD -m limit --limit 1/s -j LOG --log-prefix \"[IPTABLES FORWARD] : \"" >> $IPTABLES_CONFIG
echo "-A FORWARD -j DROP" >> $IPTABLES_CONFIG
ip6tables -A INPUT -m limit --limit 1/s -j LOG --log-prefix '[IP6TABLES INPUT] : '
ip6tables -A INPUT -j DROP
ip6tables -A FORWARD -m limit --limit 1/s -j LOG --log-prefix '[IP6TABLES FORWARD] : '
ip6tables -A FORWARD -j DROP


# reflete as configurações do firewall ubuntu
echo "COMMIT" >> $IPTABLES_CONFIG
cat $IPTABLES_CONFIG > /etc/iptables/rules.v6
cat $IPTABLES_CONFIG > /etc/iptables/rules.v4

if [ -f /etc/init.d/netfilter-persistent ]; then
	sudo dpkg-reconfigure iptables-persistent
	/etc/init.d/netfilter-persistent restart
	sudo netfilter-persistent save
else
	systemctl restart iptables
	systemctl restart ip6tables
fi
rm -f $IPTABLES_CONFIG

# COMANDOS RESOLUÇÃO DE PROBLEMAS
#sudo systemctl restart systemd-networkd.service
#sudo systemctl restart systemd-networkd-wait-online.service
#sudo systemctl restart systemd-resolved.service
#sudo netplan apply
#sudo ifconfig eth0 down && ifconfig eth0 up
#sudo ifconfig eth1 down && ifconfig eth1 up
