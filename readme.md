<h1>A collection of my commonly used cPanel/Centos scripts </h1>
<h2>Larger scripts</h2>

#quick overview of server/connections. Can be used with/without site arguments. 

```
quick_review()
{
GREEN='\033[0;32m'
NC='\033[0m' # No Color
echo -e "${GREEN}Current Processes involving $1 ${NC}\n"
pgrep -lc  "$1"
echo -e "${GREEN}PHP-FPM maxing out from $1${NC}\n"
tail -n2 /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log | grep max 2>/dev/null  
echo -e "${GREEN}Apache Errors involving $1${NC}\n"
tail -n2 /usr/local/apache/logs/error_log | grep "$1" 2>/dev/null 
echo -e "${GREEN}Nginx Errors involving $1${NC}\n"
tail -n2 /var/log/nginx/error.log | grep "$1" 2>/dev/null  
echo -e "${GREEN}Top 20 site connections to $1${NC}\n"
sort /usr/local/apache/domlogs/"$1"  | awk '{print $1}'| uniq -c | sort -hr | head -n20 2>/dev/null  
echo -e "${GREEN}Server load for past 10 minutes${NC}\n"
sar -q | tail -n5 2>/dev/null 
echo -e "${GREEN}Top Port 80  Connections${NC}\n"
netstat -tn 2>/dev/null | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head 2>/dev/null  
echo -e "${GREEN}Top P:ort 443 connections${NC}\n"
netstat -tn 2>/dev/null | grep :443 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head 2>/dev/null  
echo -e "${GREEN}PHP-FPM Error logs${NC}\n"
grep -i "$1" /var/cpanel/php-fpm/*/logs/error.log | tail -n5 2>/dev/null  
echo -e "${GREEN}Domain Apache  Access Logs for ${NC}\n"
tail -n5 /usr/local/apache/domlogs/"$1" 2>/dev/null  
echo -e "${GREEN}Nginx Access Logs for ""$1"" Site Asset Site Name ${NC}\n" 
sort /var/log/nginx/access.log | grep -v "$(hostname -i)" | grep "$1" | awk '{print $1,$7,$27}'| uniq -c | sort -hr | head -n20
echo "MySQL errors today $(for i in $(grep error /etc/my.cnf | sed 's/log-error=//'); do echo "$i" ; tail -5 "$i" ; done)"
}
````

#To perform every site on server, use the following

```
for i in $(for a in /var/named/*.db; do echo $(basename $a .db); done); do quick_review $i; done
```

#overview of cPanel access. Includes cPanel,Root, Password Changes, Webmail and Webmail password changes.

```
(
clear
echo -e "IP User/Email_User Date Operating-System Browser"
echo -e "cPanel_Access"
grep -a "paper_lantern/index.html" /usr/local/cpanel/logs/access_log | awk '{print $1,$3,$4,$13,$20}' | sort -u | uniq
echo -e "Root_WHM_Access"
grep -a "login=1&post_login" /usr/local/cpanel/logs/access_log | awk '{print $1,$3,$4,$13,$20}' | sort -u | uniq
echo -e "cPanel_Password_Changes"
grep -a "passwd" /usr/local/cpanel/logs/access_log  |   awk '{print $1}' | sort -u | uniq
echo -e "Webmail_Access" 
grep "%40" /usr/local/cpanel/logs/access_log | awk '{print $1,$3,$4}' | sort -u | uniq
echo -e "Webmail_Password_changes"
grep -a passwd_pop /usr/local/cpanel/logs/access_log | awk '{print $1,$3}' | sort -u | uniq
echo -e "SSH Access"
 grep -i accepted /var/log/secure | awk '{print $1,$2,$3,$11}' | sort -u | uniq
) | column -t
```
#Same thing, but excludes the date, which makes the output extremely verbose.


```
(
GREEN='\033[0;32m'
NC='\033[0m' # No Color
clear
echo -e "${GREEN}IP User/Email_User Operating-System Browser ${NC}\n"
echo -e "${GREEN}cPanel_Access${NC}\n" 
grep -a "paper_lantern/index.html" /usr/local/cpanel/logs/access_log | awk '{print $1,$3,$13,$20}' | sort -u | uniq
echo -e "${GREEN}Root_WHM_Access${NC}\n"
grep -a "login=1&post_login" /usr/local/cpanel/logs/access_log | awk '{print $1,$3,$13,$20}' | sort -u | uniq
echo -e "${GREEN}cPanel_Password_Changes${NC}\n"
grep -a "passwd" /usr/local/cpanel/logs/access_log  |   awk '{print $1}' | sort -u | uniq
echo -e "${GREEN}Webmail_Access${NC}\n"
grep "%40" /usr/local/cpanel/logs/access_log | awk '{print $1,$3}' | sort -u | uniq
echo -e "${GREEN}Webmail_Password_changes${NC}\n"
grep -a passwd_pop /usr/local/cpanel/logs/access_log | awk '{print $1,$3}' | sort -u | uniq
echo -e "SSH Access"
 grep -i accepted /var/log/secure | awk '{print $1,$2,$3,$11}' | sort -u | uniq
) | column -t
```
#skims over common<a href="https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-log-files/">Log Files</a>for an  IP address

```
err()
	{
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color
	clear
	echo -e "\n${GREEN} Server Log${NC}"
	grep "$1"  /var/log/messages | tail -n3
	echo -e "\n${GREEN} Apache Error Log${NC}" 
	grep "$1"  /usr/local/apache/logs/error_log | tail -n3
	echo -e "\n${GREEN} Nginx Error Log${NC}" 
	grep "$1"  /var/log/nginx/error.log | tail -n3
	echo -e "\n${GREEN} cPanel Access Log${NC}" 
	grep "$1"  /usr/local/cpanel/logs/access_log | tail -n3
	echo -e "\n${GREEN} SSH/SFTP commands Log${NC}" 
	grep "$1"  /var/log/secure | tail -n3
	echo -e "\n${GREEN} cPanel logins ${NC}"
	grep "$1"  /usr/local/cpanel/logs/login_log | tail -n3
	}
```


#add dmarc/SPF records to one  domain, show proptime

#Example <a href="https://support.cpanel.net/hc/en-us/articles/1500000323641-How-to-add-a-DNS-record-to-a-domain-using-the-WHM-API-" target="_blank">Docs</a>

#Full  <a href="https://documentation.cpanel.net/display/DD/WHM+API+1+Functions+-+addzonerecord" target="_blank">API Docs </a>

#This does NOT factor in dedicated IP addresses, in other words, it references the servers IP address itself

```
SPF_DMARC()
{
tar -czf /root/named_backup_$(date +%F).tar.gz /var/named*
ls -lah /root/named_backup_$(date +%F).tar.gz
whmapi1 addzonerecord domain="$1" name="_dmarc.$1." class=IN ttl=86400 type=TXT txtdata='v=DMARC1; p=none'
 whmapi1 addzonerecord domain=$1 name=$1 class=IN ttl=86400 type=TXT txtdata="v=spf1 +a +mx +ip4:$(hostname -i) -all"
echo -e "This will take effect globally between $(date -d "+4 hours") and $( date -d "+24 hours")"
echo "$1"
for i in $(dig ns $1 +short |head -n1); do dig @$i txt $1 +short ; done
for i in $(dig ns $1 +short |head -n1); do dig @$i txt _dmarc.$1 +short ; done
echo https://www.whatsmydns.net/#TXT/_dmarc."$1"
echo https://www.whatsmydns.net/#TXT/"$1"
}
```
#do for every domain
```
for i in $(for a in /var/named/*.db; do echo $(basename $a .db); done); do SPF_DMARC $i; done
```

#Can't find your blocked ip in a fail2ban env?

```
f2b(){
    clear;
    unblock "$1"
    #root required
    whmapi1 flush_cphulk_login_history_for_ips ip="$1"
    /scripts/cphulkdwhitelist "$1"
    [ -f /etc/csf/csf.conf ] && csf -a "$1" || apf -a "$1"
    #fail2ban log
    tail -n5 /var/log/fail2ban.log | grep "$1"
    #mail client login fails
    sudo cat /var/log/maillog | grep 'auth failed' | grep "$1"
    #failing exim
    sudo cat /var/log/exim_mainlog | grep 'authenticator failed' | grep "$1"
    #Modsec blocks
    sudo cat /usr/local/apache/logs/error_log | grep -E 'id "(13052|13051|13504|90334)"' | grep "$1"
    #cPanel blocks
    sudo cat  /usr/local/cpanel/logs/login_log | grep "FAILED LOGIN" | grep "$1"
    #apf/csf logs, requires root
    sudo grep "$1" /etc/*/*.deny
}
```

#Sends mail out to a test email of your choosing from a mailbox of your chooseing, and watches the logs for it. creates an email account for testing

Echoes out dns information on the test email as well. 

Stops tailing log after 1 minutes.

Includes link to multirbl to cover any blacklisting

#Syntax: 
localdomain.com to@domain.com. 

#replace $2 with your test recipient email; can take multiple recipents, just seperate with commas

```
mailtest()
  {
    clear
      /scripts/addpop test@"$1" "$(date | md5sum)" 50
         echo -e "This is a test email sent on $(date '+%Y-%m-%d') by a member of the Technical Support team. \nThese are  the DNS records for ""$1""  \n$(dig any "$1" +short). \nThis is the MX records IP address: $(dig a $(dig mx "$1" +short) +short). \nBlacklisted? $(echo http://multirbl.valli.org/lookup/$(hostname -i).html)
 \nReplies are not monitored. Please ignore." | mail -s  "Email Test Support" -r test@"$1" "$2"
         	clear ;
         		echo "sending mail from ""$1"" to ""$2"""
         			sudo timeout 1m tail -f /var/log/exim_mainlog | grep "$1"
         			  }
```
#excludes DNS records 
```
mailtest()
  {
    clear
      /scripts/addpop "$1" $(date | md5sum) 50
         echo "This is a test email sent on $(date '+%Y-%m-%d') by a member of the Technical Support team. Replies are not monitored. Please ignore." | mail -s  "Email Test Support" -r "$1" "$2"
	 	clear ;
			echo "sending mail from ""$1"" to ""$2"""
				sudo tail -f /var/log/exim_mainlog | grep "$1"
				  }
```

##emails out disk usage, top 20 files, and saves to text file

```
  mailusage()
  {
    du -cahS --threshold=500M --exclude="{virtfs,cache,etc,logs,perl5, public_ftp,mail,public_html,quarantine,ssl,tmp}" /home/* /backup /home/*/.trash| sort -hr > usage.$(date +%F)
    clear
         echo -e "This is the  current disk usage  for ""$(hostname)""  \n$(cat usage.$(date +%F)).
         \n Disk Usage as of $(date +%F)
         \n $(df -h | head -n2)
 		\nReplies are not monitored." | mail -s  "Disk Usage Report" -r usage@"$(hostname)" "$1"
    }
 ```
		



#clean up InnoDB logfiles. Keep in mind, InnoDB cannot be disabled
#https://dev.mysql.com/doc/refman/5.7/en/innodb-turning-off.html

```
	{
	clear
	tail -10 /var/lib/mysql/*.err
	systemctl stop mysql;
	mv /var/lib/mysql/ib_logfile0 /var/lib/mysql/ib_logfile0.bak;
	mv /var/lib/mysql/ib_logfile1 /var/lib/mysql/ib_logfile1.bak;
	systemctl start mysql ; systemctl status mysql
	}
```
#Dumps all DBS to root/dbbackups, datestamps 

```
(
clear
path="/root/dbbackups-$( date +"%Y-%m-%dT%H:%M:%S%z" )"
mkdir $path && touch $path/dumplist 
echo "Dumping into $path"
for db in $( mysql -e 'show databases' | grep -v "Database\|information_schema\|leechprotect\|cphulkd\|modsec\|mysql\|performance_schema\|roundcube" | awk '{print $1}' ) ; do 
echo "Dumping $db ..."
mysqldump --add-drop-table --databases $db > $path/$db.sql
echo $db >> $path/dumplist
done
echo "Logged to $path/dumplist"
)
mysqlcheck -reA
systemctl restart mysql ; systemctl status mysql

```

##Renames ibdata logfiles
More details here
https://forums.cpanel.net/resources/innodb-corruption-repair-guide.395/

```
	{
	clear
	tail -10 /var/lib/mysql/*.err
	systemctl stop mysql;
	mv /var/lib/mysql/ib_logfile0 /var/lib/mysql/ib_logfile0.bak;
	mv /var/lib/mysql/ib_logfile1 /var/lib/mysql/ib_logfile1.bak;
	systemctl start mysql ; systemctl status mysql
	}
```

#rebuild cpanel <a href="https://docs.cpanel.net/knowledge-base/accounts/how-to-rebuild-userdata-files/" target="_blank">userdata files</a>? files

```
(
mv /var/cpanel/userdata /var/cpanel/userdata.orig.$(date +%F)
mkdir /var/cpanel/userdata
/usr/local/cpanel/bin/userdata_update --reset
/usr/local/cpanel/bin/fix_userdata_perms
/scripts/updateuserdatacache
/scripts/rebuildhttpdconf
/scripts/restartsrv_httpd
)
```


#install <a href="https://redis.io/documentation" target="_blank">Redis</a>? 
```
(
yum update
yum install epel-release -y
yum install redis -y 
systemctl start redis
service redis start
systemctl enable redis
chkconfig –add redis
redis-cli ping
)
```
#specs at a glance
```
{
clear
 df -h | head -n2 |column -t
 free -mh | head -n2| column -t
 grep -i 'model name' /proc/cpuinfo | head -n1 |column -t
 hostname |column -t; hostname -i |column -t
 cat /etc/redhat-release |column -t && /usr/local/cpanel/cpanel -V |column -t
 ls /etc/cpanel/ea4/is_ea4
 mysql --version
 php --version
}
```


#emails out disk usage, top 20 files, and saves to text file
```
  mailusage()
  {
    du -cahS --threshold=500M --exclude="{virtfs,cache,etc,logs,perl5, public_ftp,mail,public_html,quarantine,ssl,tmp}" /home/* /backup /home/*/.trash| sort -hr > usage.$(date +%F)
    clear
         echo -e "This is the  current disk usage  for ""$(hostname)""  \n$(cat usage.$(date +%F)).
         \n Disk Usage as of $(date +%F)
         \n $(df -h | head -n2)
 		\nReplies are not monitored." | mail -s  "Disk Usage Report" -r usage@"$(hostname)" "$1"
    }
```


##generates keypair

##usage genkey username username@IP

```
 genkey()
{
ssh-keygen -f ~/.ssh/"$1"-ecdsa -t ecdsa -b 521
ssh-copy-id -i ~/.ssh/"$1"-ecdsa "$2"
echo "alias "conn_"$1"=\"ssh -i ~/.ssh/"$1"-ecdsa "$2"\" >> .bashrc
}
```

##Checks for new autossl certs, creates a nightly cron to do so, moves current cpanel queue and forces a restart
```
(
clear
echo "$(($RANDOM%60)) $(($RANDOM%24)) * * * root /usr/local/cpanel/bin/autossl_check --all" > /etc/cron.d/cpanel_autossl && /scripts/restartsrv_crond
mv -v /var/cpanel/autossl_queue_cpanel.sqlite{,_old}
clear
/usr/local/cpanel/bin/autossl_check_cpstore_queue --force
/usr/local/cpanel/bin/autossl_check --all
)
```


##Need to manually view themost recent AutoSSL log?
```
tail  `/bin/ls -1td /var/cpanel/logs/autossl/*/txt| /usr/bin/head -n1`
```
