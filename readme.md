<h1>A collection of my commonly used cPanel/Centos scripts </h1>
<h2>General Overview</h2>


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

#quick overview of server/connections. Primarily geared towards Apache, will clean up for nginx soon. 

```
{
clear
GREEN='\033[0;32m'
NC='\033[0m' # No Color
echo -e "${GREEN}Top 5 Processes  ${NC}\n"
ps aux | sort -nrk 3,3 | head -n 5
echo -e "${GREEN}Top Processes from each user ${NC}\n"
for i in $(cat /etc/userdomains  | awk {'print $2'} | grep -v nobody | uniq ); do echo "Processes for $i"; ps cax --sort -pmem  |grep $i; done
echo -e "${GREEN}PHP-FPM maxing out from ${NC}\n"
tail -n2 /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log
echo -e "${GREEN}Apache Errors ${NC}\n"
tail -n2 /usr/local/apache/logs/error_log 
echo -e "${GREEN}Nginx Errors${NC}\n"
tail -n2 /var/log/nginx/error.log
echo -e "${GREEN}Top 20 Apache  domain connections per site today ${NC}\n"
for i in $(for a in /var/named/*.db; do echo $(basename $a .db); done
); do echo $i; sort /usr/local/apache/domlogs/"$i"  | grep $(date +"%d/%b/%Y") | awk '{print $1,$4,$7}'|  uniq -c | sort -hr | head -n20 ; done
echo -e "${GREEN}Server load for past 10 minutes${NC}\n"
sar -q | tail -n5
echo -e "${GREEN}Top current Apache Connections${NC}\n"
netstat -tn 2>/dev/null | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head
echo -e "${GREEN}Top Nginx connections${NC}\n"
netstat -tn 2>/dev/null | grep :443 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head
echo "MySQL errors today $(for i in $(grep error /etc/my.cnf | sed 's/log-error=//'); do echo "$i" ; tail -5 "$i" ; done)"
echo "current IP addresses connected"
netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n | grep -v 127.0.0.1
}

````


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

<h2>DNS</h2>

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

<h2>Firewall</h2>
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

<h2>Email</h2>
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
/scripts/addpop test@"$1" "$(head -c32 /dev/urandom | md5sum)" 50
mail -s "Email Test Support" -r test@"$1" "$2" << END
This is a test email sent on $(date '+%Y-%m-%d') by a member of the Technical Support team. 
These are the DNS records for ""$1""
$(dig any "$1" +short)
This is the MX records IP address: $(dig a $(dig mx "$1" +short) +short)
Blacklisted? $(echo http://multirbl.valli.org/lookup/$(hostname -i).html)
Replies are not monitored. Please ignore. 
END
clear
echo "sending mail from ""test@$1"" to ""$2"""
sudo tail -f /var/log/exim_mainlog | grep "$1"&
}
```

<h2>Disk Usage</h2>

##emails out disk usage, top > 500M files


 
```
diskusage()
{
clear
mail -s  "Disk Usage Report" -r usage@"$(hostname)" "$1" << END
This is the  current disk usage  for $(hostname) as of $(date +%F) above 500M
Logs
$(du -cahS --threshold=500M /var/log/ | sort -hr)
Home Directories
$(du -cahS --threshold=500M /home/*/ | sort -hr)
Trash
$(du -cahS --threshold=500M /home/*/.trash | sort -hr)
Backups
$(du -cahS --threshold=500M /backup/ | sort -hr)
$(df -h)
END
}
```

narrow down highest amount of inode usage, change directory to that folder
```
{
    cd || exit
    clear
	for run in {1..10}
	do for i in $(du --inodes | sort -hr | head -n2 | sed -n '2 p' | awk {'print $2'})
	do cd "$i" || exit
	done
	echo "Highest inodes are in  $(pwd)"
	ls | wc -l 
	done
} 
```
		


<h2>SQL</h2>
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

Enable General MySQL Logging for one hour

```
{
  cp -fv /etc/my.cnf{,.bak_$(date +%F)}
  echo "general_log" >> /etc/my.cnf
  service mysql restart
  echo "general MySQL log is /var/lib/mysql/$(hostname | cut -d"." -f1).log"
  at now + 1 hour <<END
  cp -fv /etc/my.cnf{.bak_$(date +%F),}
  service mysql restart
END
}
```

#enable query logging in mysql for 24 hours, email out to $1
```
slow_query()
{
  cp -fv /etc/my.cnf{,.bak_$(date +%F)}
  touch /var/log/slowqueries
  echo "slow_query_log = /var/log/slowqueries" >> /etc/my.cnf
  echo "slow_query_log_file = /var/log/slowqueries" >> /etc/my.cnf
  chown mysql:mysql /var/log/slowqueries
  service mysql restart
  at now + 24 hour <<END
cp -fv /etc/my.cnf{.bak_$(date +%F),}
service mysql restart
cat /var/log/slowqueries  |   mail -s "SQL Slow Query logs" -r root@"$(hostname)" "$1"
END
}	
```



<h2>cPanel</h2>

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



##Checks for new autossl certs, creates a nightly cron to do so, moves current cpanel queue and forces a restart. searches todays autossl logs
```
(
auto_ssl_search()
{
clear
echo "$(($RANDOM%60)) $(($RANDOM%24)) * * * root /usr/local/cpanel/bin/autossl_check --all" > /etc/cron.d/cpanel_autossl && /scripts/restartsrv_crond
mv -fv /var/cpanel/autossl_queue_cpanel.sqlite{,_old}
/usr/local/cpanel/bin/autossl_check_cpstore_queue --force
/usr/local/cpanel/bin/autossl_check --all
eval "whmapi1 reset_service_ssl_certificate service="{exim,dovecot,ftp,cpanel}";"
eval "/scripts/restartsrv_"{exim,dovecot,ftpd,cpsrvd}";"
/usr/local/cpanel/bin/checkallsslcerts --allow-retry --verbose
clear
grep -C 3 $1 /var/cpanel/logs/autossl/$(date +%F)*/txt
}
```

<h2>Wordpress</h2>


Wordpress general info/backup crit files
```
{
wp cache flush&
wp db repair&
wp core verify-checksums&
wp db export --skip-{plugins,themes}
for i in .htaccess php.ini  wp-config.php ; do cp $i{,.$(date +%F).bak}; done
clear
awk -F"'" '/DB_/{print $4}' wp-config.php;
for i in theme plugin user ; do echo $i for $(wp option get siteurl --skip-{plugins,themes} );  wp $i list --skip-{plugins,themes} ; done
mv *.sql ..
}
```

loop through each plugin, and curl site. replace plugins with theme for themes.  
```
{
wp db export plugins.$(date +%F).sql
clear
for i in $(wp plugin list --skip-{plugins,themes} | awk {'print $1'})
 do echo "disabling $i for $(wp option get siteurl)"
 wp plugin deactivate "$i" --skip-{plugins,themes}
 curl -sLA "foo" $(wp option get siteurl) | grep -i error
 done
 wp db import plugins.$(date +%F).sql
}
```


The purpose of this is to echo out the database credentials for any CMS and the instructions on how to do it correctly, instead of guessing at database/username combos, or potentially fat-fingering a sql command, everything is filled in. Copy and paste the raw file to get those functions started. 
	#Joomla coming soon™
	#Moodle coming soon™
	#Drupal coming soon™ 
```
	{
	if test -f wp-config.php;
	then
		clear
		test -f wp-config.php; echo "This is Wordpress $(wp core version)"
		echo "Password for $(awk -F"'" '/DB_NAME/{print $4}' wp-config.php) is $(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)"
		echo "mysqldump -p -u $(awk -F"'" '/DB_USER/{print $4}' wp-config.php) $(awk -F"'" '/DB_NAME/{print $4}' wp-config.php) > $(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).$(whoami).$(date +%F).sql" 
		fi
	   if test -f "config/settings.inc.php"; 
	   then
	     	{
		clear
		if test -f "config/settings.inc.php"; then echo "This is Prestashop $(awk -F"'" '/PS_VERSION/{print $4}' config/settings.inc.php) installed on $(awk -F"'" '/PS_CREATION_DATE/{print $4}' config/settings.inc.php)" ;fi 
		echo "Password for $(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php) is $(awk -F"'" '/DB_PASSWD_/{print $4}' config/settings.inc.php)"
		echo "mysqldump -p -u $(awk -F"'" '/DB_USER/{print $4}' config/settings.inc.php) $(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php) > $(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php).$(whoami).$(date +%F).sql"
		} 
		fi
	 if test -f "configuration.php"; then 
	 {
	clear
	    echo "This is Joomla"
	    echo "DB Username"
	    echo -e "$(grep  'public $user = ' configuration.php)" | awk {'print $4'}
	     echo "DB Password"
	    echo -e "$(grep  'public $password = ' configuration.php)" | awk {'print $4'}
	     echo "DB Name"
	    echo -e "$(grep  'public $db = ' configuration.php)" | awk {'print $4'}
	 }
	fi
		if test -f "moodle/config.php"; then echo "This is Moodle. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "app/etc/env.php"; then echo "This is Magento. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "include/connect.php"; then echo "This is PHP. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "index.html"; then echo "This is HTML. I got nothin as of $(date +%F)  ¯\_(ツ)_/¯ " ;f
	   fi
	   echo "mysqldump -p -u user database_name > backup.sql" 
	}
```



<h1>Non Root</h1>

#checks for all conns in cpanel acess logs
```
domain_access()
{
echo "IP_Address Date/Time Site_Page for $1" | column -t
cat ~/access-logs/$1 | awk {'print $1,$4,$7'} | uniq -c | sort -hr
}
```

#Same thing, but for all domains
```
all_domain_access()
{
echo "$1" | column -t
cat ~/access-logs/*.com | awk {'print $1,$4,$7'} | uniq -c | sort -hr
}
clear ; for i in $(ls -lah ~/access-logs/ | awk {'print $9'}); do all_domain_access $i  ; done
```


#view bots on all sites 
```
for i in $(ls -l ~/access-logs/ | awk {'print $9'}); do  echo $i  ; grep -i bot ~/access-logs/$i   2>/dev/null| awk {'print $1,$14'} | uniq; done```
```

#creates deny rule based on any useragent identifying as a bot

```
{
	cp -v .htaccess{,.bak_$(date +%F)}
	for i in $(cat ~/access-logs/*  | grep -i bot | awk {'print $1'} | uniq); do echo "deny from $i" >> .htaccess ; done
	tail .htaccess | grep deny
}
```

<h2>Misc</h2>
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


##runs 2 applications at the same time
#usage split_em command_1 command_2
```
split_em()
{
tmux new-session \; \
  send-keys "$1" C-m \; \
  split-window -v \; \
  send-keys "$2" C-m \;
}
```



##brief scan of root logins/rootkits
```
(
yum install rkhunter -y
screen -dmS rkhunter_$(date +%F) rkhunter -c 
clear
echo "Root logins using ssh keys"
grep -i "Accepted publickey " /var/log/secure | awk {'print $1,$2,$3,$11'}
echo "Root logins using password"
grep -i "Accepted password " /var/log/secure | awk {'print $1,$2,$3,$11'}
echo "remote servers that have created authorized keys. "
cat .ssh/authorized_keys | awk '{print $3}'
echo "current processes"
pstree 
echo "users that have  UID/GID of 0"
grep -i " 0 " /etc/group
echo "Exploits in /dev/shm or /tmp" 
ls -lah /dev/shm/ /tmp
)
```

