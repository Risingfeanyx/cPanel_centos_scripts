<h2>A collection of my commonly used cPanel/Centos scripts </h2>

#To be used in a root env; you'd create a targz of a cpanel account, and move it to a sites public_html. 
#Usage back userna5 domain.com

```
back(){
	/scripts/pkgacct $1
	mv /home/cpmove-$1.tar.gz /home/$1/public_html
	chmod 644 /home/$1/public_html/cpmove-$1.tar.gz
	echo "$2/cpmove-$1.tar.gz" | mail -s "Backup Generated" $3
	clear
	}
```

#Creates a list of email accounts based on an existing text file. The text files only need the 'user' section of user@domain.com

```
 for i in $(cat userlist); do /scripts/addpop "$i"@domain.com $(date | md5sum) 50 ; done
```
#The same thing, but for all domains on your server

```
 for i in $(cat userlist); do /scripts/addpop "$i"@$(for a in /var/named/*.db; do echo $(basename $a .db); done) $(date | md5sum) 50 ; done
```

#And to remove them as well, solely for testing purposes

```
for i in $(cat userlist); do /scripts/delpop "$i"@domain.com ; done
```


#Creates two screens, one to spin up a backup for all your users, and another to run cPanel updates, both email you out once finished.
#usage $email@address


```
backup_update_email() 
	{
	clear;
	screen -dmS Backups_$(date +%F) /usr/local/cpanel/bin/backup --force ;
	echo "Backups for $(cat /etc/userdomains | awk {'print $2'} | grep -v nobody | sort -n | uniq) located at $(ls /home/*.tar.gz)" | mail-s "Backup Notification for $(hostname) on $(date +%F)" $1 ;  
	screen -dmS Updates_$(date +%F) /scripts/upcp --force && echo "$(hostname) bumped up to $(/usr/local/cpanel/cpanel -V)" | mail -s "cPanel Upgraded" $1;
	screen -ls;
	}
```


#in a non-root environment, kills cons for a non-root user

```
bounce_shared_user()
	{
	ps faux | grep $1 >> $1_pre_bounce_$(date +%F)
	check_software $1
	account-review $1
	sudo /opt/sharedrads/suspend_user $1 -r billing
	sudo /opt/sharedrads/unsuspend_user $1
	switch $1
	} 
```

#In a root env, kills cons for user. 

```
bounce_vps_user()
	{
	ps faux | grep $1 >> $1_pre_bounce_$(date +%F)
	check_software $1
	account-review $1
	sudo /scripts/suspendacct $1
	sudo /scripts/unsuspendacct $1
	su $1
	} 
```

#In a Virtuozzo environment, eyeballs the logs relating to a container, waits to reboot if needed.

```
bounce_vps_CTID ()
{
	clear
	echo "##What's that VPS$1 doing"
	sudo cat /var/log/messages | grep $1 | tail -5
	echo "##Is VPS$1 suspended?"
	grep $1 /var/log/suspension.log/messages; echo "##Has VPS$1 moved   away?"
	cat /opt/vzmigrate/$1.log/messages ; 
	echo "##Is VPS$1 moving away?"
	ls -l /opt/vzmigrate/inprogress/$1
	echo "##Is VPS$1 napping? alive? full? Lets find out!"
	vzlist -a -o veid,hostname,ip,status,laverage,description,diskspace,diskinodes | grep $1
	read -p "Press Enter to reboot $1"
	suspend_vps -r test $1
	unsuspend_vps $1
}
```


#IPs connecting/accessing your cpanel in a non-root env

```
clear ;  sudo cat  /usr/local/cpanel/logs/access_log | grep 'POST\|$userna5\|pass' | grep -v cx.ip.add.ress
```


#restart all cpanel services
```
for f in /scripts/restartsrv_*; do "$f" -H ; done
```


#Test HTTP codes/A records/whois info on all domains on your server

https://developer.mozilla.org/en-US/docs/Web/HTTP/Status

```
for i in $(for a in /var/named/*.db; do echo $(basename $a .db); done); do echo $i ; curl -o /dev/null --silent --head --write-out '%{http_code}\n' $i ; dig a $i +short ; whois $i | grep 'Name Server\|Expiry\|Domain Status' ; done
```





#Can't find your blocked ip in a fail2ban env?

```
f2b(){
clear;
unblock $1
tail -n 5 /var/log/fail2ban.log $1
sudo cat /var/log/maillog | grep 'auth failed' | grep $1
sudo cat /var/log/exim_mainlog | grep 'authenticator failed' | grep $1
sudo cat /usr/local/apache/logs/error_log | grep -E 'id "(13052|13051|13504|90334)"' $1
#sudo cat /var/log/messages grep $1
}

```

#History of all IPs that have accessed your cPanel

```
 for i in $(sort /usr/local/cpanel/logs/session_log | grep $(date +%F) | awk '{print $6}' | uniq -u) ; do curl ipinfo.io/"$i" ; done
```



#Force HTTPS in a .htaccess file

```
	{
	clear
	cp .htaccess{,.pre_https_$(date +%F)}
	sed -i '1 i\RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' .htaccess
	sed -i '1 i\RewriteCond %{HTTPS} off ' .htaccess
	sed -i '1 i\RewriteEngine On' .htaccess
	}
```

#sends mail out to a test email of your choosing, and watches the logs for it. 
#Syntax: mailtest test@domain.com
```
mailtest()
  {
	echo "This is a test email sent on $(date '+%F') by a member of the Technical Support team. Replies are not monitored. Please ignore." | mail -s  "Email Test Support" $1; 
	clear ;
	sudo tail -f /var/log/exim_mainlog | grep $1
	}
```

#What is going on with mysql?
#Creates db backups as well
```
mysql_bandaid()
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


#Glance at all error logs for an IP
#ROOT/VPS
#Syntax: 'err $IP_ADDRESS'

```
err()
	{
	clear
	sudo grep $1 cat /var/log/messages | tail -1
	sudo grep $1 cat /usr/local/apache/logs/error_log | tail -1
	sudo grep $1 cat /var/log/nginx/error.log | grep | tail -1
	sudo grep $1 cat /usr/local/cpanel/logs/access_log | tail -1
	sudo grep $1 cat /var/log/secure | tail -1
	sudo grep $1 cat /usr/local/cpanel/logs/login_log | tail -1
	}
```

#NON ROOT/SHARED

```
err()
	{
	clear
	sudo cat /var/log/messages | grep $1 
	sudo cat /usr/local/apache/logs/error_log | grep $1 
	sudo cat /var/log/nginx/error.log | grep $1 grep | grep $1 
	sudo cat /usr/local/cpanel/logs/access_log | grep $1 
	sudo cat /var/log/secure | grep $1 
	sudo cat /usr/local/cpanel/logs/login_log | grep $1 
	}
```

#need a root WHM login?


```
clear ; /usr/local/cpanel/bin/whmapi1 create_user_session user=root service=whostmgrd | grep url
```


#WIP SITE MOVER. TODO: automate search-replacing

```
##1 is the destination docroot. Don't forget to search-replace
doc_mover()
	{
	wp db export&
	tar -caf "OG.$(date +%F).tar.gz" *
	clear
	rsync -azPv  OG.$(date +%F).tar.gz ~/$1/.
	cd ~/$1
	tar -xvzf OG.$(date +%F).tar.gz
	}
```

#Best run in a screen, watches a domain and outputs to a text file

```
site_watch()
	{
	clear;
	echo $1 >> site_watch_$1.txt;
	echo $(date) >> site_watch_$1.txt;
	wget --server-response wget -r -np -R "index.html*" $1 2>&1 | awk '/^  HTTP/{print $2}' >> $HOME/site_watch_$1.txt;
	clear ; 
	cat $HOME/site_watch_$1.txt;
	}
```


#Tests serving functionality of server. Be in docroot of site; usage is testpage $domain.tld

```
testpage()
	  {
	 clear
	 echo "This is a test page created on $(date '+%Y-%m-%d') by a member of the Technical Support team." >> testpage
	 echo ""https://$1/testpage""
	 curl -LA "foo"  $1/testpage
	 }
```

#Yet another DNS wrapper. (it crashes when indented, one of these days I'll figure out why)

```
trackDNS()
{
clear
IP=$(dig a $1 +short)
NSIP=$(dig ns $1 +short)
MX=$(dig mx $1 +short)
TXT=$(dig txt $1 +short)
RED='\033[0;31m'
NC='\033[0m' # No Color
clear
echo -e "${RED}IP INFORMATION for $1 ${NC}"
curl ipinfo.io/$IP
echo -e "${RED}Auth A, MX and TXT records  @$NSIP for $1 ${NC}"
dig a $1 @$NSIP  +short
dig mx $1 @$NSIP +short
dig txt $1 @$NSIP  +short
echo -e "${RED}REGISTRY for $1 ${NC}"
whois $1 | grep 'Name Server\|Expiry\|Domain Status'
curl -IL  $1 | head -1
ping -c4 $1
traceroute $1
}
```

#Wordpress backup/info

```
wpinfo()
	{
	clear
	wp cache flush&
	wp db size
	wp db repair&  --skip-{plugins,themes}; 
	wp core verify-checksums&  --skip-{plugins,themes};
	wp db export --skip-{plugins,themes};
	cp .htaccess{,.bak_$(date +%F)};
	cp php.ini{,.bak_$(date +%F)};
	cp wp-config.php{,.bak_$(date +%F)};
	wp core version --skip-{plugins,themes};
	##developer.wordpress.org/cli/commands/
	##Set Permalinks to Default
	##wp option update permalink_structure ""
	#wp config set WP_DEBUG true
	#wp plugin deactivate --all --skip-{plugins,themes};
	#echo "define( 'WP_MEMORY_LIMIT', '512M' );" >> wp-config.php;
	awk -F"'" '/DB_/{print $4}' wp-config.php;
	cat wp-config.php | grep is_multisite
	pwd ; ls *bak_* *.sql
	}
```

#Update dns zone for all domains on server

```
clear; for a in /var/named/*.db; do /scripts/dnscluster synczone $(basename $a .db); done

```
