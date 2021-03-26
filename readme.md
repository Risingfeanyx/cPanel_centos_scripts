<h2>A collection of my commonly used cPanel/Centos scripts </h2>

#To be used in a root env; you'd create a targz of a cpanel account, and move it to a sites public_html. 
#Usage back userna5 domain.tld email@domain.com

#save manpages for every command your user can run in one file
```
for i in $(compgen -c | sort -h); do man "$i" >> man.pages."$(date +%F)"; done
```

```
back(){
	/scripts/pkgacct "$1"
	mv /home/cpmove-"$1".tar.gz /home/"$1"/public_html
	chmod 644 /home/"$1"/public_html/cpmove-"$1".tar.gz
	echo "$2/cpmove-$1.tar.gz" | mail -s "Backup Generated" "$3"
	clear
	}
```

#Want to back up all your  <a href="https://documentation.cpanel.net/display/84Docs/The+cpconftool+Script#ThecpconftoolScript-BackupBackupaconfigurationmodule" target="_blank">Root WHM Configs</a> and  <a href="https://documentation.cpanel.net/display/CKB/How+to+Run+a+Manual+Backup" target="_blank">cPanel users</a>?


```
(
	clear
	for i in $(/usr/local/cpanel/bin/cpconftool --list-modules); do  /usr/local/cpanel/bin/cpconftool --backup --modules="$i" ; done
	/usr/local/cpanel/bin/backup --force
)
```

#Creates a list of email accounts based on an existing text file. The text files only need the 'user' section of user@domain.com. 
#usage email_creation domain.com

```
email_creation()
{
 for i in $(cat userlist); do /scripts/addpop "$i"@$1 $(date | md5sum) 50 ; done
 }
```
#The same thing, but for all domains on your server

```
 for i in $(cat userlist); do /scripts/addpop "$i"@$(for a in /var/named/*.db; do echo $(basename $a .db); done) $(date | md5sum) 50 ; done
```

#And to remove them as well, solely for testing purposes

```
for i in $(cat userlist); do /scripts/delpop "$i"@domain.com ; done
```
#non-root, view IPs connecting to site.

```
sudo cat /usr/local/apache/domlogs/userna5/domain.com | awk {'print $1'}| uniq -c | tail -n100
```


#As of cPanel 86, a known glitch spawning massive amounts of build_locale_da processes. This will kill that, and force an upgrade to $latest_supported version. Glitch went away in 88


```
	{
	clear
	dmesg
	pkill -9 build_locale_da ;
	/scripts/upcp --force ;
	clear
	ps faux | grep build_locale_da
	}
```

#As of cPanel 94, a known glitch which randomly kills dnsadmin.. This can be identifyed by the following error in the /usr/local/cpanel/whostmgr/bin/dnsadmin log


```
(internal error) Timed out while running GETZONES
Died at /usr/local/cpanel/whostmgr/bin/dnsadmin line 794, <$mysock> line 2.
Smartmatch is experimental at /usr/local/cpanel/Cpanel/NameServer/Remote/IMH.pm line 254, <$mysock> line 4.
```

```
whmapi1 set_tweaksetting key='dormant_services'  value='dnsadmin'
```
Then go ahead and restart dnsadmin





#Creates two s, one to spin up a backup for all your users, and another to run cPanel updates, both email you out once finished.
#usage $email@address


```
backup_update_email() 
	{
	clear;
	screen -dmS Backups_$(date +%F) /usr/local/cpanel/bin/backup --force; 
	screen -dmS Updates_$(date +%F) /scripts/upcp --force && echo -e "$(hostname) bumped up to $(/usr/local/cpanel/cpanel -V). \n See https://docs.cpanel.net/changelogs/ for more information" | mail -s "cPanel Upgraded" $1;
	screen -ls;
	}
```

#drop into .bashrc to generate a warning for any users logging in via ssh. will email out from w/e user has been logged in 

```
echo -e "This IP has logged into  $(whoami) at $(who | awk {'print $3,$4'})  \n $(echo $(curl -s ipinfo.io/$(dig a  $(who  | awk '{gsub(/\(|\)/,"");print $5}') +short))) " | mail -s  "$(whoami) SSH alert" -r "$(whoami).alert@$(hostname)" your@email.address	

```

#check processes for only your users

```
for i in $(cat /etc/userdomains | awk {'print $2'} | grep -v nobody | sort -n | uniq); do ps aux | grep -i $i  | grep -v grep; done
```

#generates bandwidth logs for each user, saves to /home/*/tmp/webalizer

```
for username in $(cat /etc/userdomains | awk {'print $2'} | grep -v nobody | sort -n | uniq);do /scripts/runweblogs "$username";done ; clear ; ls  /home/*/tmp/webalizer
```




#In a Virtuozzo environment, eyeballs the logs relating to a container, waits to reboot if needed.

```
bounce_vps_CTID ()
{
	clear
	echo "##What's that VPS$1 doing"
	sudo cat /var/log/messages | grep "$1" | tail -5
	echo "##Is VPS$1 suspended?"
	grep "$1" /var/log/suspension.log/messages; echo "##Has VPS$1 moved   away?"
	cat /opt/vzmigrate/"$1".log/messages ; 
	echo "##Is VPS$1 moving away?"
	ls -l /opt/vzmigrate/inprogress/"$1"
	echo "##Is VPS$1 napping?"
	vzlist -a -o veid,hostname,ip,status,laverage,description,diskspace,diskinodes | grep "$1"
	read -pr "Press Enter to reboot $1"
	suspend_vps -r test "$1"
	unsuspend_vps "$1"
}
```


#IPs connecting/accessing your cpanel in a non-root env

```
sudo cat  /usr/local/cpanel/logs/access_log | grep "POST\|userna5\|pass" | awk {'print $1,$4'} | uniq -c
```
#ditto, in a root env, as shell, curls to ipinfo to pull geo info
```
for i in $(cat /home/*/.lastlogin | awk '{ print $1 }' | uniq -c); do curl ipinfo.io/"$i" ; done
```

#just pulls IPs, date and timestamps

```
cat /home/*/.lastlogin | awk '{ print $1,$3,$4 }' | uniq -c)
```

#What's taking up "Other space" within your  user. Change threshold as needed.

```
du -cahS --threshold=25M --exclude="{cache,etc,logs,perl5, public_ftp,mail,public_html,quarantine,ssl,tmp}"  | sort -hr 
```

#What's taking up "Other Space" for all your users

```
du -cahS --threshold=25M --exclude="{cache,etc,logs,perl5, public_ftp,mail,public_html,quarantine,ssl,tmp}" /home/* | sort -hr
```
#ditto, trash
```
du -cahS --threshold=25M  /home/*/.trash | sort -hr
```

#largest files  for all your users in genereal, capped at 25M

```
for i in $(awk '{print $2}' /etc/trueuserdomains); do echo $i; du -cahS --threshold=25M /home/$i | sort -hr; done
```

#restart all cpanel services
```
for f in /scripts/restartsrv_*; do "$f" -H ; done
```

#view last logs for all systemd services. tack on ```>> systemd.log.$(date +%b)``` to save it

```
for i in $( ls /etc/systemd/system/) ; do systemctl status $i | grep -i "$(date +%b)" ; done
```


#Test HTTP codes/A records/whois on all domains on your server

https://developer.mozilla.org/en-US/docs/Web/HTTP/Status

```
for i in $(for a in /var/named/*.db; do echo $(basename "$a" .db); done); do echo "$i" ; curl -o /dev/null --silent --head --write-out '%{http_code}\n' "$i" ; dig @ns ns "$i" +short  ; echo https://www.whatsmydns.net/#NS/"$i";  done
```

#file breakdown of all users >500M
```
for i in $(ls /home/) ; do du -cahS --threshold=500M $i | sort -hr ; done
```



#Can't find your blocked ip in a fail2ban env?

```
f2b(){
	clear;
	unblock $1
	#fail2ban log
	tail -n 2 /var/log/fail2ban.log $1
	#mail client login fails
	sudo cat /var/log/maillog | grep 'auth failed' | grep $1
	#failing exim
	sudo cat /var/log/exim_mainlog | grep 'authenticator failed' | grep $1
	#Modsec blocks
	sudo cat /usr/local/apache/logs/error_log | grep -E 'id "(13052|13051|13504|90334)"' | grep $1
	#cPanel blocks
	sudo cat 2 /usr/local/cpanel/logs/login_log | grep "FAILED LOGIN" | grep $1
	}

```

#History of all IPs that have accessed your cPanel

```
for i in $(sort /usr/local/cpanel/logs/session_log | grep "$(date +%F)" | awk '{print $6}' | uniq -u) ; do curl ipinfo.io/"$i" ; done
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

#sends mail out to a test email of your choosing from a mailbox of your chooseing, and watches the logs for it. creates an email account for testing.#Syntax: 
localdomain.com to@domain.com. spits out dns information on the test email as well. Stops tailing log after 1 minutes. includes link to multirbl to cover any blacklisting

```
mailtest()
  {
    clear
      /scripts/addpop test@"$1" "$(date | md5sum)" 50
         echo -e "This is a test email sent on $(date '+%Y-%m-%d') by a member of the Technical Support team. \nThese are  the DNS records for ""$1""  \n$(dig any "$1" +short). \nThis is the MX records IP address: $(dig a $(dig mx "$1" +short) +short). \nBlacklisted? $(echo http://multirbl.valli.org/lookup/$(hostname -i).html)
 \nReplies are not monitored. Please ignore." | mail -s  "Email Test Support" -r test@"$1" "$2"
         	clear ;
         		echo "sending mail from ""$1"" to ""$2"""
         			sudo timeout 1m tail -f /var/log/exim_mainlog | grep "$2"
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
				  

use /scripts/delpop to remove test account after



#What is going on with mysql?

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

##loops through all currently existing screens

```
 for i in $(screen -ls | awk '{print $1}') ; do screen -x "$i" ; done
```

#Glance at all error logs for an IP
#ROOT/VPS
#Syntax: 'err $IP_ADDRESS'

```
err()
	{
	clear
	sudo grep "$1" cat /var/log/messages | tail -1
	sudo grep "$1" cat /usr/local/apache/logs/error_log | tail -1
	sudo grep "$1" cat /var/log/nginx/error.log | grep | tail -1
	sudo grep "$1" cat /usr/local/cpanel/logs/access_log | tail -1
	sudo grep "$1" cat /var/log/secure | tail -1
	sudo grep "$1" cat /usr/local/cpanel/logs/login_log | tail -1
	}

#NON ROOT/SHARED

```
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



#need a root WHM login?


```
clear ; whmapi1 create_user_session user=root service=whostmgrd | grep "url:" | awk '{print $2}' 
```

#how about a non-root cpanel login? It will loop through each user on the server, the 'session=' section will give away which user it is. 
```
clear ; whmapi1 create_user_session user=$(cat /etc/userdomains | awk {'print $2'} | grep -v nobody | sort -n | uniq) service=cpaneld | grep "url:" | awk '{print $2}'
```


##To be used within a user; moves site data from one folder to another. 
USAGE: doc_mover original_site_folder new_site_folder

```

doc_mover()
	{
	clear
	mkdir ~/"$2"
	cd "$1" || exit
	tar -cvzf "OG.$1.$(date +%F).tar.gz" *
	clear
	rsync -azPv  "OG.$1.$(date +%F).tar.gz" ~/"$2"
	cd ~/"$2" || exit
	tar -xvzf "OG.$1.$(date +%F).tar.gz"
	clear
	diff ~/"$1" ~/"$2"
	cd || exit
	}
```

#Best run in a screen, watches a domain and outputs to a text file

```
site_watch()
	{
	clear;
	echo "$1" >> site_watch_"$1".txt;
	echo "$(date)" >> site_watch_"$1".txt;
	wget --server-response wget -r -np -R "index.html*" "$1" 2>&1 | awk '/^  HTTP/{print $2}' >> "$HOME"/site_watch_"$1".txt;
	clear ; 
	cat "$HOME"/site_watch_"$1".txt;
	}
```


#Tests serving functionality of server. Be in docroot of site; usage is testpage $domain.tld. As long as both test pages load, then Apache/Nginx is serving correctly. 

```
testpage()
	  {
	 clear
	 echo "This is a test page created on $(date '+%Y-%m-%d') by a member of the Technical Support team." >> testpage
	 echo ""https://"$1"/testpage""
	 curl -LA "foo"  "$1"/testpage
	 }
```
#install redis
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
 ls /etc/cpanel/ea4/is_ea4 |column -t
}
```

#Yet another wrapper. (it crashes when indented, one of these days I'll figure out why)

```
trackDNS()
{
clear
IP=$(dig a "$1" +short)
NSIP=$(dig ns "$1" +short)
MX=$(dig mx "$1" +short)
TXT=$(dig txt "$1" +short)
RED='\033[0;31m'
NC='\033[0m' # No Color
clear
echo -e "${RED}IP INFORMATION for $1 ${NC}"
curl ipinfo.io/"$IP"
echo -e "${RED}Auth A, MX and TXT records  @$NSIP for $1 ${NC}"
dig a "$1" @"$NSIP"  +short
dig mx "$1" @"$NSIP" +short
dig txt "$1" @"$NSIP"  +short
echo -e "${RED}REGISTRY for $1 ${NC}"
whois "$1" | grep 'Name Server\|Expiry\|Domain Status'
curl -IL  "$1" | head -1
ping -c4 "$1"
traceroute "$1"
}
```

#Wordpress backup/info. I run this before EVER touching a wordpress site; makes all relevent backups and deliberately holds up STDIN until its done

```
{
	wp cache flush&
	wp db repair&	
	wp core verify-checksums&
	wp db export&
	cp .htaccess{,.$(date +%F).bak};
	cp php.ini{,.$(date +%F).bak};
	cp wp-config.php{,.$(date +%F).bak};
	clear
	awk -F"'" '/DB_/{print $4}' wp-config.php;
	cat wp-config.php | grep is_multisite
	pwd ; ls *bak_* *.sql
	mv *.sql ..
}
```

#Reinstalls DNS admin, Update dns zone for all domains on server, shows all domains

```
(
yum -y remove imh-cpanel-dnsadmin;rpm -e --nopostun imh-cpanel-dnsadmin;yum clean;yum -y install imh-cpanel-dnsadmin; /usr/local/cpanel/whostmgr/bin/dnsadmin --start; rm -f /var/cpanel/clusterqueue/status/imh{,-down};/usr/local/cpanel/cpkeyclt; 
clear; for a in /var/named/*.db; do /scripts/dnscluster synczone $(basename $a .db); done; 
clear ; for a in /var/named/*.db; do echo $(basename $a .db); done
)
```

Learn who is attempting to access your site
```
for i in $(sort /usr/local/apache/domlogs/*.com  | awk '{print $1}' | uniq -u) ; do  curl ipinfo.io/$i ; done
```

cPanel Attempts

```
for i in $(sort /usr/local/cpanel/logs/access_log  | awk '{print $1}' | uniq -u) ; do  curl ipinfo.io/$i ; done

```


Successfull cPanel logins from today

Want to find out where your blocked IPs are from?

```
for i in $( cat /etc/*/*.deny | awk '{print $1}') ; do curl ipinfo.io/$i ; done
```

How about your whitelisted ones?

```
for i in $( cat /etc/*/*.allow | awk '{print $1}') ; do curl ipinfo.io/$i ; done
```


```
for i in $(sort /usr/local/cpanel/logs/session_log  | grep  $(date +%F) |  awk '{print $6}' |  uniq -u) ; do  curl ipinfo.io/$i ; done
```

Temporarily block those attempting to access cPanel. Make sure you're not blocking  <a href="http://fetchip.com/" target="_blank">yourself</a>
. Might want to run it in a screen/multiplexer. Doesn't exactly require CSF, since it is just firewall rules. Will rewerite for iptables at some point. 

```
for i in $(sort /usr/local/cpanel/logs/access_log  | awk '{print $1}' | uniq -u) ; do csf -td $i "Attempted cPanel Access, blocked on $(date +%F)"; done
```
