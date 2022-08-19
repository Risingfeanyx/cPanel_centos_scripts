<h1>A collection of my commonly used cPanel/Centos scripts </h1>


<a href="#cpanel" 
target="_blank">cPanel</a>

<a href="#disk-usage" 
target="_blank">Disk Usage</a>

<a href="#dns"
target="_blank">DNS</a>

<a href="#email" 
target="_blank">Email</al>


<a href="#firewall" 
target="_blank">Firewall</a>

<a href="#non-root" 
target="_blank">Non-Root</a>

<a href="#php" 
target="_blank">PHP</a>

<a href="#sql" 
target="_blank">SQL</a>

<a href="#testing" 
target="_blank">Site Testing</a>

<a href="#wordpress" 
target="_blank">Wordpress</a>

<a href="#vz" 
target="_blank">vz</a>


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

in progress, watches common logs for string. todo: enable choosing local variables, echo logname

```

watch_logs()
{
clear
cat << END
  Apache Access /usr/local/apache/domlogs/* 
  Apache Error Log /usr/local/apache/logs/error_log
  cPanel Access /usr/local/cpanel/logs/access_log
  cPanel Error Log /usr/local/cpanel/logs/error_log
  cPanel Logins  /usr/local/cpanel/logs/login_log
  Email Logins /var/log/maillog
  Exim /var/log/exim_mainlog
  Nginx /var/log/nginx/access.log
  Nginx Error Logs /var/log/nginx/error.log
  SSH/FTP /var/log/messages
  SSH Secure /var/log/messages
END
tail -f /usr/local/apache/domlogs/* /usr/local/apache/logs/error_log /usr/local/cpanel/logs/access_log /usr/local/cpanel/logs/error_log /usr/local/cpanel/logs/login_log /var/log/maillog /var/log/exim_mainlog  /var/log/nginx/access.log /var/log/nginx/error.log /var/log/messages /var/log/messages | grep $1
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
echo -e "${GREEN}Last 5 Out of Memory Errors${NC}\n"
grep OOM /var/log/messages | tail -n5
echo -e "${GREEN}PHP-FPM maxing out from ${NC}\n"
tail -n2 /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log
echo -e "${GREEN}Current Server-wide PHP-FPM Values${NC}\n"
grep 'pm_max_children\|pm_max_requests\|pm_process_idle_timeout' /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml
echo -e "${GREEN}Current Domain-Specific PHP-FPM Values${NC}\n" 
egrep "max_children|max_requests|idle_timeout" /var/cpanel/userdata/*/*.php-fpm.yaml
echo -e "${GREEN}Apache Errors ${NC}\n"
tail -n2 /usr/local/apache/logs/error_log 
echo -e "${GREEN}Nginx Errors${NC}\n"
tail -n2 /var/log/nginx/error.log
echo -e "${GREEN}Top 5 Apache  domain connections per site today ${NC}\n"
for i in $(for user in $(awk -F: '{print $1}' /etc/trueuserowners); do uapi --user="$user" DomainInfo list_domains; done | awk '/ -/ || /main_domain/{print $2}');  do echo -e "\n $i"; sort /home/*/access-logs/* | grep $i  | grep $(date +"%d/%b/%Y") | awk '{print $1,$4,$7,$11}'|  uniq -c | sort -hr | head -n5 ; done
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


Update php-fpm values on the fly 
See also
https://api.docs.cpanel.net/openapi/whm/operation/php_fpm_config_set/
https://api.docs.cpanel.net/openapi/whm/operation/php_fpm_config_get/

https://support.cpanel.net/hc/en-us/articles/360036533754-PHP-FPM-Performance-Tuning-Basics
```
change_php_fpms()
{
  GREEN='\033[0;32m'
  NC='\033[0m' # No Color
  clear
  echo -e "${GREEN}Current Server-wide PHP-FPM Values${NC}\n"
  echo -e "/var/cpanel/ApachePHPFPM/system_pool_defaults.yaml"
  egrep "max_children|max_requests|idle_timeout" /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml
  echo -e "${GREEN}Current Domain-Specific PHP-FPM Values${NC}\n" 
  echo -e "${GREEN}PHP-FPM hitting caps ${NC}\n" 
  cat /opt/cpanel/ea-*/root/usr/var/log/php-fpm/error.log | grep -ia consider
  egrep "max_children|max_requests|idle_timeout" /var/cpanel/userdata/*/*.php-fpm.yaml
  read -erp  "Which files did you need to update? Please paste the full file path Max Children, then the Max Requests " fpm_changes max_children max_requests
  cp -v $fpm_changes{,.bak_$(date +%F)}
  sed -i "/pm_max_children/c\pm_max_children: $max_children" $fpm_changes 
  sed -i "/pm_max_requests/c\pm_max_requests: $max_requests" $fpm_changes 
  /scripts/rebuildhttpdconf
  service httpd restart
  /scripts/php_fpm_config --rebuild
  /scripts/restartsrv_apache_php_fpm
  ngxconf -RrdF && ngxutil -Z
  grep 'pm_max_children\|pm_max_requests\|pm_process_idle_timeout' $fpm_changes
  echo "Backup of that configuration is stored in $fpm_changes.bak_$(date +%F)"
}
````

test said values on a domain, using https://support.cpanel.net/hc/en-us/articles/1500005107141-How-To-display-a-domains-FPM-status-variables

```
test_php_fpms()
{
  clear
  grep documentroot /var/cpanel/userdata/*/$1 | awk {'print $2'}
  cp -v /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml{,.bak_$(date +%F)}
  echo "pm_status_path: /status.phtml" >> /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml
  /scripts/php_fpm_config --rebuild
  echo "<html></html>" >> $(grep documentroot /var/cpanel/userdata/*/$1 | awk {'print $2'})/status.phtml
  /scripts/restartsrv_apache_php_fpm --reload
  curl -LA "php_test" $1/status.phtml?full
}


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
#Same thing, searches by date, format 2 digit month/day/year, as in ##/##


```
login_dates()
{
GREEN='\033[0;32m'
NC='\033[0m' # No Color
clear
echo -e "${GREEN}IP User/Email_User Operating-System Browser ${NC}\n"
echo -e "${GREEN}cPanel_Access${NC}\n" 
grep -a "paper_lantern/index.html" /usr/local/cpanel/logs/access_log | grep "$1" | awk '{print $1,$3,$13,$20}' 
echo -e "${GREEN}Root_WHM_Access${NC}\n"
grep -a "login=1&post_login" /usr/local/cpanel/logs/access_log | grep "$1" | awk '{print $1,$3}' 
echo -e "${GREEN}cPanel_Password_Changes${NC}\n"
grep -a "passwd" /usr/local/cpanel/logs/access_log  | grep "$1" | awk '{print $1,$3,$4}' 
echo -e "${GREEN}Webmail_Access${NC}\n"
grep "%40" /usr/local/cpanel/logs/access_log |grep "$1" | awk '{print $1,$3,$4}' 
echo -e "${GREEN}Webmail_Password_changes${NC}\n"
grep -a passwd_pop /usr/local/cpanel/logs/access_log | grep "$1"| awk '{print $1,$3,$4}' 
echo -e "${GREEN}SSH Access${NC}\n"
 grep -i accepted /var/log/secure | awk '{print $1,$2,$3,$11}' 
} 

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


explode nginx/apache stack. Or "why aren't my changes pushing out?"
```
(
    /scripts/rebuildhttpdconf
    service httpd restart
    /scripts/php_fpm_config --rebuild
    /scripts/restartsrv_apache_php_fpm
	ngxconf -RrdF && ngxutil -Z
)
```

Bots hitting server-wide
```
for i in $(for user in $(awk -F: '{print $1}' /etc/trueuserowners); do uapi --user="$user" DomainInfo list_domains; done | awk '/ -/ || /main_domain/{print $2}');  do echo -e "\n $i"; sort /home/*/access-logs/* | grep $i  | grep 'bot\|crawl\|spider\|80logs'| grep $(date +"%d/%b/%Y") | awk '{print $1,$4,$7,$11}'|  uniq -c | sort -hr | head -n20 ; done
```

<h2>cPanel</h2>

create database

```
(
new_user="$(echo $(whoami)_$(tr -dc a-za </dev/urandom | head -c 5))"
new_pass="$(openssl rand -base64 14 | tr -cd [:alpha:])"
uapi Mysql create_database name="${new_user}"
uapi Mysql create_user name="${new_user}" password="${new_pass}" && uapi Mysql set_privileges_on_database user="${new_user}" database="${new_user}" privileges='ALL PRIVILEGES'
echo "Database credentials are as follows"
echo -e "\n${new_user} \n${new_pass}"
)
```

#list all domains

```
for a in /var/named/*.db; do echo $(basename $a .db); done
```

#list all users
#https://api.docs.cpanel.net/openapi/whm/operation/listaccts/ for more detail about said users

```
modify-account  --list-users
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



##Checks for new autossl certs, creates a nightly cron to do so, moves current cpanel queue and forces a restart. searches todays autossl logs, checks status of latest autossl order 

https://documentation.cpanel.net/display/DD/WHM+API+1+Functions+-+fetch_ssl_certificates_for_fqdns

https://documentation.cpanel.net/display/DD/UAPI+Functions+-+SSL%3A%3Ainstalled_host


```
auto_ssl_kick()
{
  clear
  echo "$(($RANDOM%60)) $(($RANDOM%24)) * * * root /usr/local/cpanel/bin/autossl_check --all" > /etc/cron.d/cpanel_autossl && /scripts/restartsrv_crond
  mv -fv /var/cpanel/autossl_queue_cpanel.sqlite{,_old}
  /usr/local/cpanel/bin/autossl_check_cpstore_queue --force
  /usr/local/cpanel/bin/autossl_check --all
  eval "whmapi1 reset_service_ssl_certificate service="{exim,dovecot,ftp,cpanel}";"
  eval "/scripts/restartsrv_"{exim,dovecot,ftpd,cpsrvd}";"
  /usr/local/cpanel/bin/checkallsslcerts --allow-retry --verbose
}
```

rename existing cert, re-runs autossl service

```
domain_ssl_kick()
{
domain=$1
  clear
  mv /var/cpanel/ssl/apache_tls/$domain/ /var/cpanel/ssl/apache_tls/$domain.$(tr -dc A-Za </dev/urandom | head -c 5).$(date -I)
  /usr/local/cpanel/bin/autossl_check --user=$(/scripts/whoowns $domain)
  grep -EhC3 "$domain|error|WARN" /var/cpanel/logs/autossl/*/txt | tail -n5
  echo "SSL Status for $domain"
  curl -v --stderr - https://www.$domain | grep -A10 "Server certificate"
}
```


Search cpanel logs for most recnet autossl order, check ssl status for single domain

```
 auto_ssl_search()
{
domain=$1
domain_arec=$(/scripts/cpdig $domain a)
    echo -e "\n AutoSSL Logs for $domain"
    grep -EhC3 "$domain|error|WARN" /var/cpanel/logs/autossl/*/txt | tail -n5
    echo "SSL Status for $domain"
    curl -v --stderr - https://www.$domain | grep -A10 "Server certificate"
echo "Forcing HTTPS?"
    curl -sIA securetest $domain | grep Location
echo "Where is  $domain_arec?"
    ipusage | grep $domain_arec| awk {'print $1'}
     whois $domain_arec | egrep 'Organization|OrgName'
}
```

AutoSSL keeps assigning a cert to the wrong domain?

disables this in Tweak Settings 
Choose the closest matched domain for which that the system has a valid certificate when redirecting from non-SSL to SSL URLs. Formerly known as “Always redirect to SSL/TLS” 


When a user visits /cpanel, /webmail, /whm, or visits other URLs that redirect to a cPanel service, the system will redirect to an SSL URL for the closest matched domain that the system has a valid certificate. If you disable this option, the system will redirect to the equivalent URL that they visited based on the original request made via HTTPS or HTTP. This option also controls how the system will redirect unencrypted cPanel, Webmail, WHM, and DAV requests to the best matched certificate for the domain when “Require SSL” is enabled. When enabled, it will redirect closest matched domain that the system has a valid certificate for. When it is disabled, it will simply redirect equivalent HTTPS URL.

Enables this in Tweak Settings
Generate a self signed SSL certificate if a CA signed certificate is not available when setting up new domains. 

When you create a new domain, cPanel will apply the best available certificate (CA signed); otherwise cPanel will apply a self-signed SSL certificate and request a new certificate via AutoSSL if it is enabled. Warning: If you disable this option, and a CA signed certificate is not available, when a user attempts to visit the newly created domain over https, the user will see the first SSL certificate installed on that IP address. Warning: If you enable this option and do not have a CA signed certificate or AutoSSL enabled, Google search results may point to the SSL version of the site with a self-signed certificate, which will generate warnings in the users’ browser. To avoid both of these concerns, we strongly recommend that you enable AutoSSL.


```
(
cp -v /var/cpanel/cpanel.config{,.bak_$(date +%F)}
sed -i "s/selfsigned_generation_for_bestavailable_ssl_install=0/selfsigned_generation_for_bestavailable_ssl_install=1/g" /var/cpanel/cpanel.config
sed -i "s/alwaysredirecttossl=1/alwaysredirecttossl=0/g" /var/cpanel/cpanel.config
grep alwaysredirecttossl /var/cpanel/cpanel.config
grep selfsigned_generation_for_bestavailable_ssl_install /var/cpanel/cpanel.config
)
```
AutoSSL not generating certs for service subdomains?

Make sure Service subdomain override [?] is disabled


Allow users to create cpanel, webmail, webdisk, cpcalendars, cpcontacts, and whm subdomains that override automatically generated service subdomains


```
(
cp -v /var/cpanel/cpanel.config{,.bak_$(date +%F)}
sed -i "s/proxysubdomainsoverride=1/proxysubdomainsoverride=0/g" /var/cpanel/cpanel.config
)
```

check status of recent autossl orders
```
(
if  grep "order item ID" /var/cpanel/logs/autossl/"$(date -I)"*/txt | awk {'print $8,$12'} ; 
then 
clear
whmapi1 get_autossl_providers | grep -E "Sectigo|LetsEncrypt"
echo "SSL orders from $(date -I)"
grep "order item ID" /var/cpanel/logs/autossl/"$(date -I)"*/txt | awk {'print $8,$12'}
read -rp "Need to check the status of a cPanel SSL order? Paste in the above ID(s) with a space between each ID: " cert
for i in $cert; do 
curl -sLA "foo"  https://store.cpanel.net/json-api/ssl/certificate/order/"$i" | jq
done
else "no new certs for today"
fi
)
```

Want to see if your server qualifies for Lets Encrypt?

https://docs.cpanel.net/knowledge-base/security/guide-to-ssl/#autossl-providers
https://letsencrypt.org/docs/rate-limits/

```
    (
GREEN='\033[0;32m'
NC='\033[0m' # No Color
RED='\033[0;31m'
subdomain_count=$(for user in $(awk -F: '{print $1}' /etc/trueuserowners); do uapi --user="$user" DomainInfo list_domains; done | awk '/ -/ || /main_domain/{print $2}'| wc -l)
domain_count=$(for a in /var/named/*.db; do echo $(basename $a .db); done | wc -l)
clear
whmapi1 get_autossl_providers | grep -E "Sectigo|LetsEncrypt"
if (( "$subdomain_count" <= "100" )) && (( "$domain_count" <= "50" ))
then 
echo -e "$domain_count Domains \n$subdomain_count Subdomains \n ${GREEN} Let's Encrypt! ${NC}\n"
else
echo -e "$domain_count Domains \n$subdomain_count Subdomains \n ${RED} Let's not Encrypt! ${NC} \n see https://letsencrypt.org/docs/rate-limits/ \n https://docs.cpanel.net/knowledge-base/security/guide-to-ssl/#autossl-providers for rate limits:
The Let’s Encrypt provider has the following limitations:
    \nA rate limit of 300 certificate orders every three hours.
    \nA weekly limit of 50 registered domains.
    \nA maximum of 100 subdomains per certificate.
    \nLimits the certificates it issues to a specific set of domains to five certificates per week. After this, Let’s Encrypt blocks any further certificates for that set of domains.
"
fi
)
```

```
```
Generate cPanel logins for each user on server
See below for more info
https://api.docs.cpanel.net/openapi/whm/operation/create_user_session/

```
(
clear
 for i in $(ls /var/cpanel/users |grep -v 'system')
 do echo -e "\n Cpanel login for $i"
 whmapi1 create_user_session user=$i service=cpaneld | grep "url:" | awk '{print $2}' 
 done
 )

 ```
 
 Backup existing server configs/ea profile
 
 https://docs.cpanel.net/whm/scripts/the-cpconftool-script/82/

```
(
  for i in $(/usr/local/cpanel/bin/cpconftool --list-modules); do  /usr/local/cpanel/bin/cpconftool --backup --modules="$i" ; done
  ea_current_to_profile 
)
```


<a href="https://docs.cpanel.net/ea4/basics/the-ea-cpanel-tools-package-scripts/#create-a-new-profile" target="_blank">Back up Ea4 Profile</a> 

```
ea_current_to_profile file.json
```

<a href="https://docs.cpanel.net/ea4/basics/the-ea-cpanel-tools-package-scripts/#provision-an-ea4-profile" target="_blank">Restore Existing Ea4 Profile </a> 


Restore existing Ea4 Profile, excellent to use post migration to a new server. 

```
ea_install_profile --install file.json
```

installs  <a href="https://docs.imunify360.com/command_line_interface/#malware" target="_blank">Imunify</a> , enables scanning for users, starts a scan, outputs details of the scan



```
(
clear
curl -sL https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh | bash -
/usr/share/av-userside-plugin.sh
imunify-antivirus malware user scan
imunify-antivirus malware user list
)
```


<h2>Disk Usage</h2>

See <a href="https://unix.stackexchange.com/a/194058" target="_blank">this</a> for more info on clearing the journal logs based on size/days in usage

largest files over 500M

```
{
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color
clear
echo -e "These are the largest files over 500M for $(hostname) as of $(date)"
df -hT -xtmpfs -xdevtmpfs
echo -e "\n${GREEN} Logs ${NC}"
find /var/log/ -size +500M -exec ls -hsS1 {} +
journalctl --disk-usage
echo -e "Run the following to clear logs older then X days \njournalctl --vacuum-time=Xd"
echo -e "\n${GREEN} Backups ${NC}"
find /backup*/ -size +500M -exec ls -hsS1 {} +
echo -e "\n${GREEN}Backups outside of /backup directory${NC}"
find /home/ -type f \( -iname \*.tar.gz -o -iname \*.zip \) -size +500M -exec du -sh {} \; | grep -vE "(/var|/usr|/root|/opt|cpbackup|\.cpanm|\.cpan)" |sort -h
echo -e "\n${GREEN} Databases ${NC}"
mysql << EOF
SELECT table_schema AS "Database", 
ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)" 
FROM information_schema.TABLES 
GROUP BY table_schema;
EOF
echo -e "\n${GREEN} Home Directories ${NC}"
find /home*/  -not -path "/home/virtfs/*" -size +500M -exec ls -hsS1 {} +
}
```



Uses find, largest files over a pre-set amount, #M or #G

```
diskusage()
{
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color
clear
echo -e "These are the largest files over $1 for $(hostname) as of $(date)"
df -hT -xtmpfs -xdevtmpfs
echo -e "\n${GREEN} Logs ${NC}"
find /var/log/ -size +$1 -exec ls -hsS1 {} +
journalctl --disk-usage
echo -e "Run the following to clear logs older then X days \njournalctl --vacuum-time=Xd"
echo -e "\n${GREEN} Backups ${NC}"
find /backup*/ -size +$1 -exec ls -hsS1 {} +
echo -e "\n${GREEN}Backups outside of /backup directory${NC}"
find /home/ -type f \( -iname \*.tar.gz -o -iname \*.zip \) -size +$1 -exec du -sh {} \; | grep -vE "(/var|/usr|/root|/opt|cpbackup|\.cpanm|\.cpan)" |sort -h
echo -e "\n${GREEN} Databases ${NC}"
mysql << EOF
SELECT table_schema AS "Database", 
ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)" 
FROM information_schema.TABLES 
GROUP BY table_schema;
EOF
echo -e "\n${GREEN} Home Directories ${NC}"
find /home*/  -not -path "/home/virtfs/*" -size +$1 -exec ls -hsS1 {} +
}

```


##same as above, just emails out 
diskusage $size $email

```
diskusage()
{
clear
mail -s  "Disk Usage Report" -r usage@"$(hostname)" "$2" << END
This is the  current disk usage  for $(hostname) as of $(date) above $1

Logs
$(find /var/log/* -size +$1 -exec ls -hsS1 {} +)
journalctl --disk-usage

Home Directories
$(find /home*/ -size +$1 -exec ls -hsS1 {} +)

Backups
$(find /backup*/* -size +$1 -exec ls -hsS1 {} +)
$(df -h)

Current Database sizes
$(mysql << EOF
SELECT table_schema AS "Database", 
ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)" 
FROM information_schema.TABLES 
GROUP BY table_schema;
EOF
)
END
}


```



narrow down highest amount of inode usage, change directory to that folder
```
{
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


<h2>DNS</h2>

Explanation of mail related DNS

```
SPF (Sender Policy Framework) record:
	This protects the envelope sender address used for message delivery. SPF allows you to create a policy and dictate a list of authorized senders. This means that only those on the list are able to be authenticated by any receiving server checking for spoofing. Upon a successful check, the email is assumed to be legitimate. If the check is unsuccessful, the email is considered fake and dealt with according to how the SPF policy is set up. Looking over yours, I see it doesn't actually exist.
	A SPF record needs to have your current IP address in order to validate, and not trip any kind of SPF based spam filter. As with all DNS modifications, this can take up to 24 hours to take effect.

DMARC(Domain-based Message Authentication and Conformance)
	is a record that is defined in the DNS records associated with your domain name. 
	The DMARC record contains a set of rules that work with SPF and DKIM records to best provide security for your email. 
	The record also lets mail service providers like Gmail or Yahoo! know that the domain is using DMARC rules.

MX (Mail exchanger) 
	are DNS entries that indicate where email is being processed. If you are using the default settings for both hosting your website and handling your email, then you don’t need to change the MX records. However, if you intend to keep your old email service after moving your website, or if you want to use a third party service (e.g. Gsuite, Microsoft Exchange, iCloud), then you will need to make changes to the MX records.


(DKIM) DomainKeys Identified Mail  
	is a method for associating a domain name to an email message, thereby allowing a person, role, or organization to claim some responsibility for the message.
	DKIM is an e-mail authentication system that allows for incoming mail to be checked against the server it was sent from to verify that the mail has not been modified. This ensures that messages are actually coming from the listed sender and allows abusive messages to be tracked with more ease.
```


Back up your zone file before running any of these.

```
tar -czf /root/named_backup_$(date +%F).tar.gz /var/named*
ls -lah /root/named_backup_$(date +%F).tar.gz
```



#test HTTP codes for all domains on server (will rebuuld as a function to take in arguments to specify dns record types 

```
for i in $(for a in /var/named/*.db; do echo $(basename "$a" .db); done); do echo "$i" ; curl -o /dev/null --silent --head --write-out '%{http_code}\n' "$i" ; dig @ns ns "$i" +short  ; echo https://www.whatsmydns.net/#NS/"$i";  done
```

#add dmarc/SPF records to one  domain, show proptime

#Example <a href="https://support.cpanel.net/hc/en-us/articles/1500000323641-How-to-add-a-DNS-record-to-a-domain-using-the-WHM-API-" target="_blank">Docs</a>

#Full  <a href="https://documentation.cpanel.net/display/DD/WHM+API+1+Functions+-+addzonerecord" target="_blank">API Docs </a>

#This does NOT factor in dedicated IP addresses, in other words, it references the servers IP address itself


    v=DMARC1 specifies the DMARC version
    p=none specifies the preferred treatment, or DMARC policy
	
    none: treat the mail the same as it would be without any DMARC validation
    quarantine: accept the mail but place it somewhere other than the recipient’s inbox (typically the spam folder)
    reject: reject the message outright

    rua=mailto:dmarc-user@tld.com is the mailbox to which aggregate reports should be sent
    ruf=mailto:dmarc-yser@tld.com is the mailbox to which forensic reports should be sent
    pct=# is the percentage of mail to which the domain owner would like to have its policy applied



```
SPF()
{
cp -v /var/named/$1.db{,.bak_$(date +%F)}
whmapi1 addzonerecord domain=$1 name=$1 class=IN ttl=86400 type=TXT txtdata="v=spf1 +mx +a +ip4:$(hostname -i) ~all "
echo -e "This will take effect globally between $(date -d "+4 hours") and $( date -d "+24 hours")"
echo "$1"
for i in $(dig ns $1 +short |head -n1); do dig @$i txt $1 +short ; done
for i in $(dig ns $1 +short |head -n1); do dig @$i txt _dmarc.$1 +short ; done
echo https://www.whatsmydns.net/#TXT/_dmarc."$1"
echo https://www.whatsmydns.net/#TXT/"$1"
}
```

```

DMARC()
{
 cp -v /var/named/$1.db{,.bak_$(date +%F)}
whmapi1 addzonerecord domain="$1" name="_dmarc.$1." class=IN ttl=86400 type=TXT txtdata='v=DMARC1; p=none'
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
for i in $(for a in /var/named/*.db; do echo $(basename $a .db); done); do SPF $i; DMARC $i done
```

Test/generates DNS information for all domains on server

```


{
clear
for i in $(for a in /var/named/*.db; do echo $(basename "$a" .db); done)
do echo -e " \n $i"
curl -Is $i | head -n 1
dig  any $i +short
for d in A CNAME MX NS PTR SOA SRV TXT CAS ; do  echo https://www.whatsmydns.net/#$d/"$i" ; done 
done
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
domain=$1
sudo tail -f /var/log/exim_mainlog | egrep "$1|$2"&
clear
mail -s "Email Test Support" -r test@"$domain" "$2" << END
This is a test email sent from $domain on $(date '+%Y-%m-%d') by a member of the Technical Support team. 
SPF: $(dig txt  "$domain" +short)
DMARC: $(dig txt "_dmarc.$domain" +short)
MX: $(dig MX "$domain" +short | awk {'print $2'})
This is the MX records IP address: $(dig a $(dig mx "$domain" +short| awk {'print $2'})  +short)
This is the current PTR record: $(dig -x $(hostname -i) +short)
Blacklisted? $(echo http://multirbl.valli.org/lookup/$(dig a $(dig mx "$domain" +short) +short).html)
Replies are not monitored. Please ignore. 
END
clear
echo "sending mail from ""$domain"" to ""$2"""
sudo tail -n10 /var/log/exim_mainlog | grep "$2"&
}
```


<h2>Firewall</h2>
#Can't find why the firewall blocked your IP?
Firewall wrapper for common firewalls CSF,APF,Imunify360, iptables, and CPhulk

```

allfw(){

local ARG1="$1"
local ARG2="$2"
local ARGUMENT="${ARG1:-helpme}"
GREEN='\033[0;32m'
NC='\033[0m' # No Color
RED='\033[0;31m'
YELLOW='\033[0;33m'


unblock_ip()
{
	 echo -e "\n${GREEN}Unblocking "$1" in.....${NC}\n"
	#see https://api.docs.cpanel.net/openapi/whm/operation/flush_cphulk_login_history_for_ips/
	
	echo -e "\n${GREEN}...Cphulk Firewall${NC}"
	whmapi1 flush_cphulk_login_history_for_ips ip="$1"
	/scripts/cphulkdwhitelist  "$1"
	
	echo -e "\n${GREEN}...APF/CSF${NC}"
	[ -f /etc/csf/csf.conf ] && csf -a  "$1" || apf -a  "$1"
     
     #imunify blocks
     #https://docs.imunify360.com/command_line_interface/#whitelist
     echo -e "${GREEN}...in Imunify360; if this is the free version, this will show no output,IP deny/blocking is only available in the paid version.${NC}"
    imunify360-agent whitelist ip add  "$1" 2>/dev/null  || echo "this is the free version of Imunify, which does not allow for whitelisting/blacklisting IP"
    
    #iptables
    echo -e "${GREEN}...in iptables${NC}"
    iptables -vA INPUT -s  $1 -j ACCEPT
}

block_ip()
{
	 echo -e "\n${RED}Blocking "$1" in.....${NC}\n"
	#see https://api.docs.cpanel.net/openapi/whm/operation/flush_cphulk_login_history_for_ips/
	
	echo -e "\n${RED}...Cphulk Firewall${NC}"
	whmapi1 flush_cphulk_login_history_for_ips ip="$1"
	/scripts/cphulkdblacklist "$1" 2>/dev/null
	
	echo -e "\n${RED}...APF/CSF${NC}"
	[ -f /etc/csf/csf.conf ] && csf -d  "$1" || apf -d  "$1"
     
     #imunify blocks
     #hhttps://docs.imunify360.com/command_line_interface/#blacklist
     echo -e "\n${RED}...in Imunify360; if this is the free version, this will show no output, as it failed.${NC}"
    imunify360-agent blacklist ip add  "$1" 2>/dev/null
    
    #iptables
    echo -e "\n${RED}...in iptables${NC}"
    iptables -vA INPUT -s  "$1" -j DROP
}


view_ip()
{
	echo -e "\n${YELLOW}Looking for "$1" in.....${NC}\n"
	#https://api.docs.cpanel.net/openapi/whm/operation/read_cphulk_records/
	echo -e "\n${YELLOW}Cphulk${NC}"
    whmapi1    read_cphulk_records   list_name='black'| grep  "$1"

	echo -e "\n${YELLOW}Fail2ban${NC}"
    tail -n2 /var/log/fail2ban.log | grep  "$1"

	echo -e "\n${YELLOW}SSH/FTP${NC}"
    grep  "$1" /var/log/messages | tail -n2
    grep  "$1" /var/log/secure | tail -n2
    
	echo -e "\n${YELLOW}LFD${NC}"
    grep  "$1" /var/log/lfd.log| tail -n2

	echo -e "\n${YELLOW}Email Logins${NC}"
    grep  "$1" /var/log/maillog | grep 'auth failed' | tail -n2
    
    #failing exim
    grep  "$1" /var/log/exim_mainlog | grep 'authenticator failed' | tail -n2 
 
    #Modsec blocks
	echo -e "\n${YELLOW}ModSecurity${NC}"
    grep  "$1" /usr/local/apache/logs/error_log | grep -E 'id "(13052|13051|13504|90334)"' | tail -n2

    #cPanel blocks
	echo -e "\n${YELLOW}cPanel${NC}"
     grep  "$1" /usr/local/cpanel/logs/access_log /usr/local/cpanel/logs/login_log  /usr/local/cpanel/logs/error_log | grep "FAILED LOGIN" | tail -n2

    #apf/csf logs, requires root
	echo -e "\n${YELLOW}CSF/APF${NC}"
   grep  "$1" /etc/*/*allow* /etc/*/*deny*| tail -n2
	echo -e "\n${YELLOW}iptables${NC}"
	iptables -L -n | grep $1

}




     help_document(){
       cat << EOF
A wrapper for common firewalls 


'allfw allow' will whitelist  in  CSF,APF,Imunify360, iptables, and CPhulk
https://support.cpanel.net/hc/en-us/articles/360058211754-Useful-CSF-Commands
https://docs.imunify360.com/command_line_interface/#whitelist
https://docs.cpanel.net/knowledge-base/security/https://cphulk-management-on-the-command-line/#blacklist-an-ip-address

 'allfw view' will go through logs and find why an IP address was originally blocked. This makes no changes
Fail2Ban: /var/log/fail2ban.log
SSH/FTP: /var/log/messages /var/log/secure
Email Logins: /var/log/maillog 
ModSecurity: /usr/local/apache/logs/error_log
cPanel Logins: /usr/local/cpanel/logs/login_log 

 'allfw deny' will block an IP in each service mentioned above 
EOF
}

   case $ARGUMENT in
      allow )   unblock_ip  "$2" ;;
      view )   view_ip   "$2" ;;
      deny )   block_ip  "$2" ;;	
      * )     help_document ;;
      esac
      }


```

backup existing FW rules from apf/csf and iptables. will implement into above at some point 

```
backup_rules()
{
	fw_backup=fw_backup.$(date -I).tar.gz
	iptables-save > "iptables_rules.$(date -I)"
	[ -f /etc/csf/csf.conf ] && tar -vcaf "$fw_backup" /etc/csf/ || tar -vcaf "$fw_backup" /etc/apf
	tar -vcaf "$fw_backup" "iptables_rules.$(date -I)"
	echo "$([ -f /etc/csf/csf.conf ] && echo "CSF" || echo "APF") and $(iptables -V) rules saved to $fw_backup"
}
```


Easily swap between CSF and APF. 

```
csf_apf_swap(){
# CSF and APF managemnt utility.

  local ARG1="${@}"
  local ARGUMENT="${ARG1:-helpme}"

  help_document(){
    cat << EOF

  [+] APF and CSF firewall manager managemnet wizard
    [-] Allows the cycling of APF and CSF at a whim with the args:
                        \`a2c\`       \`c2a\`

EOF
  }

  remove_apf(){
    # Removes APF firewall maanager
    service apf stop
    chkconfig --del apf
    yum -y remove apf-ded whm-addip
    rm -fr /etc/init.d/apf /usr/local/sbin/apf /etc/apf /usr/local/cpanel/whostmgr/cgi/{apfadd,addon_add2apf.cgi}
    if [[ ! -z $(grep -q add_ip_to_firewall /var/cpanel/pluginscache.yaml) ]];then
      sed '3,/add_ip_to_firewall/d' -i /var/cpanel/pluginscache.yaml
    fi
  }

  remove_csf(){
    # Removes CSF firewall manager
    service csf stop
    chkconfig --del csf
    rm -fr /etc/init.d/csf /usr/sbin/csf /usr/local/cpanel/whostmgr/cgi/configserver
    yum -y remove csf-ded
    if [[ ! -z $(grep -q add_ip_to_firewall /var/cpanel/pluginscache.yaml) ]];then
      sed '3,/configserver_security_firewall/d' -i /var/cpanel/pluginscache.yaml
    fi
  }

  install_apf(){
    # Installs APF firewall manaegr
    yum -y install apf-ded whm-addip
    printf 'add_ip_to_firewall' >> /var/cpanel/resellers
  }

  install_csf(){
    # Installs CSF firewall manager
    yum install -y csf-ded
    printf 'root:0:USE,ALLOW,DENY,UNBLOCK' >> /etc/csf/csf.resellers
    # filter top user
    for user in $(awk -F': ' '{print $2}' /etc/trueuserowners|uniq -c|tail -n1|awk '{print $2}'|xargs);do
      printf '$user:0:USE,ALLOW,DENY,UNBLOCK' >> /etc/csf/csf.resellers
    done
    printf ',software-ConfigServer-csf' >> /var/cpanel/resellers
    sed 's/\(LF_\(PERMBLOCK\|SSHD\|FTPD\|SMTPAUTH\|POP3D\|IMAPD\|CPANEL\) *= *"\)[^"]\+/\11/;s/\(LF_TRIGGER *= *"\)[^"]\+/\13/'   -i  /etc/csf/csf.conf
    wget http://download.configserver.com/csupdate -P /usr/bin/
    chmod +x /usr/bin/csupdate
    perl -i -pe 'y|\r||d' /usr/bin/csupdate
    /usr/bin/csupdate
  }

  csf_to_apf(){
    if [[ ! -z $(which csf) ]];then
      remove_csf
      install_apf
    fi
  }

  apf_to_csf(){
    if [[ ! -z $(which apf) ]];then
      remove_apf
      install_csf
    fi
  }


  case $ARGUMENT in
     c2a )   csf_to_apf  ;;
     a2c )   apf_to_csf ;;
     * )     help_document ;;
  esac
}

```

bulk  change cpanel passwords

```
(
clear
export ALLOW_PASSWORD_CHANGE=1
newpassword="$(openssl rand -base64 14 | head -c13)";
for users in $( cat /etc/userdomains | awk {'print $2'} | grep -v nobody | uniq)
do /scripts/chpass $users $newpassword
echo "$user changed to $newpassword"
done
echo "Test at $(hostname):2083";
) 
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


Scan for anonfox meddled contact emails + created emails, automaticaly removes the contact email entry  and disables cpanel password resets
```
(
  modified=$(grep -EHl 'anonymousfox|smtpfox' /home*/*/.contactemail /home/*/.cpanel/contactinfo /home/*/etc/*/shadow /home/*/etc/*/passwd)
  clear
if  grep -EH 'anonymousfox|smtpfox' /home*/*/.contactemail /home/*/.cpanel/contactinfo /home/*/etc/*/shadow /home/*/etc/*/passwd; then
  echo -e "\n cPanel contact emails modified by AnonymousFox"
  echo 
  echo $modified
  sed -i.cleared '/anonymousfox/d' $modified
  sed -i.cleared '/smtpfox/d' $modified
  whmapi1  set_tweaksetting  key='resetpass' value=0
  for i in $( cat /etc/userdomains | awk {'print $2'} | grep -v nobody | uniq); do  uapi --user=$i Email list_pops |grep -E 'anonymousfox|smtpfox'; 
  done
  echo -e  "\nhttps://support.cpanel.net/hc/en-us/articles/360058051173-What-is-the-anonymousfox-address-on-my-system \nhttps://sucuri.net/guides/anonymousfox-hack-guide/"
else echo "No contact emails have been modified by AnonymousFox"
fi
)

```
Go <a href="https://support.cpanel.net/hc/en-us/articles/360058051173-What-is-the-anonymousfox-address-on-my-system-" target="_blank">here</a>

for loop to run a core verif on all wordpress sites.
```
 clear ; for i in $(find /home/*/ -name wp-config.php | grep -v virtfs); do echo -e "\n$i"; cd $(dirname $i); wp core verify-checksums --allow-root; done
```

Checks for conns for domains
As non root user

```
domain_access()
{
echo "IP_Address Date/Time Site_Page for $1" | column -t
cat ~/access-logs/$1* | awk {'print $1,$4,$7'} | uniq | sort -hr
echo -e "\nIndividual IPs that have accessed $1"
cat  ~/access-logs/$1* | awk {'print $1'} | uniq
}
```

As root user 

```
domain_access()
{
echo "IP_Address Date/Time Site_Page for $1" | column -t
cat /home/*/access-logs/$1* | awk {'print $1,$4,$7'} | uniq | sort -hr
echo -e "\nIndividual IPs that have accessed $1"
cat  /home/*/access-logs/$1* | awk {'print $1'} | uniq
}
```

<h1>Non Root</h1>


#view bots on all sites 
```
for i in $(ls -l ~/access-logs/ | awk {'print $9'}); do  echo $i  ; grep -i bot ~/access-logs/$i   2>/dev/null| awk {'print $1,$14'} | uniq; done
```

#creates deny rule based on any useragent identifying as a bot

```
{
	cp -v .htaccess{,.bak_$(date +%F)}
	for i in $(cat ~/access-logs/*  | grep -i bot | awk {'print $1'} | uniq); do echo "deny from $i" >> .htaccess ; done
	tail .htaccess | grep deny
}
```

Show all IPs connecting to site(s) today

```
{
clear
for i in ~/access-logs/*
do echo -e "\n $i"
grep $(date +%d/%b/%Y) $i | awk {'print $1'}| uniq -c | sort -hr
done
}
```

Show all IPs connecting to site(s) today, along with their browser agents/pages connected
```
{
clear
for i in ~/access-logs/*
do echo -e "\n $i"
grep $(date +%d/%b/%Y) $i | awk {'print $1,$4,$7,$12,$13,$14,$15'}
done
}
```




<h2>PHP</h2>

Beef up PHP settings, run in sites docroot

```
{
cp -v php.ini{,.bak_$(date +%F)}
cat <<EOT >> php.ini
display_errors = On
error_log = $(pwd)/error_log
max_execution_time = 60
max_input_time = 60
max_input_vars = 1000
memory_limit = 512M
post_max_size = 512M
session.gc_maxlifetime = 1440
session.save_path = /tmp
upload_max_filesize =  512M
EOT
}
```

```
	mv -v php.ini{.bak_$(date +%F),}
```
to restore OG file


<h2>SQL</h2>
#clean up InnoDB logfiles. Keep in mind, InnoDB cannot be disabled
#https://dev.mysql.com/doc/refman/5.7/en/innodb-turning-off.html

```
	{
	clear
	tail -n10 /var/lib/mysql/*.err
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


Getting this error?
 The Aria engine must be enabled to continue as mysqld was configured with --with-aria-tmp-tables
 rename them aria log files 

```
(
clear
mkdir aria_old.$(date +%F)
mv -v /var/lib/mysql/aria_log* ~/aria_old.$(date +%F)
systemctl restart mysql
systemctl status mysql
)
```

Enable  MySQL error Logging for $1  hour

```
{
  cp -fv /etc/my.cnf{,.bak_$(date +%F)}
  echo "log-error=/var/log/mysql_error_log" >> /etc/my.cnf
  service mysql restart
  echo "error MySQL log is /var/log/mysql_error_log"
  at now + 1 hour <<END
  cp -fv /etc/my.cnf{.bak_$(date +%F),}
  service mysql restart
END
}
```
enable slow query logs for $1 hours email results to $2
```
slow_query()
{
  cp -fv /etc/my.cnf{,.bak_$(date +%F)}
  touch /var/log/slowqueries
  echo "slow_query_log = /var/log/slowqueries" >> /etc/my.cnf
  echo "slow_query_log_file = /var/log/slowqueries" >> /etc/my.cnf
  chown mysql:mysql /var/log/slowqueries
  systemctl restart mysqld
  at now + $1 hours <<END
cp -fv /etc/my.cnf{.bak_$(date +%F),}
systemctl restart mysqld 
echo "Slow Query Logging has been disabled and is saved to /var/log/slowqueries"  |   mail -s "SQL Slow Query logs for $(hostname)" -r mysql@"$(hostname)" "$2"
END
}
```



Need to search ALL your databases for a certain string?

```
search_db()
{
for i in $(mysql -e 'show databases;' | awk {'print $1'} | grep -v Database)
do 
echo -e "\n All instances of $1 in $i" >> $1_sql_$(date +%F)
mysqldump  "$i" | grep -i "$1"  | tee -a $1_sql_$(date +%F)
done
}



```
searches all instances of filenames/text in files for string
```
search_text()
{
clear
find $(pwd) -name  "*$1*" -print >> $1_results.$(date -I)
grep -rnw $(pwd) -e "*$1*" >> $1_results.$(date -I)
}
```

<h2>Testing</h2>
uses <a href="https://gtmetrix.com/api/docs/2.0/" 
target="_blank">gtmetrix API </a> to  run external report on site

```
test()
{
export GTMETRIX_USER=
export GTMETRIX_KEY=

sites=$1

for site in "${sites[@]}"
do
  echo "starting test for $site"
  test_id=`curl --silent --user ${GTMETRIX_USER}:${GTMETRIX_KEY} --form url=$site --form x-metrix-adblock=0 https://gtmetrix.com/api/0.1/test | jq -r .test_id`

  echo "test id is $test_id"
  state=unknown
  loop_run_time_secs=0

  while [[ "$state" != "completed" && $loop_run_time_secs < 60 ]]
  do
    results=`curl --silent --user ${GTMETRIX_USER}:${GTMETRIX_KEY} https://gtmetrix.com/api/0.1/test/$test_id`
    state=`echo $results | jq -r .state`
    echo -ne "${state} ...\r"
    sleep 6
    loop_run_time_secs=$((loop_run_time_secs + 6))
  done

  page_load_time=`echo $results | jq -r .results.page_load_time`
  html_bytes=`echo $results | jq -r .results.html_bytes`
  page_elements=`echo $results | jq -r .results.page_elements`
  report_url=`echo $results | jq -r .results.report_url`
  html_load_time=`echo $results | jq -r .results.html_load_time`
  page_bytes=`echo $results | jq -r .results.page_bytes`
  pagespeed_score=`echo $results | jq -r .results.pagespeed_score`
  yslow_score=`echo $results | jq -r .results.yslow_score`

  echo -e "`date`\n Site: $site,\n Page Load Time: $page_load_time\n HTML Bytes: $html_bytes \n Page Elements: $page_elements\n HTML Load Time: $html_load_time\n Page Bytes: $page_bytes\n Page Speed Score: $pagespeed_score \n YSlow Score: $yslow_score \n $report_url"
done
}
```

Lists common php values for domain

```
find_php_info()
{
echo "<?php phpinfo(); ?>" >>phpinfo.php
echo $1
echo "Directive LocalValue MasterValue" | column -t
curl -ksLA "foo" $1/phpinfo.php |  lynx -stdin -dump | grep -E "doc_root|memory_limit|allow_url_fopen|disable_functions|display_errors|error_log|max_execution_time|memory_limit" | sort -u 
}

```



<h2>Wordpress</h2>
Does require knowledge of the  <a href="https://developer.wordpress.org/cli/commands/" 
target="_blank">WP CLI</a>

https://developer.wordpress.org/cli/commands/cache/flush/
https://developer.wordpress.org/cli/commands/db/repair/
https://developer.wordpress.org/cli/commands/core/download/
https://developer.wordpress.org/cli/commands/core/verify-checksums/




Wordpress general info/backup crit files/replaces core files
```
{
 wp db export ~/$(date -I).$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).sql --skip-{plugins,themes}&
wp cache flush&
wp db repair&
#wp core download --version=$(wp core version) --force
wp core verify-checksums&
for i in .htaccess php.ini  wp-config.php ; do cp $i{,.$(date +%F).bak}; done
clear
awk -F"'" '/DB_/{print $4}' wp-config.php | head -n3
for i in theme plugin user ; do echo $i for $(wp option get siteurl --skip-{plugins,themes} );  wp $i list --skip-{plugins,themes} ; done
}
```

tests if a users email already exists, if it does, updates the pass, if it does not, creates it


```
test_user()
{


temp_user=$1
newpass=$(openssl rand -base64 16 | tr -cd '[:alnum:]')
wp_db_backup=$(wp eval 'echo DB_NAME;').$(date -I).sql

wordpress_dump()
{
#Wordpress DB creds
  wp_db_backup=$(wp eval 'echo DB_NAME;').$(date -I).sql
  wp_db_pass=$(wp eval 'echo DB_PASSWORD;')
  wp_db_name=$(wp eval 'echo DB_NAME;')
  wp_db_user=$(wp eval 'echo DB_USER;')

  clear
  echo "This is a Wordpress site"
  echo "backing up database to ~/$wp_db_backup"
  mysqldump -p"$wp_db_pass" -u "$wp_db_user" "$wp_db_name" > ~/"$wp_db_backup"
}



create_user()
{
if [[ $(wp user list --skip-{plugins,themes} --field=user_email | grep "$temp_user") = "$temp_user" ]]; 
then
  wp user update "$temp_user" --user_pass="${newpass}" --skip-{plugins,themes} ;
  echo "New password for $temp_user is $newpass and will expire in 15 minutes"
else
  wp user create test --role=administrator "$temp_user" --skip-{plugins,themes}
fi
echo "wp user delete $temp_user --reassign=1" | at now + 15 minutes 
}

(
if [ -f ~/"$wp_db_backup" ]
then
      echo  "$wp_db_backup already exists"
else
      echo  "$wp_db_backup NOT exist" ; wordpress_dump
fi
)

create_user "$temp_user"

}
```


Takes in error, tests site and loops through existing plugins to verify if said plug is causing the error.

Make sure to put error in double quotes
```
plugin_loop()
{
db=~/testing_plugins.$(date +%F).sql
domain=$(wp option get siteurl --skip-{plugins,themes} | sed 's/https\?:\/\///')
error_text=$1
  wp_db_backup=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).$(date -I).sql
  wp_db_pass=$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)
  wp_db_name=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)
  wp_db_user=$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)
clear
if [ "$( curl -skLA "foo" "$domain" |   lynx -stdin -dump | grep "$error_text")" ];
then
    echo "$domain throwing $error_text"
    wp db export "$wp_db_backup"
    for i in $(wp plugin list --skip-{plugins,themes} --field=name) 
    do echo "disabling $i for $domain"
    wp plugin deactivate "$i" --skip-{plugins,themes}
    echo "testing $domain with $i deactivated"
      if [[ "$(curl -skLA "foo" "$domain" |   lynx -stdin -dump | grep "$error_text")" ]]; then
    wp plugin activate "$i" --skip-{plugins,themes}
    else
    echo "$i was breaking the site"'!'
    wp plugin verify-checksums $i --skip-{plugins,themes}
    echo "backup located at $wp_db_backup"
    break
    fi
    done
       else
        echo "$domain not throwing $error_text"
      fi
}
```

Same thing, but just takes in the domain and spits out the curl output

```
{
db=~/plugins.$(date +%F).sql
clear
read -rp "What is the $domain we are testing?" domain
    wp db export "$db"
    for i in $(wp plugin list --skip-{plugins,themes} --field=name) 
    do echo "disabling $i for $domain"
    wp plugin deactivate "$i" --skip-{plugins,themes}
    echo "testing $domain with $i deactivated"
    curl -sLA "foo" $domain | lynx -stdin -dump | head -n10 
    echo  wp plugin activate "$i" --skip-{plugins,themes}
    echo "backup located at $db"
    done
 }
```

Test site speeds with each plug deactivated

```
(
clear
db=~/plugins.$(date +%F).sql
site=$(wp option get siteurl --skip-{plugins,themes})
    echo "Testing $site speeds"
    wp db export "$db"
    for i in $(wp plugin list --skip-{plugins,themes} --field=name) ;
    do echo "disabling $i for $site"
    wp plugin deactivate "$i" --skip-{plugins,themes} --quiet
    echo "Testing "$site" Response Time with "$i" deactivated"
    curl -ksw "%{time_total}\n" $(wp option get siteurl --skip-{plugins,themes}) -o /dev/null
    wp plugin activate "$i" --quiet
done
   echo "Testing "$site" Response Time with all plugins deactivated"
    wp plugin deactivate "$i" --all --quiet
    curl -ksw "%{time_total}\n" $(wp option get siteurl --skip-{plugins,themes}) -o /dev/null
    wp db import $db
)

```

####Currently WIP, not stable####
Same thing, but saves to a results file and sorts the output from that file to show which plugs are the most resource intensive

```
(
clear
db=~/plugins.$(date +%F).sql
site=$(wp option get siteurl --skip-{plugins,themes} | sed 's/https\?:\/\///')
results=~/results_$(date -I)_$site
    echo "Testing $site speeds"
    wp db export "$db"
    for i in $(wp plugin list --skip-{plugins,themes} --field=name) ;
    do echo "disabling $i for $site"
    wp plugin deactivate "$i" --skip-{plugins,themes} --quiet 
    echo "Testing "$site" Response Time with "$i" deactivated $(curl -ksw "%{time_total}\n" $(wp option get siteurl --skip-{plugins,themes}))" | tee -a $results
    wp plugin activate "$i" --quiet
done
   echo "Testing "$site" Response Time with all plugins deactivated $(wp plugin deactivate "$i" --all --quiet
    curl -ksw "%{time_total}\n" $(wp option get siteurl --skip-{plugins,themes}) )" | tee -a $results
    wp db import $db
    clear
     sort -nk8 $results
)



```


Reset all your Wordpress users passwords. creates a database backup jic
```
{
wp db export
for i in $(wp user list | awk {'print $1'})
do
wp user update $i --user_pass=$(head -c32 /dev/urandom | md5sum | awk {'print $1'})
done
}
```

		

Adds 50 random users for testing. creates db backup as well
```
{
wp db export
for run in {1..50}
do
for a in $(xxd -l 6 -c 32 -p < /dev/random)
do
wp user create $a --role=administrator $a@$a.com --skip-{plugins,themes}&
done
done
wp user list --skip-{plugins,themes}
}
```

lists all dbs+wp docroots using them

```
(
clear
database=$(mysql -e 'show databases;' | awk {'print $1'} | grep -v Database)
for i in $(find /home/*/ -name wp-config.php | grep -v virtfs)
	do echo "$i"
	grep "$database" "$i" |awk {'print $3'}
	done
)
```

Gets Admin URLS for the following
iThemes 
Cerber Security
WPS 
All In One WP Security
Easy Hide Login
rename-wp-login
```
(
wp option pluck itsec-storage hide-backend slug 
wp option pluck cerber-main loginpath
wp option get whl_page 
wp option pluck aio_wp_security_configs aiowps_login_page_slug 
wp option pluck wpseh_l01gnhdlwp slug 
wp option pluck rwl_page 
)2>/dev/null
```


WP CLI failing to return results for a search/search replace?
Creates a database backup, uses sed to run that replacement manually
search_replace old new
```
search_replace()
{
      clear
      wp db search $1
      wp db export  --skip-{plugins,themes} --porcelain ../pre_search.sql
      sed -i 's/$1/$2/g' ../pre_search.sql
      wp db import ../pre_search.sql
      wp db search $1 
}
```






Wordpress site cloner. only arguement required is the destination document root and clone name, in that order . Can only be run within single user
#to do: detect nonstandard wp prefixes/update accordingly
```
wp_clone()
{
destination_root=$1
destination_name=$2
site_backup=$(basename "$PWD").$(date -I).tar.gz
db_backup=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).$(date -I).sql
db_pass=$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)
db_name=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)
db_user=$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)

db_create()
{
db_pref="$(uapi Mysql get_restrictions | grep prefix | awk {'print $2'})"
new_user="$(tr -dc a-za </dev/urandom | head -c 5)"
new_pass="$(openssl rand -base64 14 | tr -cd [:alpha:])"
uapi Mysql create_database name="${db_pref}${new_user}"  2>&1 > /dev/null
uapi Mysql create_user name="${db_pref}${new_user}" password="${new_pass}" 2>&1 > /dev/null
 uapi Mysql set_privileges_on_database user="${db_pref}${new_user}" database="${db_pref}${new_user}" privileges='ALL PRIVILEGES'  2>&1 > /dev/null 
echo "Database credentials are as follows"
echo -e "\n${db_pref}${new_user} \n${new_pass}"
}

##test if destination directory exists
if [ -d "$destination_root" ]
then
      echo  "$destination_root exists"
else
      echo  "$destination_root does NOT exist" ; return 1
fi

##test if WP install
if test -f wp-config.php;
then


echo "backing up database to $db_backup and $site_backup"
     mysqldump -p"$db_pass" -u "$db_user" "$db_name" > "$db_backup"
 echo "zipping up $(pwd)"
 tar -caf "$site_backup" *
  echo "zipping up $destination_root"
      tar -caf ~/$destination_name.$(date -I).tar.gz $destination_root
echo "copying everything over to $destination_root"
rsync -azvP "$site_backup" "$destination_root"
cd "$destination_root" 
tar -xvf "$site_backup"
       mv -f "$site_backup" ~/
##Create databases


(
db_create

##recreate wp-config
  mv -vf wp-config.php{,.bak_$(date +%F)}
wp config create --dbuser="${db_pref}${new_user}" --dbpass="${new_pass}" --dbname="${db_pref}${new_user}"
  
  #import db
mysql -p"$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)" -u "$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)" "$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)" < "$db_backup"

##create wordpress .htaccess file

cat << EOF > .htaccess
# BEGIN WordPress

RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]

# END WordPress
EOF


#update site home/urls
 
wp search-replace "$(wp option get home)" "https://$destination_name " --all-tables || vim -c "/table_prefix" wp-config.php

wp search-replace "$(wp option get siteurl)" "https://$destination_name " --all-tables

##test
  wp option get siteurl --skip-{plugins,themes}
  wp option get home  --skip-{plugins,themes}


)
else
   echo "This is NOT a Wordpress install"
   
fi
}
```




The purpose of this is to automate dumping databases from common CMS's 

Wordpress ✓
Prestashop ✓
Joomla ✓
Drupal ✓
Moodle ✓
CodeIgnitor ✓

	#Laravel coming soon™ 


in progress  | stable so far
```
cms_dump()
{
##universal database dumper

#subshells

presta_dump()
{

#Prestashop DB creds
ps_db_backup=$(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php).$(whoami).$(date +%F).sql"
ps_db_pass=$(awk -F"'" '/DB_PASSWD_/{print $4}' config/settings.inc.php)"
ps_db_name=$(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php)
ps_db_user=$(awk -F"'" '/DB_USER/{print $4}' config/settings.inc.php)
clear 
  echo "This is Prestashop $(awk -F"'" '/PS_VERSION/{print $4}' config/settings.inc.php)"
  echo "backing up database to ~/$ps_db_backup"
  mysqldump -p"$ps_db_pass" -u "$ps_db_user" "$ps_db_name" > ~/"$ps_db_backup"
}

joomla_dump()
   {
     #Joomla DB creds
jl_db_backup=$(grep  'public $db = ' configuration.php | awk {'print $4'} | tr -d "';").$(date -I).sql
jl_db_user=$(grep  'public $user = ' configuration.php | awk {'print $4'} | tr -d "';")
jl_db_pass=$(grep  'public $password = ' configuration.php | awk {'print $4'} | tr -d "';")
jl_db_name=$(grep  'public $db = ' configuration.php | awk {'print $4'} | tr -d "';")

  clear
  echo "This is a Joomla install"
  echo "backing up database to ~/$jl_db_backup"
  mysqldump -p"$jl_db_pass" -u "$jl_db_user" "$jl_db_name" > ~/"$jl_db_backup"
   }

wordpress_dump()
{
#Wordpress DB creds
  wp_db_backup=$(wp eval 'echo DB_NAME;').$(date -I).sql
  wp_db_pass=$(wp eval 'echo DB_PASSWORD;')
  wp_db_name=$(wp eval 'echo DB_NAME;')
  wp_db_user=$(wp eval 'echo DB_USER;')

  clear
  echo "This is a Wordpress site"
  echo "backing up database to ~/$wp_db_backup"
  mysqldump -p"$wp_db_pass" -u "$wp_db_user" "$wp_db_name" > ~/"$wp_db_backup"
}


  drupal_dump()
{
  #Drupal DB creds
dr_db_backup=$(grep -A1 $(whoami)_ sites/default/settings.php | awk {'print $3'} | tr -d "'," | head -n1).$(date -I).sql
dr_db_user=$(grep -A1 $(whoami)_ sites/default/settings.php | awk {'print $3'} | tr -d "'," | head -n1)
dr_db_pass=$(grep -A1 $(whoami)_ sites/default/settings.php | awk {'print $3'} | tr -d "'," | tail -n1)
dr_db_name=$(grep -A1 $(whoami)_ sites/default/settings.php | awk {'print $3'} | tr -d "'," | head -n1)
clear
  echo "This is Drupal"
  echo "backing up database to ~/$dr_db_backup"
  mysqldump -p"$dr_db_pass" -u "$dr_db_user" "$dr_db_name" > ~/"$dr_db_backup"
}

no_dbs()
{
  echo -e "databases currently in $(whoami) \n$(uapi  Mysql list_databases | grep database:| awk {'print $2'}) "
  echo "any conf files in $(pwd) that have DB configs?"
  grep --include='*.php' -lR "$(whoami)_"
}


magento_dump()
{
#Wordpress DB creds
  mag_db_backup=$(awk -F"'" '/dbname/{print $4}' app/etc/env.php).$(date -I).sql
  mag_db_pass=$(awk -F"'" '/password/{print $4}' app/etc/env.php)
  mag_dbname=$(awk -F"'" '/dbname/{print $4}' app/etc/env.php)
  mag_db_user=$(awk -F"'" '/username/{print $4}' app/etc/env.php)

  clear
  echo "This is a Magento 2.0 site"
  echo "backing up database to ~/$mag_db_backup"
  mysqldump -p"$mag_db_pass" -u "$mag_db_user" "$mag_dbname" > ~/"$mag_db_backup"
}




moodle_dump()
   {
     #Joomla DB creds
moodle_db_backup=$(grep  '$CFG->dbname    =' config.php | awk {'print $3'} | tr -d "';").$(date -I).sql
moodle_db_user=$(grep  '$CFG->dbuser    =' config.php | awk {'print $3'} | tr -d "';")
moodle_db_pass=$(grep  '$CFG->dbpass    =' config.php | awk {'print $3'} | tr -d "';")
moodle_db_name=$(grep  '$CFG->dbname    =' config.php | awk {'print $3'} | tr -d "';")

  clear
  echo "This is a Moodle install"
  echo "backing up database to ~/$moodle_db_backup"
  mysqldump -p"$moodle_db_pass" -u "$moodle_db_user" "$moodle_db_name" > ~/"$moodle_db_backup"
   }

codeignitor_dump()
{
#Code Ignitor DB creds
  ci_db_backup=$(awk -F"'" '/database/{print $4}' application/config/database.php).$(date -I).sql
  ci_db_pass=$(awk -F"'" '/password/{print $4}' application/config/database.php)
  ci_db_name=$(awk -F"'" '/database/{print $4}' application/config/database.php)
  ci_db_user=$(awk -F"'" '/username/{print $4}' application/config/database.php)

  clear
  echo "This is a Code Ignitor  site"
  echo "backing up database to ~/$ci_db_backup"
  mysqldump -p"$ci_db_pass" -u "$ci_db_user" "$ci_db_name" > ~/"$ci_db_backup"
}


clear
##test if WP install
  if test -f wp-config.php;
  then wordpress_dump
    
##test if Prestashop install
      elif test -f "config/settings.inc.php"; then  presta_dump
     
##Test if Drupal install
 elif test -f "sites/default/settings.php"; then 
       drupal_dump
##Test if Joomla install
 elif test -f "configuration.php"; then 
       joomla_dump

##test if CodeIgnitor install


##Test if Moodle install
 elif test -f "config.php"; then 
       moodle_dump
       else 
       no_dbs
       fi

}
```


Command line installer for common CMS
todo: automatically connect databases, add in other CMS beyond Wordpress, Prestashop and Joomla

```

cms_download()
{
  local ARG1="${@}"
  local ARGUMENT="${ARG1:-helpme}"
  
  
db_create()
{
db_pref="$(uapi Mysql get_restrictions | grep prefix | awk {'print $2'})"
new_user="$(tr -dc a-za </dev/urandom | head -c 5)"
new_pass="$(openssl rand -base64 14 | tr -cd [:alpha:])"
uapi Mysql create_database name="${db_pref}${new_user}"  2>&1 > /dev/null
uapi Mysql create_user name="${db_pref}${new_user}" password="${new_pass}" 2>&1 > /dev/null
 uapi Mysql set_privileges_on_database user="${db_pref}${new_user}" database="${db_pref}${new_user}" privileges='ALL PRIVILEGES'  2>&1 > /dev/null 
echo "Database credentials are as follows"
echo -e "\n${db_pref}${new_user} \n${new_pass}"
}

install_prestashop()
{
TMPFILE=`mktemp`
PWD=`pwd`
wget "https://www.prestashop.com/en/system/files/ps_releases/prestashop_1.7.8.6.zip?token=1574e5c379" -O $TMPFILE
unzip -d $PWD $TMPFILE
rm -rf $TMPFILE
db_create
final_steps
}

install_wordpress()
{
db_create
echo "DB:" $new_user;
echo "Pass:" $new_pass;
wp core download
wp config create --dbuser="$new_user" --dbpass="$new_pass" --dbname="$new_user";
final_steps
}

install_joomla()
{
TMPFILE=`mktemp`
PWD=`pwd`
wget "https://downloads.joomla.org/cms/joomla4/4-1-4/Joomla_4-1-4-Stable-Full_Package.zip?format=zip" -O $TMPFILE
unzip -d $PWD $TMPFILE
rm -rf $TMPFILE
db_create
final_steps
}

final_steps()
{
cat << EOF

Don't forget to connect the CMS to the database
echo "DB:" $new_user;
echo "Pass:" $new_pass;
Wordpress does this automatically, howevor, the others do not.
Navigate to the domain to finish any other required steps
EOF
}

  help_document(){
    cat << EOF

Universal CMS installer 
Allows the installation/database creation of the following Content Management Systems. 

wordpress
https://wordpress.org/news/category/releases/

joomla
https://www.joomla.org/announcements/release-news.html

prestashop
https://github.com/PrestaShop/PrestaShop/releases
drupal
https://www.drupal.org/project/drupal/releases
EOF
}

  case $ARGUMENT in
     wordpress )   install_wordpress  ;;
     joomla )   install_joomla  ;;
     prestashop )   install_prestashop ;;
     drupal )   install_drupal;;
     * )     help_document ;;
  esac
}
```

<h2>vz</h2>


Restarts CT, checks proc logs following restart
```
vps_bounce()
{  
  clear
  suspend_vps "$1" -r billing
  unsuspend_vps "$1"
  vzctl enter "$1"
  ps aux | grep "$1"
  ps aux|grep '/vz/root/$1'
}
```


checks all logs for CT issues. 
```
vps_logs()
{
  clear
  echo "/var/log/messages for $1"
  sudo cat /var/log/messages | grep "$1" | tail -5
  echo "suspension log for $1"
  sudo cat /var/log/messages | grep "$1" | tail -5
  echo "migration logs for $1"
  cat /opt/vzmigrate/"$1".log/messages
  ls -l /opt/vzmigrate/inprogress/"$1"
  echo "status for $1"
  vzlist -a -o veid,hostname,ip,status,laverage,description,diskspace,diskinodes | grep "$1"&
  ps aux | grep "$1"
  ps aux|grep '/vz/root/$1'
}
```

makes a snapshot,  enters CT, makes things a bit smoother

```
vps_enter()
{
  clear
  snapshot --create $1
  snapshot --list $1
  vzlist $1 -o veid,hostname,ip,status,laverage,description,diskspace,diskinodes 
  vzctl enter $1
  exit
}

```



#sets up ssh keys, rsyncs data

```
rsync_between_servers()
	{
	destination_server=$1
	keypair=~/.ssh/intmig
	clear
	read -rep "What is the FROM and TO data?" origin_data destination_data
	clear
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color
	clear
	  echo -e 'y\n' | ssh-keygen -t rsa -N "" -f $keypair > /dev/null
	  echo -e "Paste this into ~/.ssh/authorized_keys on $destination_server \n ${GREEN} $(cat $keypair.pub)${NC}\n" 
	  echo -e "Don't forget permissions \nchmod 700 ~/.ssh/; \nchmod 600 ~/.ssh/authorized_keys"
	  echo -e "Whitelist $(hostname -i) on $destination_server"
	  read -p "Press enter once  $destination_server is whitelisted"
	  echo "Logging in"
	  ssh -i $keypair  $destination_server
	  echo -e "Run the following to SSH back in \n"ssh -i $keypair  $destination_server" "
	  echo -e "Run the following to sync data if any was chosen  \n"rsync -zvaPe "ssh -i $keypair" $origin_data $destination_server:$destination_data" "
	}
```
