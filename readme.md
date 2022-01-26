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
  cat /opt/cpanel/ea-*/root/usr/var/log/php-fpm/error.log | grep -i consider
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


#list all domains

```
for a in /var/named/*.db; do echo $(basename $a .db); done
```

#list all users

```
ls /var/cpanel/users
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


Search cpanel logs for most recnet autossl order, check ssl status for single domain

```
 auto_ssl_search()
{
domain=$1
  if [ "$(dig $domain +short)" == "$(ipusage | grep $domain | awk {'print $1'}
)" ]; then
    echo -e "\n$domain points here $(ipusage | grep $domain | awk {'print $1'}
)"
    echo "AutoSSL Logs for $domain"
    grep -EhC3 "$domain|error|WARN" /var/cpanel/logs/autossl/*/txt | tail -n5
    echo "SSL Status for $domain"
    curl -v --stderr - https://www.$domain | grep -A10 "Server certificate"
  else
      echo -e "\n$domain does not point here, it points to  $(dig $domain +short)"
      echo "https://www.whatsmydns.net/#A/$domain"
      curl ipinfo.io/$(dig a $domain +short)
    echo "SSL Status for $domain"
    curl -v --stderr - https://www.$domain | grep -A10 "Server certificate"
  fi
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
echo -e "$domain_count Domains \n$subdomain_count Subdomains \n ${RED} Let's not Encrypt! ${NC} \n see https://letsencrypt.org/docs/rate-limits/ for rate limits"
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

Uses find, largest files over 500M

```
{
clear
echo -e "These are the largest files over 500M  for $(hostname) as of $(date)"
echo -e "\n Logs"
find /var/log/ -size +500M -exec ls -hsS1 {} +
journalctl --disk-usage
echo -e "\n Backups"
find /backup*/ -size +500M -exec ls -hsS1 {} +
find /* -type f -name "*.tar.gz" -size +1G -exec du -sh {} \; | grep -vE "(/var|/usr|/root|/opt|cpbackup|\.cpanm|\.cpan)" |sort -h
echo -e "\n Databases"
mysql << EOF
SELECT table_schema AS "Database", 
ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)" 
FROM information_schema.TABLES 
GROUP BY table_schema;
EOF
echo -e "\n Home Directories"
find /home*/  -not -path "/home/virtfs/*" -size +500M -exec ls -hsS1 {} +
df -h
}
```



Uses find, largest files over a pre-set amount, #M or #G

```
diskusage()
{
clear
echo -e "These are the largest files over $1   for $(hostname) as of $(date )"
echo -e "\n Logs"
find /var/log/ -size +$1 -exec ls -hsS1 {} +
journalctl --disk-usage
echo -e "\n Backups"
find /backup*/ -size +$1 -exec ls -hsS1 {} +
find /* -type f -name "*.tar.gz" -size +1G -exec du -sh {} \; | grep -vE "(/var|/usr|/root|/opt|cpbackup|\.cpanm|\.cpan)" |sort -h
echo -e "\n Databases"
mysql << EOF
SELECT table_schema AS "Database", 
ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)" 
FROM information_schema.TABLES 
GROUP BY table_schema;
EOF
echo -e "\n Home Directories"
find /home*/ -size +$1 -exec ls -hsS1 {} +
df -h
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
dig  any $i
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
clear
mail -s "Email Test Support" -r test@"$domain" "$2" << END
This is a test email sent from $domain on $(date '+%Y-%m-%d') by a member of the Technical Support team. 
SPF: $(dig txt  "$domain" +short)
DMARC: $(dig txt "_dmarc.$domain" +short)
MX: $(dig MX "$domain" +short | awk {'print $2'})
This is the MX records IP address: $(dig a $(dig mx "$domain" +short| awk {'print $2'})  +short)
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

```
f2b(){
    clear;
    #see https://api.docs.cpanel.net/openapi/whm/operation/flush_cphulk_login_history_for_ips/
    echo -e "\n Cphulk Firewall"
    whmapi1 flush_cphulk_login_history_for_ips ip="$1"
    /scripts/cphulkdwhitelist "$1"
    echo -e "\n APF/CSF"
    [ -f /etc/csf/csf.conf ] && csf -a "$1" || apf -a "$1"
    #fail2ban log
    echo -e "\n Fail2ban"
    tail -n2 /var/log/fail2ban.log | grep "$1"
    # ssh/FTP logs
    echo -e "\n SSH/FTP"
    grep $1 /var/log/messages | tail -n2
    grep $1 /var/log/secure | tail -n2
    #mail client login fails
    #LFD blocks
    echo -e "\n LFD Logs"
    grep $1 /var/log/lfd.log| tail -n2
    echo -e "\n Failed Email Logins"
    grep "$1" /var/log/maillog | grep 'auth failed' | tail -n2| awk {'print $1,$2,$3,$5,$10,$11,$12,$13,$14 $15'}
    
    #failing exim
    echo -e "\n Failed Exim Authentication"
    grep "$1" /var/log/exim_mainlog | grep 'authenticator failed' | tail -n2  | awk  {'print $1,$2,$4,$5,$6,$9,$15'}
 
    #Modsec blocks
    echo -e "\n ModSecurity blocks"
    grep "$1" /usr/local/apache/logs/error_log | grep -E 'id "(13052|13051|13504|90334)"' | tail -n2

    #cPanel blocks
    echo -e "\n Cpanel Login Failures"
     grep "$1" /usr/local/cpanel/logs/login_log | grep "FAILED LOGIN" | tail -n2 | awk {'print $1,$2,$3,$5,$6,$8,$14,$15,$16,$17'}

     #imunify blocks

     echo -e "\n Whitelisting in Imunify"
    imunify360-agent whitelist ip add $1

    #iptables
    echo -e "\n Whitelisting in iptables"
    iptables -A INPUT -s $1 -j ACCEPT

    #apf/csf logs, requires root
   echo -e "\n CSF/APF Deny/Allow Rules"
   grep "$1" /etc/*/*allow* /etc/*/*deny*| tail -n2
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
  modified=$(grep -EHl 'anonymousfox|smtpfox' /home*/*/.contactemail)
  clear
if  grep -EH 'anonymousfox|smtpfox' /home*/*/.contactemail; then
  echo -e "\n cPanel contact emails modified by AnonymousFox"
  echo 
  echo $modified
  sed -i.cleared '/anonymousfox/d' $modified
  sed -i.cleared '/smtpfox/d' $modified
  whmapi1  set_tweaksetting  key='resetpass' value=0
  for i in $( cat /etc/userdomains | awk {'print $2'} | grep -v nobody | uniq); do  uapi --user=$i Email list_pops |grep -E 'anonymousfox|smtpfox'; 
  done
  echo "https://support.cpanel.net/hc/en-us/articles/360058051173-What-is-the-anonymousfox-address-on-my-system"
else echo "No contact emails have been modified by AnonymousFox"
fi
)

```
Go <a href="https://support.cpanel.net/hc/en-us/articles/360058051173-What-is-the-anonymousfox-address-on-my-system-" target="_blank">here</a>


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
mkdir /var/lib/mysql/aria_old.$(date +%F)/
mv /var/lib/mysql/aria_log* /var/lib/mysql/aria_old.$(date +%F)
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
 newpass=$(openssl rand -base64 16 | tr -cd '[:alnum:]')
if [[ $(wp user list | grep $1 | awk {'print $4'} ) = $1 ]]; 
then
  wp user update $1 --user_pass=${newpass};
  echo $newpass 
else
  wp user create test --role=administrator $1 --skip-{plugins,themes}
fi
}
```


Getting a crit plugin error?   
```
(
db=~/plugins.$(date +%F).sql

clear
if [ "$( curl -skLA "foo" "$(wp option get siteurl --skip-{plugins,themes})" |   lynx -stdin -dump | grep "There has been a critical error")" ];
then
    echo "$(wp option get siteurl --skip-{plugins,themes}) failing"
    wp db export "$db"
    for i in $(wp plugin list --skip-{plugins,themes} --field=name) 
    do echo "disabling $i for $(wp option get siteurl --skip-{plugins,themes})"
    wp plugin deactivate "$i" --skip-{plugins,themes}
    echo "testing $(wp option get siteurl --skip-{plugins,themes})"
      if [[ "$(curl -skLA "foo" "$(wp option get siteurl --skip-{plugins,themes})" |   lynx -stdin -dump | grep "There has been a critical error")" ]]; then
    echo  wp plugin activate "$i" --skip-{plugins,themes}
    else
    echo "$i was breaking the site"'!'
    echo "backup located at $db"
    break
    fi
    done
       else
        echo "$(wp option get siteurl --skip-{plugins,themes}) not throwing critical errors"
      fi
)
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






Wordpress site cloner
#will implement db backup templates for other CMS 
site URLs still need to be updated after the restore
```
	wp_clone()
	{
	destination_root=$1
	site_backup=$(basename "$PWD").$(date -I).tar.gz
	db_backup=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).$(date -I).sql
	db_pass=$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)
	db_name=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)
	db_user=$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)
	clear
	##test if WP install
		if test -f wp-config.php;
		then
		echo "This is a Wordpress site"
	echo "backing up database to $db_backup"
	     mysqldump -p"$db_pass" -u "$db_user" "$db_name" > "$db_backup"
	 echo "zipping up $(pwd)"
		 tar -caf "$site_backup" *
	echo "copying everything over to $1"
		rsync -azvP "$site_backup" "$1"
		cd "$1" || echo -e "Correct Document root? \n$PWD"
		tar -xf "$site_backup"

	##Create databases

	(
	n="$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)_clone"
	p="$(pwmake 80)"
	uapi Mysql create_database name="${n}"
	uapi Mysql create_user name="${n}" password="${p}" && uapi Mysql set_privileges_on_database user="${n}" database="${n}" privileges='ALL PRIVILEGES'


	##update wp-config

	db_pass=$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)
	sed -i.pre_clone "s/$db_name/${n}/g" wp-config.php
	sed -i "s/$db_user/${n}/g" wp-config.php
	sed -i "s/$db_pass/$p/g" wp-config.php

    ##manually sets password to match wp-config
    uapi   Mysql set_password  user="$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)" password="$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)"
    
	mysql -p"$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)" -u "$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)" "$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)" < "$db_backup"

	)


	else
	   echo "This is NOT a Wordpress install"
	fi
	}
```




(BROKEN AT THE MOMENT) The purpose of this is to echo out the database credentials for any CMS and the instructions on how to do it correctly, instead of guessing at database/username combos, or potentially fat-fingering a sql command, everything is filled in. Copy and paste the raw file to get those functions started. 
Wordpress ✓
Prestashop ✓
Joomla ✓
Laravel ✓
	#Joomla coming soon™
	#Moodle coming soon™
	#Drupal coming soon™ 
```
	{
	clear
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
		if test -f config/database.php; then echo -e "This is Laravel \n $(grep 'DB_DATABASE\|DB_PASSWORD\|DB_USERNAME' config/database.php)"; fi
		if test -f "moodle/config.php"; then echo "This is Moodle. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "app/etc/env.php"; then echo "This is Magento. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "include/connect.php"; then echo "This is PHP. I got nothin as of $(date +%F) yet ¯\_(ツ)_/¯ " ;fi
		if test -f "index.html"; then echo "This is HTML. I got nothin as of $(date +%F)  ¯\_(ツ)_/¯ " ;fi
	   fi}
	   echo "mysqldump -p -u user database_name > backup.sql" 
	}

```

in progress
```

	(
#Wordpress DB creds
  wp_db_backup=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php).$(date -I).sql
  wp_db_pass=$(awk -F"'" '/DB_PASSWORD/{print $4}' wp-config.php)
  wp_db_name=$(awk -F"'" '/DB_NAME/{print $4}' wp-config.php)
  wp_db_user=$(awk -F"'" '/DB_USER/{print $4}' wp-config.php)
#Prestashop DB creds

ps_db_backup=$(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php).$(whoami).$(date +%F).sql"
ps_db_pass=$(awk -F"'" '/DB_PASSWD_/{print $4}' config/settings.inc.php)"
ps_db_name=$(awk -F"'" '/DB_NAME/{print $4}' config/settings.inc.php)
ps_db_user=$(awk -F"'" '/DB_USER/{print $4}' config/settings.inc.php)

	#Joomla DB creds

	#Laravel DB creds 
clear
##test if WP install
	if test -f wp-config.php;
	then
	echo "This is a Wordpress site"
echo "backing up database to $wp_db_backup"
     mysqldump -p"$wp_db_pass" -u "$wp_db_user" "$wp_db_name" > "$wp_db_backup"
     fi
##test if Prestashop install
      if test -f "config/settings.inc.php"; then echo "This is Prestashop $(awk -F"'" '/PS_VERSION/{print $4}' config/settings.inc.php)"
	echo "backing up database to $ps_db_backup"
     mysqldump -p"$ps_db_pass" -u "$ps_db_user" "$ps_db_name" > "$ps_db_backup"
     fi
##Test if Joomla install
 if test -f "configuration.php"; then 
       echo "This is a Joomla install"
       fi
)
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
