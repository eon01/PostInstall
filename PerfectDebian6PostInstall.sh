#!/bin/bash
#Original Source : http://www.thelinuxfr.org/script-post-installation-debian-wheezy/

if [[ $(id -u) -ne 0 ]] ; then
    echo "Please run this script with root privilegues!" ;
    exit 2 ;
fi

DEBIAN_OK=`cat /etc/debian_version`

if [[ "$DEBIAN_OK" = "" ]] ; then
  echo "This is not a debian server...";
  exit;
fi

dpkg-reconfigure locales

read -p "Please enter the server hostname (e.g. server123)?" HOSTNAME
CHECK=`echo $HOSTNAME | grep -E "[^[:alnum:]\-]"`
if [[ "$CHECK" != "" ]] ; then
  echo "$HOSTNAME is not a valid hostname!" ;
  exit 2;
fi

read -p "Please enter the server domain name ($HOSTNAME.mydomain.com)?" FQDNNAME
CHECK=`echo $FQDNNAME | grep -E "[^[:alnum:]\-\.-]"`
if [[ "$CHECK" != "" ]] ; then
  echo "$FQDNNAME is no valid domain name!" ;
  exit 2;
fi

FQDNNAME="$HOSTNAME.$FQDNNAME"

read -p "So the server name should be $HOSTNAME ($FQDNNAME) (y/n)?" DOIT

if [[ "$DOIT" != "j" && "$DOIT" != "y" ]] ; then
    echo "Abgebrochen." ;
    exit 0 ;
fi

read -p "Do you want to use the <stable> or <testing> distribution? [stable]" DISTRIB

if [[ "$DISTRIB" = "" ]] ; then
  DISTRIB="stable" ;
fi

if [[ "$DISTRIB" != "testing" && "$DISTRIB" != "stable" ]] ; then
    echo "aborted!" ;
    exit 0 ;
fi

read -p "We will install lots of packages now! Shall we start (y/n)?" DOIT

if [[ "$DOIT" != "j" && "$DOIT" != "y" ]] ; then
    echo "Aborted." ;
    exit 0 ;
fi

SERVERIP=`ifconfig | grep -i 'inet addr:' | sed -r "s/.*inet\s+addr:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\s+.*/\1.\2.\3.\4/" | grep -v 'addr:127.0.' | head -n 1`

OK="no"

while [[ "$OK" = "no" ]] ; do
  read -p "Main-IP of the server (has to be set up in ifconfig already) [$SERVERIP]: " SETSERVERIP ;
  if [[ "$SETSERVERIP" = "" ]] ; then
      SETSERVERIP="$SERVERIP" ;
  fi
  CHECK=`ifconfig | grep ":$SETSERVERIP "`;
  if [[ "$CHECK" = "" ]] ; then
    echo "IP not found in ifconfig" ;
  else
    OK="yes" ;
  fi
done

SERVERIP="$SETSERVERIP" ;

## set hostname
cp /etc/hosts /etc/hosts.save
cp /etc/hostname /etc/hostname.save
if [[ -e /etc/mailname ]] ; then
  cp /etc/mailname /etc/mailname.save ;
fi

CHECK=`grep "$SERVERIP" /etc/hosts`
if [[ "$CHECK" = "" ]] ; then
  echo "$SERVERIP    $FQDNNAME    $HOSTNAME" >> /etc/hosts ;
else
  sed -i -r "s/^[^0-9]*$SERVERIP\s+.*$/$SERVERIP    $FQDNNAME    $HOSTNAME/" /etc/hosts ;
fi

echo "$HOSTNAME" > /etc/hostname
echo "$FQDNNAME" > /etc/mailname
hostname $HOSTNAME
/etc/init.d/hostname.sh start

apt-get -q -y --force-yes install bc

## create apt sources
cp /etc/apt/sources.list /etc/apt/sources.list.save ;

echo "deb      http://ftp.de.debian.org/debian  $DISTRIB          main contrib non-free" > /etc/apt/sources.list ;
echo "deb-src  http://ftp.de.debian.org/debian  $DISTRIB          main contrib non-free" >>  /etc/apt/sources.list ;

echo "deb      http://security.debian.org/       $DISTRIB/updates  main contrib non-free" >> /etc/apt/sources.list ;
echo "deb-src  http://security.debian.org/       $DISTRIB/updates  main contrib non-free" >>  /etc/apt/sources.list ;

echo "deb http://ftp.de.debian.org/debian/ squeeze-updates main" >> /etc/apt/sources.list ;

#if [[ "$DISTRIB" = "stable" ]] ; then
#    echo "deb http://volatile.debian.org/debian-volatile squeeze/volatile main contrib non-free" >> /etc/apt/sources.list ;
#fi

DONE="no" ;
STEP=1 ;
while [[ "$DONE" = "no" && "$STEP" -lt "7" ]] ; do
  STEP=`echo "$STEP + 1" | bc`;
  echo "STEP: $STEP";
  ## update apt
  CHECK=`apt-get update -qq 2>&1 | grep -E "^W:" | grep 'NO_PUBKEY'`;
  echo "CHECK: $CHECK";
  if [[ "$CHECK" != "" ]] ; then
    PUBKEY=`echo "$CHECK" | sed -r "s/.*(NO_PUBKEY)\s+([0-9a-zA-Z]+)(\s+|$).*/\2/" | head -n 1` ;
    echo "PUBKEY: $PUBKEY";
    CHECK=`echo "$PUBKEY" | grep -E "[^A-Za-z0-9]"`
    echo "CHECK2: $CHECK";
    if [[ "$CHECK" = "" ]] ; then
        echo "Importiere Public key $PUBKEY." ;
        gpg --keyserver pgp.mit.edu --recv "$PUBKEY";
        gpg --export --armor "$PUBKEY" | apt-key add - ;
    fi
  else
    DONE="yes" ;
  fi
done

apt-get -q -y dist-upgrade


## check for ssh option
CHECK=`grep -e '^SSHD_OOM_ADJUST=-17' /etc/default/ssh`
if [[ "$CHECK" != "" ]] ; then
  sed -i s/SSHD_OOM_ADJUST=-17/#SSHD_OOM_ADJUST=-17/ /etc/default/ssh;
  echo "unset SSHD_OOM_ADJUST" >> /etc/default/ssh ;
fi

## install and remove programs
apt-get -q -y install ssh openssh-server vim vim-nox ntp ntpdate postfix postfix-mysql postfix-doc mysql-client mysql-server courier-authdaemon courier-authlib-mysql courier-pop courier-pop-ssl courier-imap courier-imap-ssl libsasl2-2 libsasl2-modules libsasl2-modules-sql sasl2-bin libpam-mysql openssl courier-maildrop getmail4 rkhunter binutils sudo amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils libexpat1 ssl-cert libapache2-mod-php5 php5 php5-common php5-gd php5-mysql php5-imap phpmyadmin php5-cli php5-cgi libapache2-mod-fcgid apache2-suexec php-pear php-auth php5-mcrypt mcrypt php5-imagick imagemagick libapache2-mod-suphp libruby libapache2-mod-ruby pure-ftpd-common pure-ftpd-mysql quota quotatool

## check for mysql bind option
CHECK=`grep -e '^bind-address ' /etc/mysql/my.cnf`
if [[ "$CHECK" != "" ]] ; then
  sed -i s/^bind-address /#bind-address / /etc/mysql/my.cnf;
fi

/etc/init.d/mysql restart

cd /etc/courier
rm -f /etc/courier/imapd.pem
rm -f /etc/courier/pop3d.pem


sed -i -r "s/CN=.*/CN=${FQDNNAME}/" /etc/courier/imapd.cnf
sed -i -r "s/CN=.*/CN=${FQDNNAME}/" /etc/courier/pop3d.cnf

mkimapdcert
mkpop3dcert
/etc/init.d/courier-imap-ssl restart
/etc/init.d/courier-pop-ssl restart

postconf -e 'smtpd_sasl_local_domain ='
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'broken_sasl_auth_clients = yes'
postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination, reject_non_fqdn_recipient, reject_invalid_hostname, reject_non_fqdn_hostname, reject_rbl_client zen.spamhaus.org, reject_rbl_client bl.spamcop.net'
postconf -e 'inet_interfaces = all'
postconf -e "myhostname = $FQDNNAME"

/etc/init.d/postfix restart


a2enmod suexec rewrite ssl actions include
a2enmod dav_fs dav auth_digest

/etc/init.d/apache2 restart


sed -i -r "s/STANDALONE_OR_INETD=.*/STANDALONE_OR_INETD=standalone/" /etc/default/pure-ftpd-common
sed -i -r "s/VIRTUALCHROOT=.*/VIRTUALCHROOT=true/" /etc/default/pure-ftpd-common


update-rc.d -f exim remove
update-inetd --remove daytime
update-inetd --remove telnet
update-inetd --remove time
update-inetd --remove finger
update-inetd --remove talk
update-inetd --remove ntalk
update-inetd --remove ftp
update-inetd --remove discard

/etc/init.d/openbsd-inetd reload

echo 1 > /etc/pure-ftpd/conf/TLS
mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem 
chmod 600 /etc/ssl/private/pure-ftpd.pem
/etc/init.d/pure-ftpd-mysql restart

## enable quota
cp /etc/fstab /etc/fstab.save

CHECK=`grep -E "^[^[:space:]]+[[:space:]]+\/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+" /etc/fstab | grep 'usrquota'`
if [[ "$CHECK" = "" ]] ; then
sed -i -r "s/(\S+\s+\/\s+\S+\s+)(\S+)(\s+)/\1\2,usrquota\3/" /etc/fstab ;
fi

CHECK=`grep -E "^[^[:space:]]+[[:space:]]+\/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+" /etc/fstab | grep 'grpquota'`
if [[ "$CHECK" = "" ]] ; then
sed -i -r "s/(\S+\s+\/\s+\S+\s+)(\S+)(\s+)/\1\2,grpquota\3/" /etc/fstab ;
fi

touch /quota.user /quota.group
chmod 600 /quota.*
mount -o remount /
quotacheck -avugm
quotaon -avug


apt-get -q -y install bind9 dnsutils vlogger webalizer awstats build-essential autoconf automake1.9 libtool flex bison debhelper

cd /tmp
wget http://olivier.sessink.nl/jailkit/jailkit-2.13.tar.gz
tar xvfz jailkit-2.13.tar.gz
cd jailkit-2.13
./debian/rules binary
cd ..
dpkg -i jailkit_2.13-1_*.deb
rm -rf jailkit-2.13*


apt-get -q -y install fail2ban

echo '[pureftpd]

enabled  = true
port     = ftp
filter   = pureftpd
logpath  = /var/log/syslog
maxretry = 3


[sasl]

enabled  = true
port     = smtp
filter   = sasl
logpath  = /var/log/mail.log
maxretry = 5


[courierpop3]

enabled  = true
port     = pop3
filter   = courierpop3
logpath  = /var/log/mail.log
maxretry = 5


[courierpop3s]

enabled  = true
port     = pop3s
filter   = courierpop3s
logpath  = /var/log/mail.log
maxretry = 5


[courierimap]

enabled  = true
port     = imap2
filter   = courierimap
logpath  = /var/log/mail.log
maxretry = 5


[courierimaps]

enabled  = true
port     = imaps
filter   = courierimaps
logpath  = /var/log/mail.log
maxretry = 5' > /etc/fail2ban/jail.local

echo '[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =' > /etc/fail2ban/filter.d/pureftpd.conf


echo '# Fail2Ban configuration file
#
# $Revision: 100 $
#

[Definition]

# Option:  failregex
# Notes.:  regex to match the password failures messages in the logfile. The
#          host must be matched by a group named "host". The tag "<HOST>" can
#          be used for standard IP/hostname matching and is only an alias for
#          (?:::f{4,6}:)?(?P<host>\S+)
# Values:  TEXT
#
failregex = pop3d: LOGIN FAILED.*ip=\[.*:<HOST>\]

# Option:  ignoreregex
# Notes.:  regex to ignore. If this regex matches, the line is ignored.
# Values:  TEXT
#
ignoreregex =' > /etc/fail2ban/filter.d/courierpop3.conf


echo '# Fail2Ban configuration file
#
# $Revision: 100 $
#

[Definition]

# Option:  failregex
# Notes.:  regex to match the password failures messages in the logfile. The
#          host must be matched by a group named "host". The tag "<HOST>" can
#          be used for standard IP/hostname matching and is only an alias for
#          (?:::f{4,6}:)?(?P<host>\S+)
# Values:  TEXT
#
failregex = pop3d-ssl: LOGIN FAILED.*ip=\[.*:<HOST>\]

# Option:  ignoreregex
# Notes.:  regex to ignore. If this regex matches, the line is ignored.
# Values:  TEXT
#
ignoreregex =' > /etc/fail2ban/filter.d/courierpop3s.conf


echo '# Fail2Ban configuration file
#
# $Revision: 100 $
#

[Definition]

# Option:  failregex
# Notes.:  regex to match the password failures messages in the logfile. The
#          host must be matched by a group named "host". The tag "<HOST>" can
#          be used for standard IP/hostname matching and is only an alias for
#          (?:::f{4,6}:)?(?P<host>\S+)
# Values:  TEXT
#
failregex = imapd: LOGIN FAILED.*ip=\[.*:<HOST>\]

# Option:  ignoreregex
# Notes.:  regex to ignore. If this regex matches, the line is ignored.
# Values:  TEXT
#
ignoreregex =' > /etc/fail2ban/filter.d/courierimap.conf


echo '# Fail2Ban configuration file
#
# $Revision: 100 $
#

[Definition]

# Option:  failregex
# Notes.:  regex to match the password failures messages in the logfile. The
#          host must be matched by a group named "host". The tag "<HOST>" can
#          be used for standard IP/hostname matching and is only an alias for
#          (?:::f{4,6}:)?(?P<host>\S+)
# Values:  TEXT
#
failregex = imapd-ssl: LOGIN FAILED.*ip=\[.*:<HOST>\]

# Option:  ignoreregex
# Notes.:  regex to ignore. If this regex matches, the line is ignored.
# Values:  TEXT
#
ignoreregex =' > /etc/fail2ban/filter.d/courierimaps.conf


/etc/init.d/fail2ban restart 


echo "AddDefaultCharset off" > /etc/apache2/conf.d/charset

CHECK=`grep -i -E 'Listen[[:space:]]+443' /etc/apache2/ports.conf`
if [[ "$CHECK" = "" ]] ; then
  echo "Listen 443" >> /etc/apache2/ports.conf ;
fi

a2enmod ssl
a2enmod rewrite
a2enmod suexec
a2enmod include
a2enmod php5
a2enmod ruby

/etc/init.d/apache2 restart


echo "Finished all actions" ;
