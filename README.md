# Mail-Auth-Backend
PHP script as the auth backend for POP3, IMAP and SMTP

This short guide describes the basic configuration to be able to authenticate e-mail clients in the different domains.
The script is written for the ability to have multiple mail servers.
The starting point was an [article on nginx.com](https://www.nginx.com/resources/wiki/start/topics/examples/imapauthenticatewithapachephpscript/).

1. add `mail` block under `http` block in the main NGINX config
```
sudo nano /etc/nginx/nginx.conf
```
```
mail {
    auth_http  127.0.0.1:8008/mail/auth.php;

    proxy                      on;
    proxy_pass_error_message   on;

    ssl_prefer_server_ciphers  on;
    ssl_protocols              TLSv1.1 TLSv1.2;
    ssl_ciphers                ECDHE-RSA-AES128-GCM-SHA256:...:!PSK;
    ssl_session_cache          shared:TLSSL:16m;
    ssl_session_timeout        10m;
    ssl_certificate            /etc/letsencrypt/live/<domain.com>/fullchain.pem;
    ssl_certificate_key        /etc/letsencrypt/live/<domain.com>/privkey.pem;
 
    server {
        listen             995 ssl;
        protocol           pop3;
        pop3_auth          PLAIN;
        pop3_capabilities  "TOP" "USER" "PIPELINING" "UIDL";
#        auth_http_header   X-Auth-Port 995; # you can add this header that will be passed to your backend
#        auth_http_header   User-Agent "Nginx POP3 proxy"; # you can add this header that will be passed to your backend
    }

    server {
        listen             993 ssl;
        protocol           imap;
        imap_auth          PLAIN LOGIN;
        imap_capabilities  "IMAP4rev1" "CHILDREN" "IDLE" "LITERAL+" "MULTIAPPEND" "SPECIAL-USE" "NAMESPACE" "UIDPLUS" "QUOTA" "XLIST" "ID";
    }

    server {
        listen             465 ssl;
        protocol           smtp;
        smtp_auth          PLAIN LOGIN;
        smtp_capabilities  "SIZE 10485760"  "ENHANCEDSTATUSCODES"  "8BITMIME"  "DSN";
 
        xclient    off;
        timeout    300s;
    }
}
```
```
sudo nginx -t
sudo systemctl reload nginx.service
```
where `127.0.0.1:8008` is Apache backend under NGINX.

2. install and configure Apache to listen only localhost
```
sudo pacman -S extra/apache
sudo nano /etc/httpd/conf/httpd.conf
```
```
Listen localhost:8008
```
```
sudo systemctl start httpd.service
sudo systemctl enable httpd.service
sudo systemctl status httpd.service -l
```

3. install and cofigure PHP
```
sudo pacman -S extra/php extra/php-apache
sudo nano /etc/httpd/conf/httpd.conf
```
```
#LoadModule mpm_event_module modules/mod_mpm_event.so
LoadModule mpm_prefork_module modules/mod_mpm_prefork.so

LoadModule dir_module modules/mod_dir.so
LoadModule php7_module modules/libphp7.so

Include conf/extra/php7_module.conf
```
```
sudo nano /etc/php/php.ini
```
```
date.timezone = Europe/Moscow
```
```
sudo systemctl restart httpd.service
```

4. create a directory and locate script there
```
sudo mkdir /srv/http/mail
sudo touch /srv/http/mail/auth.php
```

5. create a log file and set permissions
```
sudo touch /var/log/httpd/auth.log
sudo chmod o+w /var/log/httpd/auth.log
```
