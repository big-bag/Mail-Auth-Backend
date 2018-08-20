#!/usr/bin/php
<?php

/* DESCRIPTION */
/*
Mail client sends headers as
Auth-Method: plain, login or cram-md5
Auth-User: username@domain.com
Auth-Pass: password in plain text or encrypted with cram-md5
Auth-Protocol: pop3, imap or smtp

NGINX transfers all mail client headers
and can be configured to add two additional headers
X-Auth-Port: 995 (for POP3) or 993 (for IMAP4)
User-Agent: "Nginx POP3 proxy" or "Nginx IMAP4 proxy"

On Apache server backend these headers are seen as
HTTP_AUTH_METHOD
HTTP_AUTH_USER
HTTP_AUTH_PASS
HTTP_AUTH_SALT
HTTP_AUTH_PROTOCOL
HTTP_CLIENT_IP
HTTP_AUTH_SSL
HTTP_X_AUTH_PORT
HTTP_USER_AGENT
*/

// BEGIN

/* DEFINE VARIABLES AND WRITE HEADERS TO LOG */
$auth_method=  $_SERVER["HTTP_AUTH_METHOD"] ;
$auth_user=    $_SERVER["HTTP_AUTH_USER"] ;
$auth_pass=    $_SERVER["HTTP_AUTH_PASS"] ;
$auth_salt=    $_SERVER["HTTP_AUTH_SALT"] ;
$auth_protocol=$_SERVER["HTTP_AUTH_PROTOCOL"] ;
$client_ip=    $_SERVER["HTTP_CLIENT_IP"] ;
$auth_ssl=     $_SERVER["HTTP_AUTH_SSL"] ;
// $auth_port=    $_SERVER["HTTP_X_AUTH_PORT"] ;
// $user_agent=   $_SERVER["HTTP_USER_AGENT"] ;

writeLog('Auth-Method:   ' . $auth_method . '');
writeLog('Auth-User:     ' . $auth_user . '');
// writeLog('Auth-Pass:     "' . $auth_pass . '"');
writeLog('Auth-Salt:     ' . $auth_salt . '');
writeLog('Auth-Protocol: ' . $auth_protocol . '');
writeLog('Client-IP:     ' . $client_ip . '');
writeLog('Auth-SSL:      ' . $auth_ssl . '');
// writeLog('X-Auth-Port:   ' . $auth_port . '');
// writeLog('User-Agent:    ' . $user_agent . '');

/* GET IP ADDRESS OF MAIL SERVER BASED ON DOMAIN */
if (!getmailserver($auth_user)) {
  fail();
  exit;
} else {
  $backend_ip = getmailserver($auth_user);
  writeLog('backend_ip:    ' . $backend_ip . '');
}

/* AUTHENTICATE THE USER OR FAIL */
if (!authuser($auth_user,$auth_pass,$auth_protocol,$backend_ip)) {
  fail();
  exit;
} else {
  $backend_port = authuser($auth_user,$auth_pass,$auth_protocol,$backend_ip);
}

/* Pass! */
pass($backend_ip, $backend_port);

//END

/* FUNCTION TO GET MAIL SERVER BACKEND IP-ADDRES BASED ON DOMAIN */
function getmailserver($auth_user){
  if (in_array(substr($auth_user, -11), array("domain1.com"))) {
    return "192.168.0.1";
    return true;
  } elseif (in_array(substr($auth_user, -12), array("domain02.com"))) {
    return "172.16.0.1";
    return true;
  } elseif (in_array(substr($auth_user, -13), array("domain003.com"))) {
    return "10.0.0.1";
    return true;
  } else {
    return false;
  }
}

/* FUNCTION TO AUTH USER USING IMAP, POP3 OR SMTP */
function authuser($auth_user,$auth_pass,$auth_protocol,$backend_ip){
  // password characters encoded by nginx:
  // " " 0x20h (SPACE)
  // "%" 0x25h
  // see nginx source: src/core/ngx_string.c:ngx_escape_uri(...)

  // NGINX source https://github.com/phusion/nginx/blob/master/src/core/ngx_string.c
  // or http://lxr.nginx.org/source/src/core/ngx_string.c
  // ASCII Encoding Reference https://www.w3schools.com/tags/ref_urlencode.asp
  /* " ", "#", "%", "?", %00-%1F, %7F-%FF */

  $auth_pass = str_replace('%20',' ', $auth_pass);
  $auth_pass = str_replace('%23','#', $auth_pass);
  $auth_pass = str_replace('%25','%', $auth_pass);
  $auth_pass = str_replace('%3F','?', $auth_pass);

  switch ($auth_protocol) {

    case "pop3":
      $backend_port = "110" ;
      writeLog('backend_port:  ' . $backend_port . '');

      // open connection to mail srv backend
      // and get backend's auth salt in base64

      $socket = fsockopen($backend_ip, $backend_port, $errno, $errstr, 30);
      if(!$socket) return false;
      $socket_reply = fgets($socket, 128);

      fwrite($socket, 'AUTH CRAM-MD5'."\r\n");
      $auth_reply = fgets($socket, 128);
      $axigen_salt = substr($auth_reply, 2);

      // convert auth_pass to use with perl script

      $auth_pass = str_replace(' ','\ ', $auth_pass);
      $auth_pass = str_replace('&','\&', $auth_pass);

      // call perl script to convert login, pass and backend salt
      // to cram-md5 hash in base64
      // pass this hash to backend mail server to check authentication

      $auth_hash = shell_exec("./md5cram.pl ${auth_user} ${auth_pass} ${axigen_salt}");
      fwrite($socket, $auth_hash . "\r\n");
      $auth_hash_reply = fgets($socket, 128);

      // close connection to backend mail server

      fwrite($socket, 'QUIT'."\r\n");
      fclose($socket);

      // return true  when +OK username@domain.com has NN messages (NN octets)
      // return false when -ERR Wrong SASL response

      if (substr($auth_hash_reply, 0, 4) === '-ERR'):
        return false;
      else:
        writeLog('Auth reply:    ' . $auth_hash_reply . '');
        return "110";
        return true;
      endif;
      break;

    case "imap":
      $backend_port = "143" ;
      writeLog('backend_port:  ' . $backend_port . '');

      // open connection to mail srv backend
      // and get backend's auth salt in base64

      $socket = fsockopen($backend_ip, $backend_port, $errno, $errstr, 30);
      if(!$socket) return false;
      $socket_reply = fgets($socket, 128);

      fwrite($socket, '001 AUTHENTICATE CRAM-MD5'."\r\n");
      $auth_reply = fgets($socket, 128);
      $axigen_salt = substr($auth_reply, 2);

      // convert auth_pass to use with perl script

      $auth_pass = str_replace(' ','\ ', $auth_pass);
      $auth_pass = str_replace('&','\&', $auth_pass);

      // call perl script to convert login, pass and backend salt
      // to cram-md5 hash in base64
      // pass this hash to backend mail server to check authentication

      $auth_hash = shell_exec("./md5cram.pl ${auth_user} ${auth_pass} ${axigen_salt}");
      fwrite($socket, $auth_hash . "\r\n");
      $auth_hash_reply = fgets($socket, 128);

      // close connection to backend mail server

      fwrite($socket, '002 LOGOUT'."\r\n");
      fclose($socket);

      // return true  when 001 OK AUTHENTICATE completed
      // return false when 001 NO AUTHENTICATE failed

      if (substr($auth_hash_reply, 4, 22) === 'NO AUTHENTICATE failed'):
        return false;
      else:
        writeLog('Auth reply:    ' . $auth_hash_reply . '');
        return "143";
        return true;
      endif;
      break;

    case "smtp":
      $backend_port = "25" ;
      writeLog('backend_port:  ' . $backend_port . '');

      // open connection to mail srv backend
      // and get backend's auth salt in base64

      $socket = fsockopen($backend_ip, $backend_port, $errno, $errstr, 30);
      if(!$socket) return false;
      $socket_reply = fgets($socket, 128);

      fwrite($socket, 'EHLO '.$backend_ip."\r\n");
      $ehlo_reply = '';
      do {
        $line = fgets($socket, 128);
        $ehlo_reply .= $line;
      } while (null !== $line && false !== $line && ' ' != $line{3});

      fwrite($socket, 'AUTH CRAM-MD5'."\r\n");
      $auth_reply = fgets($socket, 128);
      $axigen_salt = substr($auth_reply, 4);

      // convert auth_pass to use with perl script

      $auth_pass = str_replace(' ','\ ', $auth_pass);
      $auth_pass = str_replace('&','\&', $auth_pass);

      // call perl script to convert login, pass and backend salt
      // to cram-md5 hash in base64
      // pass this hash to backend mail server to check authentication

      $auth_hash = shell_exec("./md5cram.pl ${auth_user} ${auth_pass} ${axigen_salt}");
      fwrite($socket, $auth_hash . "\r\n");
      $auth_hash_reply = fgets($socket, 128);

      // close connection to backend mail server

      fwrite($socket, 'QUIT'."\r\n");
      fclose($socket);

      // return true  when 235 Authentication successful
      // return false when 535 Authentication failed

      if (substr($auth_hash_reply, 0, 3) === '535'):
        return false;
      else:
        writeLog('Auth reply:    ' . $auth_hash_reply . '');
        return "25";
        return true;
      endif;
      break;

  }
}

function fail(){
  header("Auth-Status: Invalid login or password");
  exit;
}

function pass($backend_ip,$backend_port){
  header("Auth-Status: OK");
  header("Auth-Server: $backend_ip");
  header("Auth-Port: $backend_port");
  exit;
}

function writeLog($data) {
  list($usec, $sec) = explode(' ', microtime());
  $datetime = strftime("%Y%m%d %H:%M:%S",time());
  $msg = "$datetime'". sprintf("%06s",intval($usec*1000000)).": $data";
  $save_path = '/var/log/httpd/auth.log';
  $fp = @fopen($save_path, 'a'); // open or create the file for writing and append info
  fwrite($fp, $msg . PHP_EOL);
  fclose($fp); // close the file
}

?>
