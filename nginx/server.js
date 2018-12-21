server {
listen 80;
listen [::]:80;
server_name xyzsecure.me www.xyzsecure.me;
return 301 https://$server_name$request_uri;
}

server {
listen 443 ssl http2 default_server;
listen [::]:443 ssl http2 default_server;
server_name xyzsecure.me www.xyzsecure.me;

location / {
proxy_pass http://localhost:3000;

proxy_connect_timeout 240;
proxy_send_timeout    240;
proxy_read_timeout    240;
send_timeout          240;

}

#proxy_connect_timeout 240;
#proxy_send_timeout    240;
#proxy_read_timeout    240;
#send_timeout          240;

ssl_certificate /etc/letsencrypt/live/xyzsecure.me/fullchain.pem;

ssl_certificate_key /etc/letsencrypt/live/xyzsecure.me/privkey.pem;

ssl_protocols TLSv1.2 TLSv1.3;

ssl_prefer_server_ciphers on;

ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES256-CBC-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!DSS ;

ssl_session_timeout 1h;

proxy_hide_header Strict-Transport-Security;
add_header Strict-Transport-Security 'max-age= 63072000' always;
}
