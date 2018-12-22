// First, cd /etc/nginx/conf.d/ and edit server.js
server {
listen 80;
listen [::]:80;
server_name name.Name www.name.Name;
return 301 https://$server_name$request_uri;
}

server {
listen 443 ssl http2 default_server;
listen [::]:443 ssl http2 default_server;
server_name name.Name www.name.Name;

location / {
proxy_pass http://localhost:3000;
}

ssl_certificate /etc/letsencrypt/live/$PATH/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$PATH/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES256-CBC-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!DSS ;
ssl_session_timeout 1h;
add_header Strict-Transport-Security “max-age= 63072000” always;
}
# notes: name.Name is your domain and $PATH is where you've stored your cert files
# the above is to enable HTTP Strict Transport Security (HSTS). That age is 2 years in seconds (2*365*24*60*60) which is OK for your project duration.
