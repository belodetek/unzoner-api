#!/usr/bin/env bash

# https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/java-se-nginx.html
# https://stackoverflow.com/a/63818314/1559300
# https://serverfault.com/questions/318574/how-to-disable-nginx-logging
if test $(/opt/elasticbeanstalk/bin/get-config environment | jq -r .LOGGING) -eq 0; then
    for path in /var/proxy/staging/nginx /etc/nginx; do
        pushd "${path}"
        sudo sed -i'' '/access_log/d' nginx.conf
        sudo sed -i'' '/error_log/d' nginx.conf
        popd
    done

    sudo rm -r /var/log/nginx/*.log
    sudo mkdir -p /var/log/nginx/healthd
    sudo chown -R nginx:nginx /var/log/nginx
    sudo service nginx reload

    sudo rm -f /etc/rsyslog.d/web.conf
    sudo systemctl restart rsyslog
    sudo rm -f /var/log/web.stdout.log

    sudo rm -rf /var/log/rotated/*
fi
