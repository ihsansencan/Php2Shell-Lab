FROM php:8.4.26-apache

COPY apache.conf /etc/apache2/conf-enabled/zz-p2s.conf
COPY www/ /var/www/html/

RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini \
    && mkdir -p /out \
    && chown -R www-data:www-data /out

EXPOSE 80