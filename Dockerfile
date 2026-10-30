FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl libsqlite3-dev $PHPIZE_DEPS \
    && docker-php-ext-install pdo_mysql pdo_sqlite \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && a2enmod headers rewrite \
    && apt-get purge -y --auto-remove $PHPIZE_DEPS \
    && rm -rf /var/lib/apt/lists/*

COPY docker/apache.conf /etc/apache2/conf-available/mailcow-access.conf
RUN a2enconf mailcow-access

COPY public/ /var/www/html/
COPY src/ /var/www/src/
COPY docker/entrypoint.sh /usr/local/bin/mailcow-access-entrypoint
RUN chmod 0755 /usr/local/bin/mailcow-access-entrypoint \
    && mkdir -p /var/lib/mailcow-access \
    && chown -R www-data:www-data /var/lib/mailcow-access /var/www/html /var/www/src

ENTRYPOINT ["mailcow-access-entrypoint"]
CMD ["apache2-foreground"]

