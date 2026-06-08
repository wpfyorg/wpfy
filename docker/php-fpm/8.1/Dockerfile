FROM php:8.1-fpm-alpine

# Install build dependencies, compile extensions, clean up
RUN set -eux; \
    apk add --no-cache --virtual .build-deps \
        $PHPIZE_DEPS \
        freetype-dev \
        libjpeg-turbo-dev \
        libpng-dev \
        libzip-dev \
        icu-dev \
        libxml2-dev \
        oniguruma-dev \
        curl-dev \
        imagemagick-dev \
    ; \
    apk add --no-cache \
        freetype \
        libjpeg-turbo \
        libpng \
        libzip \
        icu \
        libxml2 \
        oniguruma \
        libcurl \
        curl \
        mariadb-client \
        imagemagick \
    ; \
    docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" \
        mysqli \
        gd \
        zip \
        intl \
        soap \
        xml \
        mbstring \
        curl \
        exif \
    ; \
    pecl channel-update pecl.php.net; \
    pecl install redis imagick; \
    docker-php-ext-enable redis imagick opcache; \
    apk del .build-deps; \
    rm -rf /tmp/* /var/cache/apk/*

# WP-CLI
RUN set -eux; \
    curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar; \
    chmod +x /usr/local/bin/wp; \
    wp --info

# wpfy PHP configuration
RUN set -eux; \
    { \
        echo "upload_max_filesize = 64M"; \
        echo "post_max_size = 64M"; \
        echo "max_execution_time = 300"; \
        echo "opcache.memory_consumption = 128"; \
        echo "opcache.max_accelerated_files = 10000"; \
    } > /usr/local/etc/php/conf.d/wpfy.ini
USER www-data
