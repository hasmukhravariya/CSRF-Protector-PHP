# Parent image plus system packages and config
FROM 086679231553.dkr.ecr.us-east-1.amazonaws.com/docker-parent-images:debian-php82 AS base

USER root

ENV PHP_ENV="php82"

# Install and configure apache and php packages
RUN apt-get -y update \
    && apt-mark hold php8.3-cli php8.3-xdebug php8.3-opcache php8.3-common php8.3-phpdbg php8.3-readline php8.3-xdebug \
    && apt-get -y install \
        ant \
        git \
        which \
        php8.2-xdebug \
    && apt-get clean all \
    && rm -rf /var/lib/apt/lists/*

RUN echo "xdebug.mode=coverage" >> /etc/php/8.2/cli/php.ini

RUN php --version
RUN which php

# Set and prepare the app directory
ENV APP_HOME=/var/app
RUN mkdir $APP_HOME
RUN chown -R worker $APP_HOME

WORKDIR $APP_HOME

COPY --chown=worker docs $APP_HOME/docs
COPY --chown=worker js $APP_HOME/js
COPY --chown=worker libs $APP_HOME/libs
COPY --chown=worker log $APP_HOME/log
COPY --chown=worker test $APP_HOME/test
COPY --chown=worker composer.json $APP_HOME/
RUN  composer install --dev && composer dump-autoload --optimize

CMD ["ant", "-f", "build/build.xml", "lint_test"]
