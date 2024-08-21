# Parent image plus system packages and config
FROM 086679231553.dkr.ecr.us-east-1.amazonaws.com/docker-parent-images:php74 AS base

USER root

ENV PHP_ENV="php74"

RUN yum -y update \
    && yum -y install \
        curl \
        git \
        which \
        ant \
        php74-php-pecl-xdebug \
    && yum clean all

RUN php --version

RUN echo "xdebug.mode=coverage" >> /etc/opt/remi/php74/php.ini

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
