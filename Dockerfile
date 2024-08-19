ARG PARENT_IMAGE=086679231553.dkr.ecr.us-east-1.amazonaws.com/docker-parent-images:php56
FROM $PARENT_IMAGE AS parent

USER root

RUN yum -y update && yum clean all

# Install and configure apache and php packages
RUN yum -y install curl git which ant php56-php-xdebug

# configure php unit
RUN echo "xdebug.mode=coverage" >> /opt/remi/php56/root/etc/php.ini

# Set and prepare the app directory
ENV APP_HOME=/var/app
RUN mkdir $APP_HOME
RUN chown -R worker $APP_HOME

WORKDIR $APP_HOME

COPY --chown=worker composer.json $APP_HOME/
COPY --chown=worker . $APP_HOME
RUN composer install --dev && composer dump-autoload --optimize

CMD ["ant", "-f", "build/build.xml", "lint_test"]