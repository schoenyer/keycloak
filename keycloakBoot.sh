#!/bin/sh

# Adjust password and alias of Server cert to work with Keycloak configuration
if [ -e "/certificates/server.p12" ]; then
  echo -e "\nChanging password and alias of Server cert.\n"
  keytool -keypasswd -new changeit -keystore $KEYSTORE_PATH -storepass changeit -alias 1 -keypass ${PKCS12_PASSWORD:-""}
  if [ ! -z ${PKCS12_ALIAS+x} ]; then
    keytool -changealias -alias $PKCS12_ALIAS -destalias "servercert" -keystore $KEYSTORE_PATH -storepass changeit
  fi
fi

# Set admin password
if [ ! -z $KEYCLOAK_PASSWORD ]; then
    ./keycloak/bin/add-user-keycloak.sh --user admin --password $KEYCLOAK_PASSWORD
    ./keycloak/bin/add-user.sh --container --user admin --password $KEYCLOAK_PASSWORD
  else
    echo "ERROR: ENV KEYCLOAK_PASSWORD not set, thus cannot set keycloak admin password, exit."
    exit 1
fi

# if login theme is specified use it
if [ -e "/opt/app-root/logintheme/logintheme.zip" ]; then
  echo "INFO: Seems like a .zip with a custom login theme is in place, will try to unzip content to /opt/app-root/keycloak/themes/keycloak"
  unzip -qo /opt/app-root/logintheme/logintheme.zip -d /opt/app-root/keycloak/themes/keycloak/login

  if [ ! -z $LOGIN_REGISTER_URL ]; then
    echo "INFO: Registration url for login theme set, will try to set it in custom theme."
    for filename in /opt/app-root/keycloak/themes/keycloak/login/messages/*.properties; do
      sed -i "/doRegisterLink=/c\doRegisterLink=$LOGIN_REGISTER_URL" $filename
    done
  fi
  if [ ! -z $LOGIN_PASSWORDRESET_URL ]; then
    echo "INFO: Password reset url for login theme set, will try to set it in custom theme."
    for filename in /opt/app-root/keycloak/themes/keycloak/login/messages/*.properties; do
      sed -i "/doForgotPasswordLink=/c\doForgotPasswordLink=$LOGIN_PASSWORDRESET_URL" $filename
    done
  fi
fi

./keycloak/bin/standalone.sh --server-config=standalone.xml -Djava.security.egd=file:/dev/random -b 0.0.0.0 &

# Switch to keycloak bin folder
cd ./keycloak/bin

# Wait for keycloak to be ready
wait_for_endpoint() {
  printf "Waiting for '$1'"
  until $(curl --output /dev/null --silent --head --fail $1); do
    sleep 5
    printf "."
  done
  printf "\n"
}

wait_for_endpoint "http://localhost:8080/auth"

# Set Trusted hosts
cd ../../
./configurator
