# Keycloak for Openid Setup

| env                                   | Description                                                                     |
|------                                 |-------------                                                                    |
|  KEYCLOAK_PASSWORD                    | Password of Keycloak admin user *admin*. Needs to be set.                       |
|  KEYCLOAK_TRUSTED                     | Trusted Hosts used for Openid Client Registration.                              |
|  DOMAIN_REALM                         | Name of Realm to be created during startup.                                     |
|  DOMAIN_ADMINNAME                     | Name of Administrator user of the domain realm.                                 |
|  DOMAIN_ADMINPASSWORD                 | Password of Administrator user of the domain realm.                             |
|  FACEBOOK_CLIENTID                    | Client ID used to configure Facebook Identity Provider.                         |
|  FACEBOOK_CLIENTSECRET                | Client Secret used to configure Facebook Identity Provider.                     |
|  GOOGLE_CLIENTID                      | Client ID used to configure Google Identity Provider.                           |
|  GOOGLE_CLIENTSECRET                  | Client Secret used to configure Google Identity Provider.                       |
|  LOGIN_INTERNATIONALISATION           | Specify with `true` and `false` whether internationalisation should be enabled for login page (currently hardcoded *en* and *de*) |
|  LOGIN_REGISTER_URL                   | Url that points to registration page |
|  LOGIN_PASSWORDRESET_URL              | Url that points to the password reset page |

## Basic Setup

`KEYCLOAK_PASSWORD` and `KEYCLOAK_TRUSTED`needs to be set in order for keycloak
to start.

## Domain Specific Setup

`DOMAIN_REALM` let's you specify a custom realm. Be aware that when specifying a
custom realm you also need to specify `DOMAIN_ADMINNAME` and `DOMAIN_ADMINPASSWORD`.

## Identity Providers

Currently Google and Facebook are supported as Social Media Identity Providers.
You can configure them with the env variables described above.

## Login Theme

You can put a .zip with your login theme to `/opt/app-root/logintheme/logintheme.zip`
and its content will be copied into `/opt/app-root/keycloak/themes/keycloak/login`
folder at keycloak startup.

If you added a custom login theme you can set the url that points to a registration
website and to a password reset website with `LOGIN_REGISTER_URL` and `LOGIN_PASSWORDRESET_URL`.
At startup the container will go through all `.properties` files in `/opt/app-root/keycloak/themes/keycloak/login/messages/`
and tries to replace the `doRegisterLink=` and `doForgotPasswordLink=` properties
with the urls you specified in the env variables.
