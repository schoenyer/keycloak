package main

import (
  //"github.com/docopt/docopt.go"
  "os"
  "encoding/json"
	"net/http"
	"net/url"
  "strings"
  "errors"
  "bytes"
  "time"
  "github.com/sirupsen/logrus"
)

// const usage = `
// Unofficial Keycloak APIs
//
// Usage:
//   uka addTrustedHost --url=<apiUrl> --realm=<realm> --user=<user> --password=<password> <hosts>...
//
// Options:
//   -h --help
//   --url=<apiUrl>
//   --realm=<realm>
//   --user=<user>
//   --password=<password>
// `


type BearerToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
}


type Realm struct {
	Enabled bool   `json:"enabled"`
	ID      string `json:"id"`
	Realm   string `json:"realm"`
}


type Client struct {
	ID                        string        `json:"id"`
	ClientID                  string        `json:"clientId"`
	Name                      string        `json:"name"`
	BaseURL                   string        `json:"baseUrl,omitempty"`
	SurrogateAuthRequired     bool          `json:"surrogateAuthRequired"`
	Enabled                   bool          `json:"enabled"`
	ClientAuthenticatorType   string        `json:"clientAuthenticatorType"`
	DefaultRoles              []string      `json:"defaultRoles,omitempty"`
	RedirectUris              []string      `json:"redirectUris"`
	WebOrigins                []interface{} `json:"webOrigins"`
	NotBefore                 int           `json:"notBefore"`
	BearerOnly                bool          `json:"bearerOnly"`
	ConsentRequired           bool          `json:"consentRequired"`
	StandardFlowEnabled       bool          `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool          `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool          `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool          `json:"serviceAccountsEnabled"`
	PublicClient              bool          `json:"publicClient"`
	FrontchannelLogout        bool          `json:"frontchannelLogout"`
	Protocol                  string        `json:"protocol,omitempty"`
	Attributes                struct {
	} `json:"attributes"`
	FullScopeAllowed          bool `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout int  `json:"nodeReRegistrationTimeout"`
	ProtocolMappers           []struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Protocol        string `json:"protocol"`
		ProtocolMapper  string `json:"protocolMapper"`
		ConsentRequired bool   `json:"consentRequired"`
		ConsentText     string `json:"consentText,omitempty"`
		Config          struct {
			IDTokenClaim     string `json:"id.token.claim"`
			AccessTokenClaim string `json:"access.token.claim"`
		} `json:"config"`
	} `json:"protocolMappers"`
	UseTemplateConfig  bool `json:"useTemplateConfig"`
	UseTemplateScope   bool `json:"useTemplateScope"`
	UseTemplateMappers bool `json:"useTemplateMappers"`
	Access             struct {
		View      bool `json:"view"`
		Configure bool `json:"configure"`
		Manage    bool `json:"manage"`
	} `json:"access"`
}

type Mapper struct {
	Protocol string `json:"protocol"`
	Config  MapperConf  `json:"config"`
	Name            string `json:"name"`
	ConsentRequired string `json:"consentRequired"`
	ProtocolMapper  string `json:"protocolMapper"`
}

type MapperConf struct {
  IDTokenClaim       string `json:"id.token.claim"`
  AccessTokenClaim   string `json:"access.token.claim"`
  UserinfoTokenClaim string `json:"userinfo.token.claim"`
  UserAttribute      string `json:"user.attribute"`
  ClaimName          string `json:"claim.name"`
  JSONTypeLabel      string `json:"jsonType.label"`
  Multivalued        string `json:"multivalued"`
}

type User struct {
	Enabled    bool `json:"enabled"`
	Username      string `json:"username"`
  Credentials []UserCredentials `json:"credentials"`
  ClientRoles map[string][]string `json:"clientRoles"`
}

type UserCredentials struct {
  Value string `json:"value"`
  Type string `json:"type"`
}

type UserDetails struct {
	ID                         string        `json:"id"`
	CreatedTimestamp           int64         `json:"createdTimestamp"`
	Username                   string        `json:"username"`
	Enabled                    bool          `json:"enabled"`
	Totp                       bool          `json:"totp"`
	EmailVerified              bool          `json:"emailVerified"`
	DisableableCredentialTypes []interface{} `json:"disableableCredentialTypes"`
	RequiredActions            []interface{} `json:"requiredActions"`
	NotBefore                  int           `json:"notBefore"`
	Access                     struct {
		ManageGroupMembership bool `json:"manageGroupMembership"`
		View                  bool `json:"view"`
		MapRoles              bool `json:"mapRoles"`
		Impersonate           bool `json:"impersonate"`
		Manage                bool `json:"manage"`
	} `json:"access"`
}


type Composite struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	ScopeParamRequired bool   `json:"scopeParamRequired"`
	Composite          bool   `json:"composite"`
	ClientRole         bool   `json:"clientRole"`
	ContainerID        string `json:"containerId"`
}

type Component struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderID   string `json:"providerId"`
	ProviderType string `json:"providerType"`
	ParentID     string `json:"parentId"`
	SubType      string `json:"subType"`
	Config       json.RawMessage
}

type TrustedHostsComponent struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderID   string `json:"providerId"`
	ProviderType string `json:"providerType"`
	ParentID     string `json:"parentId"`
	SubType      string `json:"subType"`
	Config       TrustedHostsConfig `json:"config"`
}

type TrustedHostsConfig struct {
  HostSendingRegistrationRequestMustMatch []string `json:"host-sending-registration-request-must-match"`
  TrustedHosts                            []string `json:"trusted-hosts"`
  ClientUrisMustMatch                     []string `json:"client-uris-must-match"`
}

type Provider struct {
	Alias                     string `json:"alias"`
	ProviderID                string `json:"providerId"`
	Enabled                   bool   `json:"enabled"`
	AuthenticateByDefault     bool   `json:"authenticateByDefault"`
	FirstBrokerLoginFlowAlias string `json:"firstBrokerLoginFlowAlias"`
	PostBrokerLoginFlowAlias  string `json:"postBrokerLoginFlowAlias"`
	StoreToken                string `json:"storeToken"`
	AddReadTokenRoleOnCreate  string `json:"addReadTokenRoleOnCreate"`
	TrustEmail                bool   `json:"trustEmail"`
	LinkOnly                  string `json:"linkOnly"`
  Config                    ProviderConfig `json:"config"`
}

type ProviderConfig struct {
  UseJwksURL      string `json:"useJwksUrl"`
  DisableUserInfo string `json:"disableUserInfo"`
  HideOnLoginPage string `json:"hideOnLoginPage"`
  ClientID        string `json:"clientId"`
  ClientSecret    string `json:"clientSecret"`
  UserIp          string `json:"userIp"`
}

type RealmConfig struct {
	ID                                  string   `json:"id"`
	Realm                               string   `json:"realm"`
	NotBefore                           int      `json:"notBefore"`
	RevokeRefreshToken                  bool     `json:"revokeRefreshToken"`
	RefreshTokenMaxReuse                int      `json:"refreshTokenMaxReuse"`
	AccessTokenLifespan                 int      `json:"accessTokenLifespan"`
	AccessTokenLifespanForImplicitFlow  int      `json:"accessTokenLifespanForImplicitFlow"`
	SsoSessionIdleTimeout               int      `json:"ssoSessionIdleTimeout"`
	SsoSessionMaxLifespan               int      `json:"ssoSessionMaxLifespan"`
	OfflineSessionIdleTimeout           int      `json:"offlineSessionIdleTimeout"`
	AccessCodeLifespan                  int      `json:"accessCodeLifespan"`
	AccessCodeLifespanUserAction        int      `json:"accessCodeLifespanUserAction"`
	AccessCodeLifespanLogin             int      `json:"accessCodeLifespanLogin"`
	ActionTokenGeneratedByAdminLifespan int      `json:"actionTokenGeneratedByAdminLifespan"`
	ActionTokenGeneratedByUserLifespan  int      `json:"actionTokenGeneratedByUserLifespan"`
	Enabled                             bool     `json:"enabled"`
	SslRequired                         string   `json:"sslRequired"`
	RegistrationAllowed                 bool     `json:"registrationAllowed"`
	RegistrationEmailAsUsername         bool     `json:"registrationEmailAsUsername"`
	RememberMe                          bool     `json:"rememberMe"`
	VerifyEmail                         bool     `json:"verifyEmail"`
	LoginWithEmailAllowed               bool     `json:"loginWithEmailAllowed"`
	DuplicateEmailsAllowed              bool     `json:"duplicateEmailsAllowed"`
	ResetPasswordAllowed                bool     `json:"resetPasswordAllowed"`
	EditUsernameAllowed                 bool     `json:"editUsernameAllowed"`
	BruteForceProtected                 bool     `json:"bruteForceProtected"`
	PermanentLockout                    bool     `json:"permanentLockout"`
	MaxFailureWaitSeconds               int      `json:"maxFailureWaitSeconds"`
	MinimumQuickLoginWaitSeconds        int      `json:"minimumQuickLoginWaitSeconds"`
	WaitIncrementSeconds                int      `json:"waitIncrementSeconds"`
	QuickLoginCheckMilliSeconds         int      `json:"quickLoginCheckMilliSeconds"`
	MaxDeltaTimeSeconds                 int      `json:"maxDeltaTimeSeconds"`
	FailureFactor                       int      `json:"failureFactor"`
	DefaultRoles                        []string `json:"defaultRoles"`
	RequiredCredentials                 []string `json:"requiredCredentials"`
	OtpPolicyType                       string   `json:"otpPolicyType"`
	OtpPolicyAlgorithm                  string   `json:"otpPolicyAlgorithm"`
	OtpPolicyInitialCounter             int      `json:"otpPolicyInitialCounter"`
	OtpPolicyDigits                     int      `json:"otpPolicyDigits"`
	OtpPolicyLookAheadWindow            int      `json:"otpPolicyLookAheadWindow"`
	OtpPolicyPeriod                     int      `json:"otpPolicyPeriod"`
	OtpSupportedApplications            []string `json:"otpSupportedApplications"`
	BrowserSecurityHeaders              struct {
		XContentTypeOptions     string `json:"xContentTypeOptions"`
		XRobotsTag              string `json:"xRobotsTag"`
		XFrameOptions           string `json:"xFrameOptions"`
		XXSSProtection          string `json:"xXSSProtection"`
		ContentSecurityPolicy   string `json:"contentSecurityPolicy"`
		StrictTransportSecurity string `json:"strictTransportSecurity"`
	} `json:"browserSecurityHeaders"`
	SmtpServer                SmtpConfig    `json:"smtpServer"`
	EventsEnabled             bool          `json:"eventsEnabled"`
	EventsListeners           []string      `json:"eventsListeners"`
	EnabledEventTypes         []interface{} `json:"enabledEventTypes"`
	AdminEventsEnabled        bool          `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool          `json:"adminEventsDetailsEnabled"`
	IdentityProviders         []struct {
		Alias                       string `json:"alias"`
		InternalID                  string `json:"internalId"`
		ProviderID                  string `json:"providerId"`
		Enabled                     bool   `json:"enabled"`
		UpdateProfileFirstLoginMode string `json:"updateProfileFirstLoginMode"`
		TrustEmail                  bool   `json:"trustEmail"`
		StoreToken                  bool   `json:"storeToken"`
		AddReadTokenRoleOnCreate    bool   `json:"addReadTokenRoleOnCreate"`
		AuthenticateByDefault       bool   `json:"authenticateByDefault"`
		LinkOnly                    bool   `json:"linkOnly"`
		FirstBrokerLoginFlowAlias   string `json:"firstBrokerLoginFlowAlias"`
		Config                      struct {
			HideOnLoginPage string `json:"hideOnLoginPage"`
			ClientID        string `json:"clientId"`
			DisableUserInfo string `json:"disableUserInfo"`
			UserIP          string `json:"userIp"`
			ClientSecret    string `json:"clientSecret"`
			UseJwksURL      string `json:"useJwksUrl"`
		} `json:"config"`
	} `json:"identityProviders"`
	InternationalizationEnabled bool          `json:"internationalizationEnabled"`
	SupportedLocales            []string      `json:"supportedLocales"`
	BrowserFlow                 string        `json:"browserFlow"`
	RegistrationFlow            string        `json:"registrationFlow"`
	DirectGrantFlow             string        `json:"directGrantFlow"`
	ResetCredentialsFlow        string        `json:"resetCredentialsFlow"`
	ClientAuthenticationFlow    string        `json:"clientAuthenticationFlow"`
	DockerAuthenticationFlow    string        `json:"dockerAuthenticationFlow"`
	Attributes                  struct {
		BrowserHeaderXXSSProtection          string `json:"_browser_header.xXSSProtection"`
		BrowserHeaderXFrameOptions           string `json:"_browser_header.xFrameOptions"`
		BrowserHeaderStrictTransportSecurity string `json:"_browser_header.strictTransportSecurity"`
		PermanentLockout                     string `json:"permanentLockout"`
		QuickLoginCheckMilliSeconds          string `json:"quickLoginCheckMilliSeconds"`
		BrowserHeaderXRobotsTag              string `json:"_browser_header.xRobotsTag"`
		MaxFailureWaitSeconds                string `json:"maxFailureWaitSeconds"`
		MinimumQuickLoginWaitSeconds         string `json:"minimumQuickLoginWaitSeconds"`
		FailureFactor                        string `json:"failureFactor"`
		ActionTokenGeneratedByUserLifespan   string `json:"actionTokenGeneratedByUserLifespan"`
		MaxDeltaTimeSeconds                  string `json:"maxDeltaTimeSeconds"`
		BrowserHeaderXContentTypeOptions     string `json:"_browser_header.xContentTypeOptions"`
		ActionTokenGeneratedByAdminLifespan  string `json:"actionTokenGeneratedByAdminLifespan"`
		BruteForceProtected                  string `json:"bruteForceProtected"`
		BrowserHeaderContentSecurityPolicy   string `json:"_browser_header.contentSecurityPolicy"`
		WaitIncrementSeconds                 string `json:"waitIncrementSeconds"`
	} `json:"attributes"`
}

type SmtpConfig struct {
  Port               string `json:"port"`
  Ssl                string `json:"ssl"`
  Starttls           string `json:"starttls"`
  Auth               string `json:"auth"`
  Host               string `json:"host"`
  From               string `json:"from"`
  Password           string `json:"password"`
  User               string `json:"user"`
  ReplyTo            string `json:"replyTo"`
  FromDisplayName    string `json:"fromDisplayName"`
  ReplyToDisplayName string `json:"replyToDisplayName"`
}

func main() {

  //// LOG SPECIFIC INIT ////
  logger := logrus.New()
  logger.SetFormatter(&logrus.TextFormatter{})

  debugLogLevel := os.Getenv("CONFIGURATOR_DEBUGLEVEL")
  if debugLogLevel == "true" {
    logger.SetLevel(logrus.DebugLevel)
  } else {
    logger.SetLevel(logrus.InfoLevel)
  }

  log := logger.WithFields(logrus.Fields{"component":"schoenyer.keycloak.configurator"})
  ///////////////////////////

  apiUrl    := "http://localhost:8080"

  log.info("Configurator started.")

  user      := "admin"
  password  := os.Getenv("KEYCLOAK_PASSWORD")
  if password == "" {
    log.Fatal("Env KEYCLOAK_PASSWORD is not set, will exit.")
  }
  trusted   := []string{os.Getenv("KEYCLOAK_TRUSTED")}
  if len(trusted) == 0 {
    panic("KEYCLOAK_TRUSTED not set. Exit.")
  }

  hostSendingRegistrationRequestMustMatch := false
  clientUrisMustMatch := true

  domainRealm := os.Getenv("DOMAIN_REALM")
  adminName :=  os.Getenv("DOMAIN_ADMINNAME")
  adminPassword := os.Getenv("DOMAIN_ADMINPASSWORD")

  facebookClientId := os.Getenv("FACEBOOK_CLIENTID")
  facebookClientSecret := os.Getenv("FACEBOOK_CLIENTSECRET")

  googleClientId := os.Getenv("GOOGLE_CLIENTID")
  googleClientSecret := os.Getenv("GOOGLE_CLIENTSECRET")

  smtpHost  := os.Getenv("SMTP_HOST")
  smtpPort := os.Getenv("SMTP_PORT")
  smtpUser := os.Getenv("SMTP_USER")
  smtpPassword := os.Getenv("SMTP_PASSWORD")
  smtpFromEmail := os.Getenv("SMTP_FROM_EMAIL")
  smtpFromDisplay := os.Getenv("SMTP_FROM_DISPLAY")
  smtpReplyEmail := os.Getenv("SMTP_REPLY_EMAIL")
  smtpReplyDisplay := os.Getenv("SMTP_REPLY_DISPLAY")

  shouldLoginInternationalisationBeEnabled := os.Getenv("LOGIN_INTERNATIONALISATION")
  availableLoginLocales := []string{"de","en"} //TODO: Fetch those values from parameter

  toBeConfiguredRealm := "master"

  clientConfigurationInterval := 30
  // clientConfigurationInterval := os.Getenv("CLIENT_CONFIGURATION_INTERVAL")
  // if len(clientConfigurationInterval) == 0 {
  //   clientConfigurationInterval := 30
  //   log.WithField("interval",clientConfigurationInterval).Info("Length of interval (in seconds) in which clients are configured wasn't set, will use default interval.")
  // }else{
  //   clientConfigurationInterval := 30   // TODO: Check if really an int value
  //   log.WithField("interval",clientConfigurationInterval).Debug("Length of interval (in seconds) in which clients are configured was set.")
  // }

  if len(domainRealm) != 0 &&
     len(adminName) != 0 &&
     len(adminPassword) != 0 {

     toBeConfiguredRealm = domainRealm
     _, err := registerRealm(apiUrl, user, password, domainRealm, adminName, adminPassword, log)
     if err != nil {
       log.WithFields(logrus.Fields{"realm":domainRealm, "error": err}).Fatal("There was an error when registering custom realm.")
       panic("Error when registering realm, will exit.")
     }
  } else {
    log.WithFields(logrus.Fields{"DOMAIN_REALM":domainRealm,"DOMAIN_ADMINNAME":adminName,"DOMAIN_ADMINPASSWORD":adminPassword}).Warning("Won't register custom realm because one of the three required parameters was not specified.")
  }

  token, err := getBearerToken(apiUrl, user, password, log)
  if err != nil {
    log.WithField("error",err).Error("Couldn't fetch token to do some initial configuration.")
  } else {
    if len(facebookClientId) != 0 &&
       len(facebookClientSecret) != 0 {
         registerFacebookIdentityProvider(apiUrl, toBeConfiguredRealm, facebookClientId, facebookClientSecret, token, log)
    }
    if len(googleClientId) != 0 &&
       len(googleClientSecret) != 0 {
          registerGoogleIdentityProvider(apiUrl, toBeConfiguredRealm, googleClientId, googleClientSecret, token, log)
    }
    if len(smtpHost) != 0 && len(smtpPort) != 0 && len(smtpUser) != 0 && len(smtpPassword) != 0 && len(smtpFromEmail) != 0 {
      enableSmtp(apiUrl, toBeConfiguredRealm, smtpHost, smtpPort, smtpUser, smtpPassword, smtpFromEmail, smtpFromDisplay, smtpReplyEmail, smtpReplyDisplay, token, log)
    }
    if len(shouldLoginInternationalisationBeEnabled) != 0 {
      enableLoginInternationalisation(apiUrl, toBeConfiguredRealm, availableLoginLocales, token, log)
    }
  }

  c, err := getComponents(apiUrl,toBeConfiguredRealm,user,password, log)
  if err != nil {
    log.WithField("realm",toBeConfiguredRealm).Error("Couldn't fetch keycloak components of realm for initial configuration.")
  } else {
    log.Info("Will manipulate trusted hosts policy...")
    trustedhost_response,trustedhost_err := addTrustedHost(apiUrl,toBeConfiguredRealm,user,password,c,hostSendingRegistrationRequestMustMatch,clientUrisMustMatch,trusted,log)
    if err != nil {
      log.WithField("error",trustedhost_err).Error("An error occured when manipulating trusted host policy.")
    } else {
      // TODO: Analyse response whether it was successful or not.
      log.WithField("response",trustedhost_response.Status).Info("Got a response from manipulating trusted host policy.")
    }
    log.Info("Will delete consent required policy...")
    deleteConsentRequiredPolicy(apiUrl,toBeConfiguredRealm,user,password,c, log)
  }

doEvery(time.Duration(clientConfigurationInterval)*time.Second, func(){
  token, err := getBearerToken(apiUrl, user, password, log)
  if err != nil {
		log.WithField("interval",clientConfigurationInterval).Error("Couldn't fetch bearer token thus won't be able to configure clients, will retry in set interval.")
	} else {
    err, clients := getClientsforRealm(apiUrl,toBeConfiguredRealm,user,password, token, log)
    if err != nil {
      log.WithField("interval",clientConfigurationInterval).WithField("realm",toBeConfiguredRealm).Error("Wasn't able to fetch clients of realm, will retry in set interval.")
    } else {
      log.WithField("realm",toBeConfiguredRealm).Info("Will update Clients of specified Realm.")
      for _, client := range clients {
        token, err := getBearerToken(apiUrl, user, password, log)
        if err != nil {
          log.WithField("client",client.ClientID).Error("An error occured when fetching Bearer Token needed to update client. Will skip client until next configuration interval.")
        } else {
          log.WithField("client",client.ClientID).Debug("Updating client.")
          adaptClientDefaults(apiUrl,toBeConfiguredRealm, client, token, log)
          setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"UsertypeMapper","Type","type", token, log)
          setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"CompanyMapper","CompanyId","company", token, log)
          setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"RolesMapper","Roles","roles", token, log)
        }
      }
    }
  }
})


}

func doEvery(d time.Duration, f func()) {
  f()
	for _ = range time.Tick(d) {
		f()
	}
}

func getBearerToken(apiUrl,user ,password string, log *logrus.Entry)(token BearerToken, err error) {

  client := &http.Client{}

  resource := "/auth/realms/master/protocol/openid-connect/token"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("url",apiUrl).Error("An error occurred when preparing the url to fetch the bearer token.")
		return
	}
  u.Path = resource

  form := url.Values{}
  form.Add("client_id","admin-cli")
  form.Add("username", user)
  form.Add("password", password)
  form.Add("grant_type","password")

  req, err := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
	if err != nil {
    log.WithField("error",err).Error("An error occurred when creating request to fetch bearer token.")
		return
	}
  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).Error("An error occurred when fetching the bearer token.")
		return
	}

  defer resp.Body.Close()

  if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		log.WithField("error",err).Error("An error occurred when decoding the received bearer token.")
	}

  return
}


func getClientsforRealm(apiUrl, realm, user,password string,  t BearerToken, log *logrus.Entry) (err error, clients []Client) {

	keycloakgeturl :=  apiUrl + "/auth/admin/realms/" + realm + "/clients"

  log.WithField("url",keycloakgeturl).Debug("Attempting to fetch clients of configured realm from rest api url.")

	req, err := http.NewRequest("GET", keycloakgeturl, nil)
  if err != nil {
		log.WithField("error",err).WithField("realm", realm).Error("Faced an error when building request to fetch available clients on realm.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithField("error",err).WithField("realm", realm).Error("Run into an error when triggering call to fetch clients of realm.")
		return
	}

  if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		log.WithField("error",err).WithField("realm", realm).Error("Couldn't process response from request to fetch clients of realm.")
	}

  defer resp.Body.Close()

	return nil, clients
}

func setMapperForClient(apiUrl, realm, client, mapperName, keycloakUserAttributeName, tokenAttributeName  string, t BearerToken, log *logrus.Entry) (err error) {

  clienturl :=  apiUrl + "/auth/admin/realms/" + realm + "/clients/" + client + "/protocol-mappers/models"

  mapper := &Mapper{Name: mapperName, Protocol: "openid-connect", Config: MapperConf{IDTokenClaim: "true",
		AccessTokenClaim: "true",
		UserinfoTokenClaim: "true",
		UserAttribute: keycloakUserAttributeName,
		ClaimName: tokenAttributeName,
		JSONTypeLabel: "String",
		Multivalued: ""} ,
    ProtocolMapper: "oidc-usermodel-attribute-mapper"}
  m, err := json.Marshal(mapper)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("client", client).Error("Error occured when marshalling request body for attribute mapper of client.")
    return
  }

	req, err := http.NewRequest("POST", clienturl, bytes.NewReader(m))
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("client", client).Error("Error occured when constructing request for attribute mapper of client.")
    return
  }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.WithField("error",err).WithField("realm", realm).WithField("client", client).Error("Request to set Attribute Mapper for client wasn't successful, got an error.")
		return
	}
	defer resp.Body.Close()

	return

}


func getComponents(apiUrl,realm,user,password string, log *logrus.Entry)(components []Component, err error){
  // TODO: Only call if token expired...
  t, err := getBearerToken(apiUrl,user,password,log)
  if err != nil {
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when parsing request uri used to get components for realm.")
		return
	}
  u.Path = resource

  req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when creating http request to get components for realm.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when triggering http request to get components for realm.")
		return
	}

  defer resp.Body.Close()

  err = json.NewDecoder(resp.Body).Decode(&components)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when decoding the response of the http request used to get components for realm.")
		return
	}

  return
}

func deleteComponent(apiUrl,realm,user,password,componentId string, log *logrus.Entry)(resp *http.Response, err error){
  // TODO: only call if token expired...
  t, err := getBearerToken(apiUrl,user,password, log)
  if err != nil {
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components/" + componentId
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when parsing request uri used to delete components for realm.")
		return
	}
  u.Path = resource

  req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when creating http request to delete components for realm.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)

  resp, err = client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when triggering http request to delete components for realm.")
		return
	}

  defer resp.Body.Close()

  return
}

func registerAdminUser(apiUrl,realm,adminuser,adminpassword string, t BearerToken, log *logrus.Entry)(err error){
  client := &http.Client{}
  resource := "/auth/admin/realms/" + realm + "/users"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when parsing request uri used to register admin user for realm.")
		return
	}

  u.Path = resource
  var mapp = make(map[string][]string)
  mapp["realm-management"] = []string{"manage-users"}
  user := &User{ Username: adminuser, Enabled: true, Credentials: []UserCredentials{UserCredentials{ Value: adminpassword, Type: "password"}},
                ClientRoles: mapp}
  userJson, err := json.Marshal(user)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("adminuser",adminuser).Error("There was an error when marshalling user json object used to register admin user for realm.")
    return
  }

  req, err := http.NewRequest("POST", u.String(), bytes.NewReader(userJson))
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("adminuser",adminuser).WithField("adminObject",userJson).Error("There was an error when creating http request to register admin user for realm.")
		return
	}

  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("adminuser",adminuser).Error("There was an error when triggering http request to register admin user for realm.")
		return
	}
  defer resp.Body.Close()

  d, err := getUserDetails(apiUrl,realm,adminuser,t, log)
  if err != nil {
    log.WithField("realm", realm).WithField("adminuser",adminuser).Error("There was an error when getting user details of freshly registered admin user.")
		return
	}
  err, c := getClientsforRealm(apiUrl,realm,adminuser,adminpassword,t, log)
  if err != nil {
    log.WithField("realm", realm).WithField("adminuser",adminuser).Error("There was an error when getting clients of realm to set freshly register admin user as an admin.")
		return
	}

  var realmManagementClientId string
  for i := range c {
    if c[i].ClientID == "realm-management" {
        realmManagementClientId = c[i].ID
        log.WithField("realm", realm).WithField("adminuser",adminuser).WithField("realm management client",realmManagementClientId).Debug("Found realm management client.")
        break
    }
  }

  comps, err := getComposites(apiUrl,realm,d.ID,realmManagementClientId, t, log)
  if err != nil {
    log.WithField("realm", realm).WithField("adminuser",adminuser).WithField("realm management client",realmManagementClientId).Error("There was an error when getting client composit of realm management client to set freshly register admin user as an admin.")
		return
	}

  var comp Composite
  for i := range comps {
    if comps[i].Name == "manage-users" {
        comp = comps[i]
        log.WithField("realm", realm).WithField("adminuser",adminuser).WithField("realm management client",realmManagementClientId).Debug("Found manager user composit of realm management client.")
        break
    }
  }

  err = setComposits(apiUrl,realm,d.ID,realmManagementClientId,comp,t, log)
  log.WithField("error",err).WithField("realm", realm).WithField("adminuser",adminuser).WithField("realm management client",realmManagementClientId).Error("There was an error when setting client composit of realm management client to set freshly register admin user as an admin.")

  return
}

func getUserDetails(apiUrl,realm,username string, t BearerToken, log *logrus.Entry)(details UserDetails, err error){
  client := &http.Client{}
  resource := apiUrl + "/auth/admin/realms/" + realm + "/users?username=" + strings.ToLower(username)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("username",username).Error("There was an error when parsing request uri used to get user details.")
		return
	}

  req, err := http.NewRequest("GET", resource,nil)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("username",username).Error("There was an error when creating http request to get user details.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("username",username).Error("There was an error when triggering http request to get user details.")
		return
	}
  defer resp.Body.Close()

  var users []UserDetails

  err = json.NewDecoder(resp.Body).Decode(&users)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("username",username).Error("There was an error when decoding response of http request to get user details.")
		return
	}

  if len(users) == 0 {
    log.WithField("realm", realm).WithField("username",username).Error("Keycloak didn't return any user details for username.")
  } else if len(users) > 1 {
    log.WithField("realm", realm).WithField("username",username).Error("Keycloak returned user details for more then one user for username.")
    details = users[0]
  } else {
    log.WithField("realm", realm).WithField("username",username).Debug("Keycloak returned the user details for username .")
    details = users[0]
  }

  return
}

func getComposites(apiUrl,realm,userID, technicalClientID string, t BearerToken, log *logrus.Entry)(composits []Composite, err error){
  client := &http.Client{}
  resource := "/auth/admin/realms/" + realm + "/users/" + userID + "/role-mappings/clients/" + technicalClientID + "/available"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientId",technicalClientID).Error("There was an error when parsing request uri used to get composite of client.")
		return
	}

  u.Path = resource

  req, err := http.NewRequest("GET", u.String(),nil)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientId",technicalClientID).Error("There was an error when creating http request to get composite of client.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientId",technicalClientID).Error("There was an error when triggering http request to get composite of client.")
		return
	}
  defer resp.Body.Close()

  //TODO: Check response code
  //println("i got a:", resp.Status, " when trying to get composits for user ", userID," on realm ", realm, " with client ", technicalClientID)

  err = json.NewDecoder(resp.Body).Decode(&composits)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientId",technicalClientID).Error("There was an error when decoding response of http request to get composite of client.")
		return
	}

  return
}

func setComposits(apiUrl,realm,userID, technicalClientID string, composite Composite, t BearerToken, log *logrus.Entry)(err error){
  client := &http.Client{}
  resource := apiUrl + "/auth/admin/realms/" + realm + "/users/" + userID + "/role-mappings/clients/" + technicalClientID
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientID",technicalClientID).Error("There was an error when parsing request uri used to set composite of client.")
		return
	}

  compositeJson, err := json.Marshal([]Composite{composite})
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientID",technicalClientID).WithField("composite",composite).Error("There was an error when encoding body of http request to set composite of client.")
		return
	}


  req, err := http.NewRequest("POST", resource, bytes.NewReader(compositeJson))
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientID",technicalClientID).Error("There was an error when creating http request to set composite of client.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("technicalClientID",technicalClientID).Error("There was an error when triggering http request to set composite of client.")
		return
	}
  defer resp.Body.Close()

  // TODO: check response code

  return
}


func registerRealm(apiUrl, adminuser, adminpassword, domainrealm, domainadminusername, domainadminpassword string, log *logrus.Entry)(components []Component, err error){
  // TODO: handover bearer token to function instead of fetching it inside.
  t, err := getBearerToken(apiUrl, adminuser, adminpassword, log)
  if err != nil {
		return
	}

  client := &http.Client{}
  resource := "/auth/admin/realms/"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", domainrealm).Error("There was an error when parsing request uri used to register realm.")
		return
	}
  u.Path = resource

  realm := &Realm{Enabled: true, ID: domainrealm, Realm: domainrealm }
  realmJson, err := json.Marshal(realm)
  req, err := http.NewRequest("POST", u.String(), bytes.NewReader(realmJson))
	if err != nil {
    log.WithField("error",err).WithField("realm", domainrealm).Error("There was an error when creating http request to register realm.")
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", domainrealm).Error("There was an error when triggering http request to register realm.")
		return
	}

  //println("i got a:", resp.Status, " when registering the realm:", domainrealm)

  defer resp.Body.Close()

  err = registerAdminUser(apiUrl, domainrealm, domainadminusername, domainadminpassword, t, log)
  if err != nil {
    log.WithField("realm", domainrealm).Error("There was an error when registering admin user for newly registered realm.")
		return
	}
  return
}

func adaptClientDefaults(apiUrl,realm string ,c Client, t BearerToken, log *logrus.Entry)(err error){
  httpClient := &http.Client{}
  clientsInfo :=   apiUrl + "/auth/admin/realms/" + realm + "/clients/" + c.ClientID
  c.ServiceAccountsEnabled = true
  c.ImplicitFlowEnabled = true
  c.DirectAccessGrantsEnabled = true

  jsonClient, err := json.Marshal(c)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("client",c).Error("There was an error when parsing request uri used to adapt client defaults.")
		return
	}

  req2, err := http.NewRequest("PUT", clientsInfo, bytes.NewReader(jsonClient))
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("client",c).Error("There was an error when creating http request to adapt client defaults.")
		return
	}

  req2.Header.Add("Accept", "application/json")
  req2.Header.Add("Authorization","Bearer " + t.AccessToken)
  req2.Header.Add("Content-Type", "application/json;charset=UTF-8")
  resp2, err := httpClient.Do(req2)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("client",c).Error("There was an error when triggering http request to adapt client defaults.")
    return
  }

  // TODO: Check response code

  defer resp2.Body.Close()
  return
}


func buildTrustedHostComponent(id string, parentId string, hostSendingRegistrationRequestMustMatch bool, clientUrisMustMatch bool, trustedHosts []string) *TrustedHostsComponent {

  var hsrrmm []string
  if hostSendingRegistrationRequestMustMatch {
     hsrrmm = []string{"true"}
  } else {
    hsrrmm = []string{"false"}
  }

  var cumm []string
  if clientUrisMustMatch {
    cumm = []string{"true"}
  } else {
    cumm = []string{"false"}
  }

  t := new(TrustedHostsComponent)
  t.ID = id
  t.Name = "Trusted Hosts"
  t.ProviderID = "trusted-hosts"
  t.ProviderType = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
  t.ParentID = parentId
  t.SubType = "anonymous"
  t.Config = TrustedHostsConfig{hsrrmm,trustedHosts,cumm}

  return t
}

func addTrustedHost(apiUrl string,realm string,user string,password string, components []Component,hostSendingRegistrationRequestMustMatch bool,clientUrisMustMatch bool,trusted []string, log *logrus.Entry)(resp *http.Response, err error){

  selected := make([]Component,0)
  for _, v := range components {
    if v.ProviderID == "trusted-hosts" {
      selected = append(selected, v)
    }
  }

  if len(selected) > 1 {
    err = errors.New("Multiple components found that match trusted-hosts ID.")
    return
  } else if len(selected) < 1 {
    err = errors.New("No component found that match trusted-hosts ID.")
    return
  }

  c := selected[0]
  thc := buildTrustedHostComponent(c.ID,c.ParentID,hostSendingRegistrationRequestMustMatch,clientUrisMustMatch,trusted)


  // TODO: only call if token expired...
  t, err := getBearerToken(apiUrl,user,password, log)
  if err != nil {
    log.Error("Failed to fetch bearer token in order to add trusted host.")
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components/" + c.ID
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("trustedHosts",trusted).Error("There was an error when parsing request uri used to add trusted hosts.")
		return
	}
  u.Path = resource

  json, err := json.Marshal(thc)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("trustedHosts",trusted).Error("There was an error when encoding request body used to add trusted hosts.")
		return
	}

  req, err := http.NewRequest("PUT", u.String(), strings.NewReader(string(json)))
	if err != nil {
		return
	}
  req.Header.Add("Content-Type", "application/json")
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)

  resp, err = client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("trustedHosts",trusted).Error("There was an error when creating http request to add trusted hosts.")
		return
	}
  defer resp.Body.Close()
  return
}

func deleteConsentRequiredPolicy(apiUrl string,realm string,user string,password string, components []Component, log *logrus.Entry){
  for _, v := range components {
    if v.ProviderID == "consent-required" {
      resp, err := deleteComponent(apiUrl,realm,user,password,v.ID, log)
      if err != nil {
        log.WithField("realm",realm).Error("There was an error when deleting consent required policy of realm.")
    		return
    	} else {
        log.WithField("realm",realm).WithField("status",resp.Status).Info("Deleted consent required policy of realm.")
      }
      // TODO: Check response code of request resp.Status
    }
  }
}

func registerFacebookIdentityProvider(apiUrl, realm, clientId, clientSecret string, t BearerToken, log *logrus.Entry) (err error) {
  facebookProvider := &Provider{
    Alias: "facebook",
    ProviderID: "facebook",
    Enabled: true,
    AuthenticateByDefault: false,
    FirstBrokerLoginFlowAlias: "first broker login",
    PostBrokerLoginFlowAlias: "",
    StoreToken: "",
    AddReadTokenRoleOnCreate: "",
    TrustEmail: true,
    LinkOnly: "",
    Config: ProviderConfig{
      UseJwksURL: "true",
      DisableUserInfo: "",
      HideOnLoginPage: "",
      ClientID: clientId,
      ClientSecret: clientSecret,
      UserIp: ""}}

  p, err := json.Marshal(facebookProvider)
  if err != nil {
    log.WithField("error",err).WithField("realm",realm).Error("There was an error when marshalling the body to register a facebook identity provider.")
    return
  }

	registrationUrl :=  apiUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances"
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when parsing request uri used to register a facebook identity provider.")
    return
  }

  reqType, err := http.NewRequest("POST", registrationUrl, bytes.NewReader(p))
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when creating http request to register a facebook identity provider.")
    return
  }

	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when triggering http request to register a facebook identity provider.")
	} else {
    log.WithField("realm", realm).Info("Successfully registered facebook identity provider.")
  }
  defer resp.Body.Close()
	return
}

func registerGoogleIdentityProvider(apiUrl, realm, clientId, clientSecret string, t BearerToken, log *logrus.Entry) (err error) {
  googleProvider := &Provider{
    Alias: "google",
    ProviderID: "google",
    Enabled: true,
    AuthenticateByDefault: false,
    FirstBrokerLoginFlowAlias: "first broker login",
    PostBrokerLoginFlowAlias: "",
    StoreToken: "",
    AddReadTokenRoleOnCreate: "",
    TrustEmail: true,
    LinkOnly: "",
    Config: ProviderConfig{
      UseJwksURL: "true",
      DisableUserInfo: "",
      HideOnLoginPage: "",
      ClientID: clientId,
      ClientSecret: clientSecret,
      UserIp: ""}}

  p, err := json.Marshal(googleProvider)
  if err != nil {
    log.WithField("error",err).WithField("realm",realm).Error("There was an error when marshalling the body to register a google identity provider.")
    return
  }

	registrationUrl :=  apiUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances"
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when parsing request uri used to register a google identity provider.")
    return
  }

  reqType, err := http.NewRequest("POST", registrationUrl, bytes.NewReader(p))
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when creating http request to register a google identity provider.")
    return
  }

	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when triggering http request to register a google identity provider.")
		return
	} else {
    log.WithField("realm", realm).Info("Successfully registered google identity provider.")
  }
	defer resp.Body.Close()
	return
}

func getRealmConfiguration(apiUrl, realm string, t BearerToken,log *logrus.Entry) (err error, config RealmConfig) {

	keycloakgeturl :=  apiUrl + "/auth/admin/realms/" + realm
	req, err := http.NewRequest("GET", keycloakgeturl, nil)
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when creating http request to get realm configuration.")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when triggering http request to get realm configuration.")
		return
	}

  if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
    log.WithField("error",err).WithField("realm", realm).Error("There was an error when decoding response of http request to get realm configuration.")
	}

  defer resp.Body.Close()

	return nil, config
}

func enableSmtp(apiUrl, realm, host, port, user, password, fromEmailAddress, fromDisplayName, replyToEmailAddress, replyToDisplayName  string, t BearerToken,log *logrus.Entry) (err error) {
  smtpconfig := &SmtpConfig{
    Port: port,
    Ssl: "true",
    Starttls:"",
    Auth:"true",
    Host: host,
    User: user,
    Password: password,
    From: fromEmailAddress,
    FromDisplayName: fromDisplayName,
    ReplyTo: replyToEmailAddress,
    ReplyToDisplayName: replyToEmailAddress}

  err, configuration := getRealmConfiguration(apiUrl, realm, t, log)
  if err != nil {
		log.WithField("realm",realm).WithField("smtpHost",host).Error("There was an error when fetching the realm configuration in order to enable an smtp server.")
		return
	}

  configuration.SmtpServer = *smtpconfig

  c, err := json.Marshal(configuration)
  if err != nil {
    log.WithField("realm",realm).WithField("smtpHost",host).Error("There was an error when marshalling body of request to enable smtp.")
    return
  }

	realmConfigUrl :=  apiUrl + "/auth/admin/realms/" + realm

  reqType, err := http.NewRequest("PUT", realmConfigUrl, bytes.NewReader(c))
  if err != nil {
    log.WithField("realm",realm).WithField("smtpHost",host).Error("There was an error when creating http request to enable smtp.")
    return
  }

	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
    log.WithField("realm",realm).WithField("smtpHost",host).Error("There was an error when triggering http request to enable smtp.")
	} else {
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      log.WithField("realm",realm).WithField("smtpHost",host).Info("Successfully enabled Smtp Server.")
    } else {
      log.WithField("realm",realm).WithField("smtpHost",host).WithField("statusCode",resp.StatusCode).WithField("status",resp.Status).Info("Tried to enable smtp server but got non-success response.")
    }
  }
	defer resp.Body.Close()
	return
}

func enableLoginInternationalisation(apiUrl, realm string, supportedLocales []string, t BearerToken,log *logrus.Entry) (err error) {
  err, configuration := getRealmConfiguration(apiUrl, realm, t, log)
  if err != nil {
    log.WithField("realm",realm).WithField("supportedLocales",supportedLocales).Error("There was an error when fetching the realm configuration in order to enable internationalisation for Login.")
    return
  }
  configuration.InternationalizationEnabled = true
  configuration.SupportedLocales = supportedLocales

  c, err := json.Marshal(configuration)
  if err != nil {
    log.WithField("realm",realm).WithField("supportedLocales",supportedLocales).Error("There was an error when marshalling body of request to enable internationalisation for Login.")
    return
  }

	realmConfigUrl :=  apiUrl + "/auth/admin/realms/" + realm

  reqType, err := http.NewRequest("PUT", realmConfigUrl, bytes.NewReader(c))
  if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("supportedLocales",supportedLocales).Error("There was an error when creating http request to enable internationalisation.")
    return
  }

	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
    log.WithField("error",err).WithField("realm", realm).WithField("supportedLocales",supportedLocales).Error("There was an error when triggering http request to enable internationalisation.")
	} else {
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      log.WithField("realm",realm).WithField("supportedLocales",supportedLocales).Info("Successfully enabled internationalisation.")
    } else {
      log.WithField("realm",realm).WithField("supportedLocales",supportedLocales).WithField("statusCode",resp.StatusCode).WithField("status",resp.Status).Info("Tried to enable internationalisation but got non-success response.")
    }
  }
	defer resp.Body.Close()

	return
}
