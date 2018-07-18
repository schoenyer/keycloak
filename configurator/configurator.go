package main

import (
  //"github.com/docopt/docopt.go"
  "os"
  "encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
  "strings"
  "errors"
  "bytes"
  	"time"
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

  apiUrl    := "http://localhost:8080"

  user      := "admin"
  password  := os.Getenv("KEYCLOAK_PASSWORD")
  if password == "" {
    panic("KEYCLOAK_PASSWORD not set. Exit.")
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

  if len(domainRealm) != 0 &&
     len(adminName) != 0 &&
     len(adminPassword) != 0 {

     toBeConfiguredRealm = domainRealm
     _, err := registerRealm(apiUrl, user, password, domainRealm, adminName, adminPassword)
     if err != nil {
       fmt.Println("There was an error when registering custom realm ",domainRealm," : ",err)
       panic("Error when registering realm, will exit.")
     }
  } else {
    fmt.Println("Won't register custom realm because one of the three required parameters was not specified: DOMAIN_REALM(",domainRealm,") DOMAIN_ADMINNAME(",adminName,") DOMAIN_ADMINPASSWORD(",adminPassword,")")
  }

  token, err := getBearerToken(apiUrl, user, password)
  if err != nil {
    fmt.Println("Couldn't fetch token to do some initial configuration: ",err)
  } else {
    if len(facebookClientId) != 0 &&
       len(facebookClientSecret) != 0 {
         registerFacebookIdentityProvider(apiUrl, toBeConfiguredRealm, facebookClientId, facebookClientSecret, token)
    }
    if len(googleClientId) != 0 &&
       len(googleClientSecret) != 0 {
          registerGoogleIdentityProvider(apiUrl, toBeConfiguredRealm, googleClientId, googleClientSecret, token)
    }
    if len(smtpHost) != 0 && len(smtpPort) != 0 && len(smtpUser) != 0 && len(smtpPassword) != 0 && len(smtpFromEmail) != 0 {
      enableSmtp(apiUrl, toBeConfiguredRealm, smtpHost, smtpPort, smtpUser, smtpPassword, smtpFromEmail, smtpFromDisplay, smtpReplyEmail, smtpReplyDisplay, token)
    }
    if len(shouldLoginInternationalisationBeEnabled) != 0 {
      enableLoginInternationalisation(apiUrl, toBeConfiguredRealm, availableLoginLocales, token)
    }
  }

  c, err := getComponents(apiUrl,toBeConfiguredRealm,user,password)
  if err != nil {
    fmt.Println(err)
  } else {
    fmt.Println("Will manipulate trusted hosts policy...")
    trustedhost_response,trustedhost_err := addTrustedHost(apiUrl,toBeConfiguredRealm,user,password,c,hostSendingRegistrationRequestMustMatch,clientUrisMustMatch,trusted)
    if err != nil {
      fmt.Println(trustedhost_err)
    } else {
      fmt.Println("Response from trusted host manipulation request: " + trustedhost_response.Status)
    }
    fmt.Println("Will delete consent required policy...")
    deleteConsentRequiredPolicy(apiUrl,toBeConfiguredRealm,user,password,c)
  }

doEvery(30*time.Second, func(){

    token, err := getBearerToken(apiUrl, user, password)
    if err != nil {
  		fmt.Println(err)
  	}
  _, clients := getClientsforRealm(apiUrl,toBeConfiguredRealm,user,password, token)
  for _, client := range clients {
    fmt.Println("Updating Client:", client.ClientID)
    adaptClientDefaults(apiUrl,toBeConfiguredRealm, client, token)
    setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"UsertypeMapper","Type","type", token)
    token, err := getBearerToken(apiUrl, user, password)
    if err != nil {
      fmt.Println(err)
    }
    setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"CompanyMapper","CompanyId","company", token)
    setMapperForClient(apiUrl,toBeConfiguredRealm, client.ClientID,"RolesMapper","Roles","roles", token)
}})


}

func doEvery(d time.Duration, f func()) {
  f()
	for _ = range time.Tick(d) {
		f()
	}
}

func getBearerToken(apiUrl,user ,password string)(token BearerToken, err error) {

  client := &http.Client{}

  resource := "/auth/realms/master/protocol/openid-connect/token"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
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
		return
	}
  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

  resp, err := client.Do(req)
	if err != nil {
		return
	}

  defer resp.Body.Close()

  if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		log.Println(err)
	}

  return
}


func getClientsforRealm(apiUrl, realm, user,password string,  t BearerToken) (err error, clients []Client) {
	fmt.Println("Getting clients for realm ", realm)


	keycloakgeturl :=  apiUrl + "/auth/admin/realms/" + realm + "/clients"
	fmt.Println("URL:>", keycloakgeturl)
	req, err := http.NewRequest("GET", keycloakgeturl, nil)
  if err != nil {
		fmt.Println("Got an error when building request: ", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Keycloak REST GET clients error: ", err)
		return
	}

  if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		fmt.Println("Keycloak REST json clients unmarshal error: ", err)
	}

  defer resp.Body.Close()

	return nil, clients

}

func setMapperForClient(apiUrl, realm, client, mapperName, keycloakUserAttributeName, tokenAttributeName  string, t BearerToken) (err error) {

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
    fmt.Println("Error occured when marshalling request body for attribute mapper of client", client, ": ", err)
    return
  }

	req, err := http.NewRequest("POST", clienturl, bytes.NewReader(m))
  if err != nil {
    fmt.Println("Error occured when constructing request for attribute mapper of client", client, ": ", err)
    return
  }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	httpClient := &http.Client{}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println("Request to set Attribute Mapper for client", client, " wasn't successful, error: ", err, " (response --> ", resp, ")")
		return
	}
	defer resp.Body.Close()

	return

}


func getComponents(apiUrl,realm,user,password string)(components []Component, err error){
  // only call if token expired...
  t, err := getBearerToken(apiUrl,user,password)
  if err != nil {
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}
  u.Path = resource

  req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)

  resp, err := client.Do(req)
	if err != nil {
		return
	}

  defer resp.Body.Close()

  err = json.NewDecoder(resp.Body).Decode(&components)
  if err != nil {
		return
	}

  return
}

func deleteComponent(apiUrl,realm,user,password,componentId string)(resp *http.Response, err error){
  // only call if token expired...
  t, err := getBearerToken(apiUrl,user,password)
  if err != nil {
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components/" + componentId
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}
  u.Path = resource

  req, err := http.NewRequest("DELETE", u.String(), nil)
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)

  resp, err = client.Do(req)
	if err != nil {
		return
	}

  defer resp.Body.Close()

  return
}

func registerAdminUser(apiUrl,realm,adminuser,adminpassword string, t BearerToken)(err error){
  client := &http.Client{}
  resource := "/auth/admin/realms/" + realm + "/users"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}

  u.Path = resource
  var mapp = make(map[string][]string)
  mapp["realm-management"] = []string{"manage-users"}
  user := &User{ Username: adminuser, Enabled: true, Credentials: []UserCredentials{UserCredentials{ Value: adminpassword, Type: "password"}},
                ClientRoles: mapp}
  userJson, err := json.Marshal(user)

  fmt.Println(string(userJson))
  req, err := http.NewRequest("POST", u.String(), bytes.NewReader(userJson))
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
		return
	}
  defer resp.Body.Close()

  //println("i got a:", resp.Status, " when trying to create the admin user for domain:", realm)

  d, err := getUserDetails(apiUrl,realm,adminuser,t)
  if err != nil {
		return
	}
  err, c := getClientsforRealm(apiUrl,realm,adminuser,adminpassword,t)
  if err != nil {
    println("Got error when fetching clients: ", err)
		return
	}

  var realmManagementClientId string
  for i := range c {
    if c[i].ClientID == "realm-management" {
        realmManagementClientId = c[i].ID
      //  println("Found client id for realm-management client of realm ",realm,": ",realmManagementClientId)
        break
    }
  }

  comps, err := getComposites(apiUrl,realm,d.ID,realmManagementClientId, t)
  if err != nil {
		return
	}

  var comp Composite
  for i := range comps {
    if comps[i].Name == "manage-users" {
        comp = comps[i]
        println("Got manage-users composite")
        break
    }
  }

  err = setComposits(apiUrl,realm,d.ID,realmManagementClientId,comp,t)

  return
}

func getUserDetails(apiUrl,realm,username string, t BearerToken)(details UserDetails, err error){
  client := &http.Client{}
  resource := apiUrl + "/auth/admin/realms/" + realm + "/users?username=" + strings.ToLower(username)
  if err != nil {
		return
	}
fmt.Println(resource)
  req, err := http.NewRequest("GET", resource,nil)
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
		return
	}
  defer resp.Body.Close()

  // println("i got a:", resp.Status, " when trying to get details of the user ",username," in realm ", realm)

  var users []UserDetails

  err = json.NewDecoder(resp.Body).Decode(&users)
  if err != nil {
		return
	}

  if len(users) == 0 {
    println("IDP didn't return any user details for username ", username)
  } else if len(users) > 1 {
    println("IDP returend more then one user for username ", username)
    details = users[0]
  } else {
    println("IDP returned the details of one user for username ", username)
    details = users[0]
  }

  return
}

func getComposites(apiUrl,realm,userID, technicalClientID string, t BearerToken)(composits []Composite, err error){
  client := &http.Client{}
  resource := "/auth/admin/realms/" + realm + "/users/" + userID + "/role-mappings/clients/" + technicalClientID + "/available"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}

  u.Path = resource

  req, err := http.NewRequest("GET", u.String(),nil)
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
		return
	}
  defer resp.Body.Close()

  //println("i got a:", resp.Status, " when trying to get composits for user ", userID," on realm ", realm, " with client ", technicalClientID)

  err = json.NewDecoder(resp.Body).Decode(&composits)
  if err != nil {
		return
	}

  return
}

func setComposits(apiUrl,realm,userID, technicalClientID string, composite Composite, t BearerToken)(err error){
  client := &http.Client{}
  resource := apiUrl + "/auth/admin/realms/" + realm + "/users/" + userID + "/role-mappings/clients/" + technicalClientID
  if err != nil {
		return
	}

  compositeJson, err := json.Marshal([]Composite{composite})
  if err != nil {
		return
	}


  req, err := http.NewRequest("POST", resource, bytes.NewReader(compositeJson))
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
		return
	}
  defer resp.Body.Close()

  //println("i got a:", resp.Status, " when trying to set user management role for user ", userID, " with realm-management client ",technicalClientID, " on realm ", realm)

  return
}


func registerRealm(apiUrl, adminuser, adminpassword, domainrealm, domainadminusername, domainadminpassword string)(components []Component, err error){
  t, err := getBearerToken(apiUrl, adminuser, adminpassword)
  if err != nil {
		return
	}
  client := &http.Client{}
  resource := "/auth/admin/realms/"
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}
  u.Path = resource

  realm := &Realm{Enabled: true, ID: domainrealm, Realm: domainrealm }
  realmJson, err := json.Marshal(realm)
  req, err := http.NewRequest("POST", u.String(), bytes.NewReader(realmJson))
	if err != nil {
		return
	}
  req.Header.Add("Accept", "application/json")
  req.Header.Add("Authorization","Bearer " + t.AccessToken)
  req.Header.Add("Content-Type", "application/json;charset=UTF-8")

  resp, err := client.Do(req)
	if err != nil {
		return
	}

  //println("i got a:", resp.Status, " when registering the realm:", domainrealm)

  defer resp.Body.Close()

  err = registerAdminUser(apiUrl, domainrealm, domainadminusername, domainadminpassword, t)
  if err != nil {
		return
	}
  return
}

func adaptClientDefaults(apiUrl,realm string ,c Client, t BearerToken)(err error){
  httpClient := &http.Client{}
  clientsInfo :=   apiUrl + "/auth/admin/realms/" + realm + "/clients/" + c.ClientID
  c.ServiceAccountsEnabled = true
  c.ImplicitFlowEnabled = true
  c.DirectAccessGrantsEnabled = true
  jsonClient, err := json.Marshal(c)
  if err != nil {
		return
	}

  req2, err := http.NewRequest("PUT", clientsInfo, bytes.NewReader(jsonClient))
  req2.Header.Add("Accept", "application/json")
  req2.Header.Add("Authorization","Bearer " + t.AccessToken)
  req2.Header.Add("Content-Type", "application/json;charset=UTF-8")
  resp2, err := httpClient.Do(req2)
  if err != nil {
    return
  }

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

func addTrustedHost(apiUrl string,realm string,user string,password string, components []Component,hostSendingRegistrationRequestMustMatch bool,clientUrisMustMatch bool,trusted []string)(resp *http.Response, err error){

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


  // only call if token expired...
  t, err := getBearerToken(apiUrl,user,password)
  if err != nil {
		return
	}

  client := &http.Client{}

  resource := "/auth/admin/realms/" + realm + "/components/" + c.ID
  u, err := url.ParseRequestURI(apiUrl)
  if err != nil {
		return
	}
  u.Path = resource

  json, err := json.Marshal(thc)
  if err != nil {
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
		return
	}
  defer resp.Body.Close()
  return
}

func deleteConsentRequiredPolicy(apiUrl string,realm string,user string,password string, components []Component){
  for _, v := range components {
    if v.ProviderID == "consent-required" {
      resp, err := deleteComponent(apiUrl,realm,user,password,v.ID)
      if err != nil {
    		return
    	}
      println("Response from consent-required policy delete request: " + resp.Status)
    }
  }
}

func registerFacebookIdentityProvider(apiUrl, realm, clientId, clientSecret string, t BearerToken) (err error) {
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

	registrationUrl :=  apiUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances"

  reqType, err := http.NewRequest("POST", registrationUrl, bytes.NewReader(p))
	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
		fmt.Println("Keycloak REST POST to register facebook identity provider error: ", err)
		return
	} else {
    fmt.Println("Successfully registered Facebook Identity Provider.")
  }
	defer resp.Body.Close()

	return
}

func registerGoogleIdentityProvider(apiUrl, realm, clientId, clientSecret string, t BearerToken) (err error) {
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

	registrationUrl :=  apiUrl + "/auth/admin/realms/" + realm + "/identity-provider/instances"

  reqType, err := http.NewRequest("POST", registrationUrl, bytes.NewReader(p))
	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
		fmt.Println("Keycloak REST POST to register google identity provider error: ", err)
		return
	} else {
    fmt.Println("Successfully registered Google Identity Provider.")
  }
	defer resp.Body.Close()

	return
}

func getRealmConfiguration(apiUrl, realm string, t BearerToken) (err error, config RealmConfig) {
	fmt.Println("Getting realm configuration of realm ", realm)

	keycloakgeturl :=  apiUrl + "/auth/admin/realms/" + realm
	fmt.Println("URL:>", keycloakgeturl)
	req, err := http.NewRequest("GET", keycloakgeturl, nil)
  if err != nil {
		fmt.Println("Got an error when building request: ", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+t.AccessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Keycloak REST GET realm config error: ", err)
		return
	}

  if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		fmt.Println("Keycloak REST json realm config unmarshal error: ", err)
	}

  defer resp.Body.Close()

	return nil, config

}

func enableSmtp(apiUrl, realm, host, port, user, password, fromEmailAddress, fromDisplayName, replyToEmailAddress, replyToDisplayName  string, t BearerToken) (err error) {
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

  err, configuration := getRealmConfiguration(apiUrl, realm, t)
  if err != nil {
		fmt.Println("There was an error when fetching the realm configuration: ", err)
		return
	}

  configuration.SmtpServer = *smtpconfig

  c, err := json.Marshal(configuration)

	realmConfigUrl :=  apiUrl + "/auth/admin/realms/" + realm

  reqType, err := http.NewRequest("PUT", realmConfigUrl, bytes.NewReader(c))
	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
		fmt.Println("Keycloak REST POST to enable SMTP server throw an error: ", err)
		return
	} else {
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      fmt.Println("Successfully enabled Smtp Server.")
    } else {
      fmt.Println("Tried to enable Smtp Server, but got response: ", resp.Status)
    }
  }
	defer resp.Body.Close()

	return

}

func enableLoginInternationalisation(apiUrl, realm string, supportedLocales []string, t BearerToken) (err error) {
  err, configuration := getRealmConfiguration(apiUrl, realm, t)
  if err != nil {
    fmt.Println("There was an error when fetching the realm configuration: ", err)
    return
  }
  configuration.InternationalizationEnabled = true
  configuration.SupportedLocales = supportedLocales

  c, err := json.Marshal(configuration)

	realmConfigUrl :=  apiUrl + "/auth/admin/realms/" + realm

  reqType, err := http.NewRequest("PUT", realmConfigUrl, bytes.NewReader(c))
	reqType.Header.Set("Content-Type", "application/json")
	reqType.Header.Set("Authorization", "bearer " + t.AccessToken)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqType)
	if err != nil {
		fmt.Println("Keycloak REST POST to enable internationalisation for login throw an error: ", err)
		return
	} else {
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      fmt.Println("Successfully enabled internationalisation for login.")
    } else {
      fmt.Println("Tried to enable internationalisation for login, but got response: ", resp.Status)
    }
  }
	defer resp.Body.Close()

	return
}
