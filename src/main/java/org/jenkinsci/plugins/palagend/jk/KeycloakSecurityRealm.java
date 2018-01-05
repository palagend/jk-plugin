package org.jenkinsci.plugins.palagend.jk;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.ServerRequest.HttpFailure;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.kohsuke.stapler.*;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author huyh
 */
public class KeycloakSecurityRealm extends SecurityRealm {

    private static final String JENKINS_COMMENCE_LOGIN_URL = "securityRealm/commenceLogin";
    private static final String JENKINS_FINISH_LOGIN_URL = "securityRealm/finishLogin";
    private static final String REFERER_ATTRIBUTE = KeycloakSecurityRealm.class.getName() + ".referer";

    private static final Logger LOGGER = Logger.getLogger(KeycloakSecurityRealm.class.getName());

    private KeycloakDeployment keycloakDeployment;
    private String keycloakJson;

    @DataBoundConstructor
    public KeycloakSecurityRealm(String keycloakJson) throws IOException {
        super();
        this.keycloakJson = keycloakJson;
        AdapterConfig adapterConfig = JsonSerialization.readValue(keycloakJson, AdapterConfig.class);
        keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfig);
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, StaplerResponse response, @Header("Referer") final String referer)
            throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        String redirect = redirectUrl(request);

        String state = UUID.randomUUID().toString();
        String authUrl = keycloakDeployment.getAuthUrl().clone()
                .queryParam(OAuth2Constants.CLIENT_ID, keycloakDeployment.getResourceName())
                .queryParam(OAuth2Constants.REDIRECT_URI, redirect)
                .queryParam(OAuth2Constants.RESPONSE_TYPE, "code")
                .queryParam(OAuth2Constants.STATE, state)
                .build().toString();
        LOGGER.info("In doCommenceLogin, the authUrl is: " + authUrl);
        return new HttpRedirect(authUrl);

    }


    private String redirectUrl(StaplerRequest request) {
        KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(request.getRequestURL().toString())
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .path(JENKINS_FINISH_LOGIN_URL);
        String redirect = builder.toTemplate();
        return redirect;
    }

    public HttpResponse doFinishLogin(StaplerRequest request) {

        String redirect = redirectUrl(request);

        try {
            AccessTokenResponse tokenResponse = ServerRequest.invokeAccessCodeToToken(keycloakDeployment, request.getParameter("code"), redirect, null);
            String tokenString = tokenResponse.getToken();
            String idTokenString = tokenResponse.getIdToken();
            String refreshToken = tokenResponse.getRefreshToken();
            String kid = null;
            HttpGet get = new HttpGet(keycloakDeployment.getJwksUrl());
            HttpClient client = keycloakDeployment.getClient();
            org.apache.http.HttpResponse response = client.execute(get);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {
                HttpEntity httpEntity = response.getEntity();
                if (httpEntity != null) {
                    JSONWebKeySet jsonWebKeySet = JsonSerialization.readValue(httpEntity.getContent(), JSONWebKeySet.class);
                    kid = JWKSUtils.getKeyForUse(jsonWebKeySet, JWK.Use.SIG).getKeyId();
                }
            }

            String realmUrl = keycloakDeployment.getRealmInfoUrl();
            AccessToken token = RSATokenVerifier.verifyToken(tokenString, keycloakDeployment.getPublicKeyLocator().getPublicKey(kid, keycloakDeployment), realmUrl);
            if (idTokenString != null) {
                JWSInput input = new JWSInput(idTokenString);

                IDToken idToken = input.readJsonContent(IDToken.class);
                SecurityContextHolder.getContext().setAuthentication(new KeycloakAuthentication(idToken, token, refreshToken));

                User currentUser = User.current();
                currentUser.setFullName(idToken.getPreferredUsername());

                if (!currentUser.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
                    currentUser.addProperty(new Mailer.UserProperty(idToken.getEmail()));
                }
            }

        } catch (HttpFailure failure) {
            LOGGER.log(Level.SEVERE, "status: " + failure.getStatus() + "\terror: " + failure.getError());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Authentication Exception", e);
        }

        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        }
        return HttpResponses.redirectToContextRoot();
    }

    /*
     * (non-Javadoc)
     *
     * @see hudson.security.SecurityRealm#allowsSignup()
     */
    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof KeycloakAuthentication)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }

    @Override
    public String getLoginUrl() {
        return JENKINS_COMMENCE_LOGIN_URL;
    }

    @Override
    public void doLogout(StaplerRequest req, StaplerResponse rsp)
            throws IOException, ServletException {
        KeycloakAuthentication keycloakAuthentication = (KeycloakAuthentication) SecurityContextHolder.getContext().getAuthentication();
        try {
            ServerRequest.invokeLogout(this.keycloakDeployment, keycloakAuthentication.getRefreshToken());
            super.doLogout(req, rsp);
        } catch (HttpFailure e) {
            LOGGER.log(Level.SEVERE, "Logout Exception ", e);
        }
    }

    public String getKeycloakJson() {
        return keycloakJson;
    }

    public void setKeycloakJson(String keycloakJson) {
        this.keycloakJson = keycloakJson;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        @Override
        public String getHelpFile() {
            return "/plugin/keycloak/help/help-security-realm.html";
        }

        @Override
        public String getDisplayName() {
            return "Keycloak Authentication Plugin";
        }
    }
}
