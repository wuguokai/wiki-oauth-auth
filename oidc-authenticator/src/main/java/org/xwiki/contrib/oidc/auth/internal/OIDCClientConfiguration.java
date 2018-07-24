/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.oidc.auth.internal;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.joda.time.LocalDateTime;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Session;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.OIDCIdToken;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.event.OAuth2AccessToken;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.endpoint.AuthorizationOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.TokenOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.UserInfoOIDCEndpoint;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.properties.ConverterManager;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Various OpenID Connect authenticator configurations.
 *
 * @version $Id$
 */
@Component(roles = OIDCClientConfiguration.class)
@Singleton
public class OIDCClientConfiguration {
    public static final String PROP_XWIKIPROVIDER = "oidc.xwikiprovider";

    public static final String PROP_USER_NAMEFORMATER = "oidc.user.nameFormater";

    public static final String DEFAULT_USER_NAMEFORMATER = "${oidc.issuer.host.clean}-${oidc.user.subject.clean}";

    public static final String PROPPREFIX_ENDPOINT = "oidc.endpoint.";

    public static final String PROP_ENDPOINT_AUTHORIZATION = PROPPREFIX_ENDPOINT + AuthorizationOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_TOKEN = PROPPREFIX_ENDPOINT + TokenOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_USERINFO = PROPPREFIX_ENDPOINT + UserInfoOIDCEndpoint.HINT;

    public static final String PROP_CLIENTID = "oidc.clientid";

    public static final String PROP_CLIENTSECRET = "oidc.clientsecret";

    public static final String CHOERODON_TOKEN = "oidc.wiki.token";

    public static final String PROP_CUSTOMSCOPE = "oidc.customscope";

    public static final String PROP_SKIPPED = "oidc.skipped";

    public static final String PROP_USERINFOCLAIMS = "oidc.userinfoclaims";

    public static final List<String> DEFAULT_USERINFOCLAIMS = Arrays.asList(OIDCUserInfo.CLAIM_XWIKI_ACCESSIBILITY,
            OIDCUserInfo.CLAIM_XWIKI_COMPANY, OIDCUserInfo.CLAIM_XWIKI_DISPLAYHIDDENDOCUMENTS,
            OIDCUserInfo.CLAIM_XWIKI_EDITOR, OIDCUserInfo.CLAIM_XWIKI_USERTYPE);

    public static final String PROP_IDTOKENCLAIMS = "oidc.idtokenclaims";

    public static final List<String> DEFAULT_IDTOKENCLAIMS = Arrays.asList(OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID);

    public static final String PROP_INITIAL_REQUEST = "xwiki.initialRequest";

    public static final String PROP_STATE = "oidc.state";

    public static final String PROP_SESSION_ACCESSTOKEN = "oidc.accesstoken";

    public static final String PROP_SESSION_OAUTH2ACCESSTOKEN = "oidc.oauth2.accesstoken";

    public static final String PROP_SESSION_IDTOKEN = "oidc.idtoken";

    public static final String PROP_SESSION_USERINFO_EXPORATIONDATE = "oidc.session.userinfoexpirationdate";

    @Inject
    private InstanceIdManager instance;

    @Inject
    private OIDCManager manager;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;

    @Inject
    // TODO: store configuration in custom objects
    private ConfigurationSource configuration;

    private HttpSession getHttpSession() {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            return ((ServletSession) session).getHttpSession();
        }

        return null;
    }

    private <T> T getSessionAttribute(String name) {
        HttpSession session = getHttpSession();
        if (session != null) {
            return (T) session.getAttribute(name);
        }

        return null;
    }

    private <T> T removeSessionAttribute(String name) {
        HttpSession session = getHttpSession();
        if (session != null) {
            try {
                return (T) session.getAttribute(name);
            } finally {
                session.removeAttribute(name);
            }
        }

        return null;
    }

    private void setSessionAttribute(String name, Object value) {
        HttpSession session = getHttpSession();
        if (session != null) {
            session.setAttribute(name, value);
        }
    }

    private String getRequestParameter(String key) {
        Request request = this.container.getRequest();
        if (request != null) {
            return (String) request.getProperty(key);
        }

        return null;
    }

    public <T> T getProperty(String key, Class<T> valueClass) {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(valueClass, requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, valueClass);
    }

    private <T> T getProperty(String key, T def) {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(def.getClass(), requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, def);
    }

    public String getUserNameFormater() {
        String userFormatter = getProperty(PROP_USER_NAMEFORMATER, String.class);
        if (userFormatter == null) {
            userFormatter = DEFAULT_USER_NAMEFORMATER;
        }

        return userFormatter;
    }

    public URL getXWikiProvider() {
        return getProperty(PROP_XWIKIPROVIDER, URL.class);
    }

    private URI getEndPoint(String hint) throws URISyntaxException, MalformedURLException {
        URL endpoint = getProperty(PROPPREFIX_ENDPOINT + hint, URL.class);

        // If no direct endpoint is provider assume it's a XWiki OIDC provider and generate the endpoint from the hint
        if (endpoint == null) {
            URL provider = getXWikiProvider();
            if (provider != null) {
                endpoint = this.manager.createEndPointURI(getXWikiProvider().toURI().toString(), hint).toURL();
            }
        }

        return endpoint == null ? null : endpoint.toURI();
    }

    public URI getAuthorizationOIDCEndpoint() throws URISyntaxException, MalformedURLException {
        return getEndPoint(AuthorizationOIDCEndpoint.HINT);
    }

    public URI getTokenOIDCEndpoint() throws URISyntaxException, MalformedURLException {
        return getEndPoint(TokenOIDCEndpoint.HINT);
    }

    public URI getUserInfoOIDCEndpoint() throws URISyntaxException, MalformedURLException {
        return getEndPoint(UserInfoOIDCEndpoint.HINT);
    }

    public ClientID getClientID() {
        String clientId = getProperty(PROP_CLIENTID, String.class);

        // Fallback on instance id
        return new ClientID(clientId != null ? clientId : this.instance.getInstanceId().getInstanceId());
    }

    public String getClientSecret() {
        return getProperty(PROP_CLIENTSECRET, String.class);
    }

    public String getChoerodonToken() {
        return getProperty(CHOERODON_TOKEN, String.class);
    }

    public State getSessionState() {
        return getSessionAttribute(PROP_STATE);
    }

    public boolean isSkipped() {
        return getProperty(PROP_SKIPPED, false);
    }

    /**
     * @since 1.2
     */
    public ClaimsRequest getClaimsRequest() {
        // TODO: allow passing the complete JSON as configuration
        ClaimsRequest claimsRequest = new ClaimsRequest();

        // ID Token claims
        List<String> idtokenclaims = getIDTokenClaims();
        if (idtokenclaims != null && !idtokenclaims.isEmpty()) {
            // ID Token claims
            for (String claim : idtokenclaims) {
                claimsRequest.addIDTokenClaim(claim);
            }
        }

        // UserInfo claims
        List<String> userinfoclaims = getUserInfoClaims();
        if (userinfoclaims != null && !userinfoclaims.isEmpty()) {
            for (String claim : userinfoclaims) {
                claimsRequest.addUserInfoClaim(claim);
            }
        }

        return claimsRequest;
    }

    /**
     * @since 1.2
     */
    public List<String> getIDTokenClaims() {
        return getProperty(PROP_USERINFOCLAIMS, DEFAULT_IDTOKENCLAIMS);
    }

    /**
     * @since 1.2
     */
    public List<String> getUserInfoClaims() {
        return getProperty(PROP_IDTOKENCLAIMS, DEFAULT_USERINFOCLAIMS);
    }

    /**
     * @since 1.2
     */
    public int getUserInfoRefreshRate() {
        return getProperty(PROP_IDTOKENCLAIMS, 600000);
    }

    /**
     * @since 1.2
     */
    public Scope getScope() {
        return new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL, OIDCScopeValue.ADDRESS,
                OIDCScopeValue.PHONE);
    }

    public Scope getCustomScope() {
        String customScope = getProperty(PROP_CUSTOMSCOPE, String.class);
        if (customScope != null && !"".equals(customScope)) {
            return new Scope(OIDCScopeValue.OPENID, new Scope.Value(customScope));
        }
        return new Scope(OIDCScopeValue.OPENID);
    }

    // Session only

    /**
     * @since 1.2
     */
    public Date removeUserInfoExpirationDate() {
        return removeSessionAttribute(PROP_SESSION_USERINFO_EXPORATIONDATE);
    }

    /**
     * @since 1.2
     */
    public void setUserInfoExpirationDate(Date date) {
        setSessionAttribute(PROP_SESSION_USERINFO_EXPORATIONDATE, date);
    }

    /**
     * @since 1.2
     */
    public void resetUserInfoExpirationDate() {
        LocalDateTime expiration = LocalDateTime.now().plusMillis(getUserInfoRefreshRate());

        setUserInfoExpirationDate(expiration.toDate());
    }

    /**
     * @since 1.2
     */
    public BearerAccessToken getAccessToken() {
        return getSessionAttribute(PROP_SESSION_ACCESSTOKEN);
    }

    /**
     * @since 1.2
     */
    public void setAccessToken(BearerAccessToken accessToken) {
        setSessionAttribute(PROP_SESSION_ACCESSTOKEN, accessToken);
    }

    public void setOAuth2AccessToken(OAuth2AccessToken accessToken) {
        setSessionAttribute(PROP_SESSION_OAUTH2ACCESSTOKEN, accessToken);
    }

    public OAuth2AccessToken getOauth2AccessToken() {
        return getSessionAttribute(PROP_SESSION_OAUTH2ACCESSTOKEN);
    }

    /**
     * @since 1.2
     */
    public IDTokenClaimsSet getIdToken() {
        return getSessionAttribute(PROP_SESSION_IDTOKEN);
    }

    /**
     * @since 1.2
     */
    public void setIdToken(IDTokenClaimsSet idToken) {
        setSessionAttribute(PROP_SESSION_IDTOKEN, idToken);
    }

    /**
     * @since 1.2
     */
    public URI getSuccessRedirectURI() {
        URI uri = getSessionAttribute(PROP_INITIAL_REQUEST);
        if (uri == null) {
            // TODO: return wiki hope page
        }

        return uri;
    }

    /**
     * @since 1.2
     */
    public void setSuccessRedirectURI(URI uri) {
        setSessionAttribute(PROP_INITIAL_REQUEST, uri);
    }
}
