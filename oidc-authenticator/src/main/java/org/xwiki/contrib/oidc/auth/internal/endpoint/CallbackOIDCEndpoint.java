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
package org.xwiki.contrib.oidc.auth.internal.endpoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.google.common.base.Objects;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.auth.OIDCAuthServiceImpl;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.auth.internal.domain.OAuth2AccessToken;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.Principal;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Token endpoint for OpenID Connect.
 *
 * @version $Id$
 */
@Component
@Named(CallbackOIDCEndpoint.HINT)
@Singleton
public class CallbackOIDCEndpoint implements OIDCEndpoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(CallbackOIDCEndpoint.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * The endpoint name.
     */
    public static final String HINT = "authenticator/callback";

    @Inject
    private Container container;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager oidc;

    @Inject
    private OIDCUserManager users;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception {
        // Parse the request
        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(httpRequest);

        // Validate state
        State state = authorizationResponse.getState();
        if (!Objects.equal(state.getValue(), this.configuration.getSessionState().getValue())) {
//            return new RedirectResponse(new URI(state.getValue()));
            //todo state不正确的处理
            return new RedirectResponse(this.configuration.getSuccessRedirectURI());
        }
        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();

        // done: remove the state from the session ? !
        session.removeAttribute(OIDCClientConfiguration.PROP_STATE);

        // Deal with errors
        if (!authorizationResponse.indicatesSuccess()) {
            // Cast to error response
            AuthorizationErrorResponse errorResponse = (AuthorizationErrorResponse) authorizationResponse;

            // If impossible to authenticate without prompt, just ignore and redirect
            if (OIDCError.INTERACTION_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())
                    || OIDCError.LOGIN_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())) {
                // Redirect to original request
//                return new RedirectResponse(new URI(authorizationResponse.getState().getValue()));
                return new RedirectResponse(this.configuration.getSuccessRedirectURI());
            }
        }

//        String accessToken = responseParameters.getOrDefault("access_token", "");
//        String tokenType = responseParameters.getOrDefault("token_type", "");
//        Long expiresIn = Long.valueOf(responseParameters.getOrDefault("expires_in", "0"));
//        String scope = responseParameters.getOrDefault("scope", "");

//        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(accessToken, "", scope, tokenType, expiresIn);

        // Cast to success response
        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;

        // Get authorization code
        AuthorizationCode code = successResponse.getAuthorizationCode();

        // Generate callback URL
//        URI callback = this.oidc.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // Get access token
        AuthorizationGrant authorizationGrant = new AuthorizationCodeGrant(code, null);

        Map<String, String> customParams = new HashMap<>();
        String clientSecret = this.configuration.getClientSecret();
        customParams.put("client_secret", clientSecret);
//        // TODO: setup some client authentication, secret, all that
        TokenRequest tokeRequest = new TokenRequest(this.configuration.getTokenOIDCEndpoint(),
                this.configuration.getClientID(), authorizationGrant, null, customParams);
        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
//
        tokenHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
                + this.getClass().getPackage().getImplementationVersion());
//        tokenHTTP.setHeader("Authorization", getBasicAuth());

//        System.out.println("header: " + tokenHTTP.getHeaders());
        LOGGER.info("get token url is {}", tokenHTTP.getURL());
//
        HTTPResponse httpResponse = tokenHTTP.send();
//
        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);
            throw new OIDCException("Failed to get access token", error.getErrorObject());
        }

        String content = httpResponse.getContent();
        OAuth2AccessToken accessToken = null;
        mapper.setPropertyNamingStrategy(PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES);
        if (content != null && isJSONValid(content)) {
            accessToken = mapper.readValue(content, OAuth2AccessToken.class);
        }

        if (accessToken == null) {
            throw new OIDCException("Failed to format access token");
        }

        // Store the access token in the session
        this.configuration.setOAuth2AccessToken(accessToken);

        String logoutUrl = this.configuration.getLogoutOIDCEndpoint();
        if (logoutUrl != null && !"".equals(logoutUrl)) {
            this.configuration.setLogoutOIDCEndpoint(logoutUrl);
        }

        // Update/Create XWiki user
        Principal principal = this.users.updateUserInfo(accessToken);

        // Remember user in the session
        session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

        // TODO: put enough information in the cookie to automatically authenticate when coming back

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }

    public static boolean isJSONValid(String jsonInString) {
        try {
            final ObjectMapper mapper = new ObjectMapper();
            mapper.readTree(jsonInString);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String getBasicAuth() throws UnsupportedEncodingException {
        String clientID = this.configuration.getClientID().getValue();
        String clientSecret = this.configuration.getClientSecret();

        System.out.println(clientID + " : " + clientSecret);

        final Base64.Encoder encoder = Base64.getEncoder();
        byte[] clientInfoByte = (clientID + ":" + clientSecret).getBytes("UTF-8");
        return "Basic " + encoder.encodeToString(clientInfoByte);
    }
}
