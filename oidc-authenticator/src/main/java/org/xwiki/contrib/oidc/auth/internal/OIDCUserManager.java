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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.user.api.XWikiRightService;
import com.xpn.xwiki.web.XWikiRequest;
import liquibase.util.file.FilenameUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.context.concurrent.ExecutionContextRunnable;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.auth.internal.domain.OAuth2AccessToken;
import org.xwiki.contrib.oidc.event.OAuthUserInfo;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserStore;
import org.xwiki.contrib.oidc.event.*;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.QueryException;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Various tools to manipulate users.
 *
 * @version $Id$
 * @since 1.2
 */
@Component(roles = OIDCUserManager.class)
@Singleton
public class OIDCUserManager {
    private static final ObjectMapper mapper = new ObjectMapper();

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCUserStore store;

    @Inject
    private ObservationManager observation;

    @Inject
    private ComponentManager componentManager;

    @Inject
    private Logger logger;

    private Executor executor = Executors.newFixedThreadPool(1);

    public void updateUserInfoAsync() throws MalformedURLException, URISyntaxException {
        final URI userInfoEndpoint = this.configuration.getUserInfoOIDCEndpoint();
        final OAuth2AccessToken accessToken = this.configuration.getOauth2AccessToken();

        this.executor.execute(new ExecutionContextRunnable(new Runnable() {
            @Override
            public void run() {
                try {
                    updateUserInfo(userInfoEndpoint, accessToken);
                } catch (Exception e) {
                    logger.error("Failed to update user informations", e);
                }
            }
        }, this.componentManager));
    }

    public void checkUpdateUserInfo() {
        Date date = this.configuration.removeUserInfoExpirationDate();
        if (date != null) {
            if (date.before(new Date())) {
                try {
                    updateUserInfoAsync();
                } catch (Exception e) {
                    this.logger.error("Failed to update user informations", e);
                }

                // Restart user information expiration counter
                this.configuration.resetUserInfoExpirationDate();
            } else {
                // Put back the date
                this.configuration.setUserInfoExpirationDate(date);
            }
        }
    }

    public Principal updateUserInfo(OAuth2AccessToken accessToken)
            throws URISyntaxException, IOException, ParseException, OIDCException, XWikiException, QueryException {
        Principal principal =
                updateUserInfo(this.configuration.getUserInfoOIDCEndpoint(), accessToken);

        // Restart user information expiration counter
        this.configuration.resetUserInfoExpirationDate();

        return principal;
    }

    private Principal updateUserInfo(URI userInfoEndpoint, OAuth2AccessToken accessToken)
            throws IOException, ParseException, OIDCException, XWikiException, QueryException {
        HTTPRequest userinfoHTTP = new HTTPRequest(HTTPRequest.Method.GET, userInfoEndpoint.toURL());
        // Get OIDC user info
        userinfoHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
                + this.getClass().getPackage().getImplementationVersion());
        userinfoHTTP.setHeader("Authorization", accessToken.getTokenType() + " " + accessToken.getAccessToken());
        HTTPResponse httpResponse = userinfoHTTP.send();

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            throw new OIDCException("Failed to get userInfo");
        }

        String content = httpResponse.getContent();
        CustomPrincipal principal = null;
        mapper.setPropertyNamingStrategy(PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        if (content != null && CallbackOIDCEndpoint.isJSONValid(content)) {
            principal = mapper.readValue(content, CustomPrincipal.class);
        }

        OAuthUserInfo userInfo = getUserInfo(principal);

        // Update/Create XWiki user
        return updateUser(userInfo);
    }

    public static OAuthUserInfo getUserInfo(CustomPrincipal principal) {
        //Done getUserInfo
        Map<String, Object> prin = principal.getPrincipal();
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setId(new Long((Integer) prin.get("userId")));
        userInfo.setLoginName((String) prin.get("username"));
        userInfo.setRealName((String) prin.get("realName"));
        userInfo.setImageUrl((String) prin.get("imageUrl"));
        userInfo.setProfilePhoto((String) prin.get("profilePhoto"));
        userInfo.setEmail((String) prin.get("email"));
        userInfo.setOrganizationId(new Long((Integer) prin.get("organizationId")));
        userInfo.setLanguage((String) prin.get("language"));
        userInfo.setPhone((String) prin.get("phone"));
        userInfo.setTimeZone((String) prin.get("timeZone"));
        return userInfo;
    }

    public Principal updateUser(OAuthUserInfo userInfo) throws XWikiException, QueryException {
        XWikiDocument userDocument =
                this.store.searchDocument(userInfo.getLoginName());

        XWikiDocument modifiableDocument;
        boolean newUser;
        if (userDocument == null) {
            userDocument = getNewUserDocument(userInfo);

            newUser = true;
            modifiableDocument = userDocument;
        } else {
            // Don't change the document author to not change document execution right

            newUser = false;
            modifiableDocument = userDocument.clone();
        }

        XWikiContext xcontext = this.xcontextProvider.get();

        // Set user fields
        BaseObject userObject = modifiableDocument
                .getXObject(xcontext.getWiki().getUserClass(xcontext).getDocumentReference(), true, xcontext);

        // Email
        if (userInfo.getEmail() != null) {
            userObject.set("email", userInfo.getEmail(), xcontext);
        }

        // First name
        if (userInfo.getLoginName() != null) {
            userObject.set("first_name", userInfo.getLoginName(), xcontext);
        }

        // Last name
        if (userInfo.getRealName() != null) {
            userObject.set("last_name", userInfo.getRealName(), xcontext);
        }

        // Phone
        if (userInfo.getPhone() != null) {
            userObject.set("phone", userInfo.getPhone(), xcontext);
        }

        // Default locale
        if (userInfo.getLanguage() != null) {
            userObject.set("default_language", Locale.forLanguageTag(userInfo.getLanguage()).toString(), xcontext);
        }

        // Time Zone
        if (userInfo.getTimeZone() != null) {
            userObject.set("timezone", userInfo.getTimeZone(), xcontext);
        }

        // Website
//        if (userInfo.getWebsite() != null) {
//            userObject.set("blog", userInfo.getWebsite().toString(), xcontext);
//        }

        // Avatar
        if (userInfo.getImageUrl() != null && !"".equals(userInfo.getImageUrl())) {
            try {
                String filename = FilenameUtils.getName("Avatar-"+ userInfo.getLoginName());
                URLConnection connection = new URL(userInfo.getImageUrl()).openConnection();
                connection.setRequestProperty("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
                        + this.getClass().getPackage().getImplementationVersion());
                try (InputStream content = connection.getInputStream()) {
                    modifiableDocument.addAttachment(filename, content, xcontext);
                }
                userObject.set("avatar", filename, xcontext);
            } catch (IOException e) {
                this.logger.warn("Failed to get user avatar from URL [{}]: {}", userInfo.getImageUrl(),
                        ExceptionUtils.getRootCauseMessage(e));
            }
        }

        //TODO 暂时不要了
        // XWiki claims
//        updateXWikiClaims(modifiableDocument, userObject.getXClass(xcontext), userObject, userInfo, xcontext);

        //TODO 暂时不需要
        // Set OIDC fields
//        this.store.updateOIDCUser(modifiableDocument, idToken.getIssuer().getValue(), userInfo.getSubject().getValue());

        // Prevent data to send with the event
        OIDCUserEventData eventData =
                new OIDCUserEventData(userInfo);

        // Notify
        this.observation.notify(new OIDCUserUpdating(modifiableDocument.getDocumentReference()), modifiableDocument,
                eventData);

        // Apply the modifications
        if (newUser || userDocument.apply(modifiableDocument)) {
            String comment;
            if (newUser) {
                comment = "Create user from OAuth Connect";
            } else {
                comment = "Update user from OAuth Connect";
            }

            xcontext.getWiki().saveDocument(userDocument, comment, xcontext);

            // Now let's add new the user to XWiki.XWikiAllGroup
            if (newUser) {
                xcontext.getWiki().setUserDefaultGroup(userDocument.getFullName(), xcontext);
            }

            // Notify
            this.observation.notify(new OIDCUserUpdated(userDocument.getDocumentReference()), userDocument, eventData);
        }

        return new SimplePrincipal(userDocument.getPrefixedFullName());
    }

    private void updateXWikiClaims(XWikiDocument userDocument, BaseClass userClass, BaseObject userObject,
                                   UserInfo userInfo, XWikiContext xcontext) {
        for (Map.Entry<String, Object> entry : userInfo.toJSONObject().entrySet()) {
            if (entry.getKey().startsWith(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER)) {
                String xwikiKey = entry.getKey().substring(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER.length());

                // Try in the user object
                if (userClass.getField(xwikiKey) != null) {
                    setValue(userObject, xwikiKey, entry.getValue(), xcontext);

                    continue;
                }

                // Try in the whole user document
                BaseObject xobject = userDocument.getFirstObject(xwikiKey);
                if (xobject != null) {
                    setValue(xobject, xwikiKey, entry.getValue(), xcontext);

                    continue;
                }
            }
        }
    }

    private void setValue(BaseObject xobject, String key, Object value, XWikiContext xcontext) {
        Object cleanValue;

        if (value instanceof List) {
            cleanValue = value;
        } else {
            // Go through String to be safe
            // TODO: find a more effective converter (the best would be to userObject#set to be stronger)
            cleanValue = Objects.toString(value);
        }

        xobject.set(key, cleanValue, xcontext);
    }

    private XWikiDocument getNewUserDocument(OAuthUserInfo userInfo) throws XWikiException {
        XWikiContext xcontext = this.xcontextProvider.get();

        // TODO: add support for subwikis
        SpaceReference spaceReference = new SpaceReference(xcontext.getMainXWiki(), "XWiki");

        // Generate default document name
        String documentName = userInfo.getLoginName();

        // Find not already existing document
        DocumentReference reference = new DocumentReference(documentName, spaceReference);
        XWikiDocument document = xcontext.getWiki().getDocument(reference, xcontext);
        for (int index = 0; !document.isNew(); ++index) {
            reference = new DocumentReference(documentName + '-' + index, spaceReference);

            document = xcontext.getWiki().getDocument(reference, xcontext);
        }

        // Initialize document
        document.setCreator(XWikiRightService.SUPERADMIN_USER);
        document.setAuthorReference(document.getCreatorReference());
        document.setContentAuthorReference(document.getCreatorReference());
        xcontext.getWiki().protectUserPage(document.getFullName(), "edit", document, xcontext);

        return document;
    }

    private String clean(String str) {
        return StringUtils.removePattern(str, "[\\.\\:\\s,@\\^]");
    }

    private void putVariable(Map<String, String> map, String key, String value) {
        map.put(key, value);
        map.put(key + ".clean", clean(value));
    }

    private String formatUserName(IDTokenClaimsSet idToken, UserInfo userInfo) {
        Map<String, String> map = new HashMap<>();

        // User informations
        putVariable(map, "oidc.user.subject", userInfo.getSubject().getValue());
        putVariable(map, "oidc.user.mail", userInfo.getEmailAddress() == null ? "" : userInfo.getEmailAddress());
        putVariable(map, "oidc.user.familyName", userInfo.getFamilyName());
        putVariable(map, "oidc.user.givenName", userInfo.getGivenName());

        // Provider (only XWiki OIDC providers)
        URL providerURL = this.configuration.getXWikiProvider();
        if (providerURL != null) {
            putVariable(map, "oidc.provider", providerURL.toString());
            putVariable(map, "oidc.provider.host", providerURL.getHost());
            putVariable(map, "oidc.provider.path", providerURL.getPath());
            putVariable(map, "oidc.provider.protocol", providerURL.getProtocol());
            putVariable(map, "oidc.provider.port", String.valueOf(providerURL.getPort()));
        }

        // Issuer
        putVariable(map, "oidc.issuer", idToken.getIssuer().getValue());
        try {
            URI issuerURI = new URI(idToken.getIssuer().getValue());
            putVariable(map, "oidc.issuer.host", issuerURI.getHost());
            putVariable(map, "oidc.issuer.path", issuerURI.getPath());
            putVariable(map, "oidc.issuer.scheme", issuerURI.getScheme());
            putVariable(map, "oidc.issuer.port", String.valueOf(issuerURI.getPort()));
        } catch (URISyntaxException e) {
            // TODO: log something ?
        }

        StrSubstitutor substitutor = new StrSubstitutor(map);

        return substitutor.replace(this.configuration.getUserNameFormater());
    }

    public void logout() {
        XWikiRequest request = this.xcontextProvider.get().getRequest();

        // TODO: remove cookies

        // Make sure the session is free from anything related to a previously authenticated user (i.e. in case we are
        // just after a logout)
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_IDTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_USERINFO_EXPORATIONDATE);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_TOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_IDTOKENCLAIMS);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_INITIAL_REQUEST);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_XWIKIPROVIDER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_STATE);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USER_NAMEFORMATER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USERINFOCLAIMS);
    }
}
