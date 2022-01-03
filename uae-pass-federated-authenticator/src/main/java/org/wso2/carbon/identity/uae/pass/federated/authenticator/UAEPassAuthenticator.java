/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.uae.pass.federated.authenticator;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.*;

public class UAEPassAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(UAEPassAuthenticator.class);
    @Override
    public boolean canHandle(HttpServletRequest request) {
        return UAEPassAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request));
    }
    @Override
    public String getFriendlyName() {
        return "UAE Pass Federated";
    }
    @Override
    public String getName() {
        return "UAEPassFederatedAuthenticator";
    }
    @Override
    public String getClaimDialectURI() {
        return UAEPassAuthenticatorConstants.OIDC_DIALECT;
    }
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(UAEPassAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(UAEPassAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(UAEPassAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDescription("The callback URL used to partner identity provider credentials.");
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authzEpUrl = new Property();
        authzEpUrl.setName(UAEPassAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        authzEpUrl.setDisplayName("Authorization Endpoint URL");
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription("Enter OAuth2/OpenID Connect authorization endpoint URL value");
        authzEpUrl.setType("string");
        authzEpUrl.setDisplayOrder(4);
        configProperties.add(authzEpUrl);

        Property tokenEpUrl = new Property();
        tokenEpUrl.setName(UAEPassAuthenticatorConstants.OAUTH2_TOKEN_URL);
        tokenEpUrl.setDisplayName("Token Endpoint URL");
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription("Enter OAuth2/OpenID Connect token endpoint URL value");
        tokenEpUrl.setType("string");
        tokenEpUrl.setDisplayOrder(5);
        configProperties.add(tokenEpUrl);

        Property locales = new Property();
        locales.setName(UAEPassAuthenticatorConstants.UI_LOCALES);
        locales.setDisplayName("Locales");
        locales.setRequired(true);
        locales.setDescription("Enter the en/ar to render English/Arabic Login Pages");
        locales.setType("string");
        locales.setDisplayOrder(6);
        configProperties.add(locales);

        Property acr_values = new Property();
        acr_values.setName(UAEPassAuthenticatorConstants.ACR_VALUES);
        acr_values.setDisplayName("ACR Values");
        acr_values.setRequired(true);
        acr_values.setDescription("Enter the conditions for authenticating the user who must authorize the access");
        acr_values.setType("string");
        acr_values.setDisplayOrder(7);
        configProperties.add(acr_values);

        return configProperties;
    }

    /**
     * Redirects the user to the login page in order to authenticate
     *
     * In this UAE Pass Authenticator plugin, the user is redirected to the login page of the application which is
     * configured in the UAE Pass side which acts as the external Identity Provider
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_ID);
                String authorizationEP =
                        authenticatorProperties.get(UAEPassAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                String callBackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.CALLBACK_URL);
                String state = context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.LOGIN_TYPE;

                String scope = UAEPassAuthenticatorConstants.OAUTH_OIDC_SCOPE;
                OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callBackUrl)
                        .setResponseType(UAEPassAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setScope(scope)
                        .setState(state).buildQueryMessage();

                String loginPage = authzRequest.getLocationUri();
                response.sendRedirect(loginPage);
            } else {
                throw new AuthenticationFailedException("Error while retrieving properties. " +
                        "Authenticator Properties cannot be null");
            }
        } catch (OAuthSystemException | IOException e) {
            throw new AuthenticationFailedException("Exception while building authorization code request", e);
        }
    }


    /**
     * Implements the logic of the custom federated authenticator.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessTokenRequest);
            String accessToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }

            String idToken = oAuthResponse.getParam(UAEPassAuthenticatorConstants.ID_TOKEN);
            if (StringUtils.isBlank(idToken)) {
                throw new AuthenticationFailedException("Id token is required and is missing in OIDC response");
            }

            context.setProperty(UAEPassAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            AuthenticatedUser authenticatedUser;
            Map<String, Object> jsonObject = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                jsonObject = getIdTokenClaims(context, idToken);
                String authenticatedUserId = getAuthenticateUser(jsonObject);
                if (authenticatedUserId == null) {
                    throw new AuthenticationFailedException("Cannot find the userId from the id_token sent " +
                            "by the federated IDP.");
                }
                authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
            } else {
                authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                        getAuthenticateUser(jsonObject));
            }
            context.setSubject(authenticatedUser);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }


    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        String state = request.getParameter(UAEPassAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }


    protected String getAuthenticateUser(Map<String, Object> oidcClaims) {
        return (String) oidcClaims.get(UAEPassAuthenticatorConstants.SUB);
    }

    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(UAEPassAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parseJSONObject(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }


    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse
            authzResponse) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = authenticatorProperties.get(UAEPassAuthenticatorConstants.OAUTH2_TOKEN_URL);
        String callbackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.CALLBACK_URL);

        OAuthClientRequest accessTokenRequest;
        try {
            accessTokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType
                    .AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).setRedirectURI
                    (callbackUrl).setCode(authzResponse.getCode()).buildBodyMessage();
            if (accessTokenRequest != null) {
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(UAEPassAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException("Error while building access token request", e);
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
        }
        return accessTokenRequest;
    }

    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new AuthenticationFailedException("Exception while requesting access token");
        }
        return oAuthResponse;
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(UAEPassAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }
}