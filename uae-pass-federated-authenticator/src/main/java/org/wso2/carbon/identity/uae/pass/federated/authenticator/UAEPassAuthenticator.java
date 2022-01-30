/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.uae.pass.federated.authenticator.util.PropertyData;
import org.wso2.carbon.identity.uae.pass.federated.authenticator.util.UAEPassAuthenticatorConstants;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UAEPassAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(UAEPassAuthenticator.class);

    @Override
    /**
     * @param request
     * @return Boolean
     */ public boolean canHandle(HttpServletRequest request) {
        return UAEPassAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    /**
     * @return String
     */ public String getFriendlyName() {
        return UAEPassAuthenticatorConstants.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME;
    }

    @Override
    /**
     * @return String
     */ public String getName() {
        return UAEPassAuthenticatorConstants.FEDERATED_IDP_COMPONENT_NAME;
    }

    @Override
    /**
     * @return String //explain the method
     */ public String getClaimDialectURI() {
        return UAEPassAuthenticatorConstants.OIDC_DIALECT;
    }

    @SuppressWarnings("checkstyle:LocalVariableName")
    @Override
    /**
     * @return List<Property> federated authenticator properties
     */ public ArrayList<Property> getConfigurationProperties() {

        //TODO:use enum for constants
        ArrayList<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(UAEPassAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName(PropertyData.PropertyDisplayName.CLIENT_ID_DISPLAY_NAME.toString());
        clientId.setRequired(true);
        clientId.setDescription(PropertyData.PropertyDescription.CLIENT_ID_DESCRIPTION.toString());
        clientId.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(UAEPassAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(PropertyData.PropertyDisplayName.CLIENT_SECRET_DISPLAY_NAME.toString());
        clientSecret.setRequired(true);
        clientSecret.setDescription(PropertyData.PropertyDescription.CLIENT_SECRET_DESCRIPTION.toString());
        clientSecret.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName(PropertyData.PropertyDisplayName.CALLBACK_URL_DISPLAY_NAME.toString());
        callbackUrl.setName(UAEPassAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDescription(PropertyData.PropertyDescription.CALLBACK_URL_DESCRIPTION.toString());
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property authzEpUrl = new Property();
        authzEpUrl.setName(UAEPassAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        authzEpUrl.setDisplayName(PropertyData.PropertyDisplayName.AUTHORIZATION_EP_URL_DISPLAY_NAME.toString());
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription(PropertyData.PropertyDescription.AUTHORIZATION_EP_URL_DESCRIPTION.toString());
        authzEpUrl.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        authzEpUrl.setDisplayOrder(4);
        configProperties.add(authzEpUrl);

        Property tokenEpUrl = new Property();
        tokenEpUrl.setName(UAEPassAuthenticatorConstants.OAUTH2_TOKEN_URL);
        tokenEpUrl.setDisplayName(PropertyData.PropertyDisplayName.TOKEN_EP_URL_DISPLAY_NAME.toString());
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription(PropertyData.PropertyDescription.TOKEN_EP_URL_DESCRIPTION.toString());
        tokenEpUrl.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        tokenEpUrl.setDisplayOrder(5);
        configProperties.add(tokenEpUrl);

        Property locales = new Property();
        locales.setName(UAEPassAuthenticatorConstants.UI_LOCALES);
        locales.setDisplayName(PropertyData.PropertyDisplayName.LOCALES_DISPLAY_NAME.toString());
        locales.setRequired(true);
        locales.setDescription(PropertyData.PropertyDescription.LOCALES_DESCRIPTION.toString());
        locales.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        locales.setDisplayOrder(6);
        configProperties.add(locales);

        Property acrValues = new Property();
        acrValues.setName(UAEPassAuthenticatorConstants.ACR_VALUES);
        acrValues.setDisplayName(PropertyData.PropertyDisplayName.ACR_VALUES_DISPLAY_NAME.toString());
        acrValues.setRequired(true);
        acrValues.setDescription(PropertyData.PropertyDescription.ACR_VALUES_DESCRIPTION.toString());
        acrValues.setType(PropertyData.PropertyType.PROPERTY_TYPE_STRING.toString());
        acrValues.setDisplayOrder(7);
        configProperties.add(acrValues);

        //add a property for additional scope

        return configProperties;
    }

    /**
     * Redirects the user to the login page in order to authentication.
     * In this UAE Pass Authenticator plugin, the user is redirected to the login page of the application which is
     * configured in the UAE Pass side which acts as the external Identity Provider
     *
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException - exception while creating the authorization code
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            if (log.isDebugEnabled()) {
                log.info("request hits towards thr login.do");
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {

                String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = authenticatorProperties.get(UAEPassAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                String callBackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.CALLBACK_URL);
                String state = context.getContextIdentifier() + "," + UAEPassAuthenticatorConstants.LOGIN_TYPE;

                String uiLocales = authenticatorProperties.get(UAEPassAuthenticatorConstants.UI_LOCALES);
                String acrValues = authenticatorProperties.get(UAEPassAuthenticatorConstants.ACR_VALUES);
                String scope = UAEPassAuthenticatorConstants.OAUTH_OIDC_SCOPE;

                OAuthClientRequest authzRequest =
                        UAEPassOAuthClientRequestWrapper.authorizationLocationEndpoint(authorizationEP)
                                .setClientId(clientId).setRedirectURI(callBackUrl)
                                .setResponseType(UAEPassAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE).setScope(scope)
                                .setState(state).setUiLocales(uiLocales).setAcrValues(acrValues).buildQueryMessage();

                String loginPage = authzRequest.getLocationUri();
                response.sendRedirect(loginPage);
            } else {
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. " + "Authenticator Properties cannot be null");
            }
        } catch (OAuthSystemException | IOException e) {
            if (log.isDebugEnabled()) {
                log.error("Authorization code request building failed.", e);
            }
            throw new AuthenticationFailedException("Exception while building authorization code request", e);
        }
    }

    /**
     * Implements the logic of the UAE Pass federated authenticator.
     *
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException - exception while creating the access token or id token
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

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
                String authenticatedUserId = getAuthenticatedUser(jsonObject);
                if (authenticatedUserId == null) {
                    throw new AuthenticationFailedException(
                            "Cannot find the userId from the id_token sent " + "by the federated IDP.");
                }
                authenticatedUser =
                        AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
            } else {
                authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                        getAuthenticatedUser(jsonObject));
            }
            context.setSubject(authenticatedUser);
        } catch (OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.error("Authentication process failed", e);
            }
            throw new AuthenticationFailedException("Authentication process failed", e);
        }
    }

    @Override
    /**
     * @param request
     * @return String
     */ public String getContextIdentifier(HttpServletRequest request) {
        String state = request.getParameter(UAEPassAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            if (log.isDebugEnabled()) {
                log.error(
                        "An unique identifier couldn't issue for both Request and Response. ContextIdentifier is NULL");
            }
            return null;
        }
    }

    /**
     * @param oidcClaims
     * @return String
     */
    protected String getAuthenticatedUser(Map<String, Object> oidcClaims) {
        return (String) oidcClaims.get(UAEPassAuthenticatorConstants.SUB);
    }

    /**
     * @param context
     * @param idToken
     * @return Map<Strng, Object> - decoded JWT payload via JSON Key value pairs
     */
    private Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(UAEPassAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        HashSet<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet =
                    (HashSet<Map.Entry<String, Object>>) JSONObjectUtils.parse(new String(decoded)).entrySet();
        } catch (ParseException e) {
            log.error("Error occurred while parsing JWT provided by federated IDP: ", e);
        }
        Map<String, Object> jwtAttributeMap = new HashMap();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
        }
        return jwtAttributeMap;
    }

    /**
     * Request the access token - Create a request to access token endpoint of the external IdP.
     *
     * @param context
     * @param authzResponse
     * @return OAuthClientRequest
     * @throws AuthenticationFailedException
     */
    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse authzResponse)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(UAEPassAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = authenticatorProperties.get(UAEPassAuthenticatorConstants.OAUTH2_TOKEN_URL);
        String callbackUrl = authenticatorProperties.get(UAEPassAuthenticatorConstants.CALLBACK_URL);

        OAuthClientRequest accessTokenRequest;
        try {
            accessTokenRequest =
                    OAuthClientRequest.tokenLocation(tokenEndPoint).setGrantType(GrantType.AUTHORIZATION_CODE)
                            .setClientId(clientId).setClientSecret(clientSecret).setRedirectURI(callbackUrl)
                            .setCode(authzResponse.getCode()).buildBodyMessage();
            if (accessTokenRequest != null) {
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(UAEPassAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }
        } catch (OAuthSystemException e) {
            if (log.isDebugEnabled()) {
                log.error("Access Token building request failed", e);
            }
            throw new AuthenticationFailedException("Error while building access token request", e);
        } catch (URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.error("Access Token building request failed", e);
            }
            throw new RuntimeException("Error occurred while building URL in tenant qualified mode.", e);
        }
        return accessTokenRequest;
    }

    /**
     * @param oAuthClient
     * @param accessRequest
     * @return OAuthClientResponse
     * @throws AuthenticationFailedException
     */
    protected OAuthClientResponse getOauthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws AuthenticationFailedException {

        OAuthClientResponse oAuthResponse;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            if (log.isDebugEnabled()) {
                log.error("Access Token requesting failed", e);
            }
            throw new AuthenticationFailedException("Exception while requesting access token");
        }
        return oAuthResponse;
    }

    /**
     * @param request
     * @return String
     */
    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(UAEPassAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            try {
                String[] stateElements = state.split(",");
                if (stateElements.length > 1) {
                    return stateElements[1];
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.error("Empty split elements in state", e);
                }
            }
        }
        log.error("Login Type's state is null");
        return null;
    }

}

