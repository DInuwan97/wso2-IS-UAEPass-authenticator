package org.wso2.carbon.identity.uae.pass.federated.authenticator;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.parameters.OAuthParametersApplier;
import org.apache.oltu.oauth2.common.parameters.QueryParameterApplier;

import org.wso2.carbon.identity.uae.pass.federated.authenticator.util.UAEPassAuthenticatorConstants;

import java.util.HashMap;
import java.util.Map;

//TODO:CHANGE THE CLASS NAME INTO REQ WRAPPER
//TODO: create a model package for this
@SuppressWarnings({"unchecked", "deprecated", "checkstyle:JavadocType"})
public class UAEPassOAuthClientRequestWrapper extends OAuthClientRequest {

    protected UAEPassOAuthClientRequestWrapper(String url) {
        super(url);
    }

    /**
     * @param url
     * @return AuthenticationRequestBuilder
     */
    public static UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder authorizationLocationEndpoint(
            String url) {
        return new UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder(url);
    }

    public static class AuthenticationRequestBuilder extends UAEPassOAuthClientRequestWrapper.OAuthRequestBuilder {
        public AuthenticationRequestBuilder(String url) {
            super(url);
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setResponseType(String type) {
            this.parameters.put(UAEPassAuthenticatorConstants.RESPONSE_TYPE, type);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setClientId(String clientId) {
            this.parameters.put("client_id", clientId);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setUiLocales(String uiLocales) {
            this.parameters.put(UAEPassAuthenticatorConstants.UI_LOCALES, uiLocales);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setAcrValues(String acrValues) {
            this.parameters.put(UAEPassAuthenticatorConstants.ACR_VALUES, acrValues);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setRedirectURI(String uri) {
            this.parameters.put(UAEPassAuthenticatorConstants.REDIRECT_URI, uri);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setState(String state) {
            this.parameters.put(UAEPassAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setScope(String scope) {
            this.parameters.put(UAEPassAuthenticatorConstants.SCOPE, scope);
            return this;
        }
    }

    public abstract static class OAuthRequestBuilder {
        protected OAuthParametersApplier applier;
        protected Map<String, Object> parameters = new HashMap();
        protected String url;

        protected OAuthRequestBuilder(String url) {
            this.url = url;
        }

        public UAEPassOAuthClientRequestWrapper buildQueryMessage() throws OAuthSystemException {
            UAEPassOAuthClientRequestWrapper request = new UAEPassOAuthClientRequestWrapper(this.url);
            this.applier = new QueryParameterApplier();
            return (UAEPassOAuthClientRequestWrapper) this.applier.applyOAuthParameters(request, this.parameters);
        }
    }
}
