package org.wso2.carbon.identity.uae.pass.federated.authenticator;

import org.apache.oltu.oauth2.client.request.ClientHeaderParametersApplier;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthMessage;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.parameters.BodyURLEncodedParametersApplier;
import org.apache.oltu.oauth2.common.parameters.OAuthParametersApplier;
import org.apache.oltu.oauth2.common.parameters.QueryParameterApplier;

import java.util.HashMap;
import java.util.Map;

public class UAEPassOAuthClientRequest extends OAuthClientRequest{
    protected String url;
    protected String body;
    protected Map<String, String> headers;

    protected UAEPassOAuthClientRequest(String url) {
        super(url);
        this.url = url;
    }

    public static UAEPassOAuthClientRequest.AuthenticationRequestBuilder authorizationLoca(String url) {
        return new UAEPassOAuthClientRequest.AuthenticationRequestBuilder(url);
    }


    public static class AuthenticationRequestBuilder extends UAEPassOAuthClientRequest.OAuthRequestBuilder {
        public AuthenticationRequestBuilder(String url) {
            super(url);
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setResponseType(String type) {
            this.parameters.put("response_type", type);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setClientId(String clientId) {
            this.parameters.put("client_id", clientId);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setUiLocales(String ui_locales){
            this.parameters.put("ui_locales",ui_locales);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setAcrValues(String acr_values){
            this.parameters.put("acr_values",acr_values);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setRedirectURI(String uri) {
            this.parameters.put("redirect_uri", uri);
            return this;
        }

        public  UAEPassOAuthClientRequest.AuthenticationRequestBuilder setState(String state) {
            this.parameters.put("state", state);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setScope(String scope) {
            this.parameters.put("scope", scope);
            return this;
        }

        public UAEPassOAuthClientRequest.AuthenticationRequestBuilder setParameter(String paramName, String paramValue) {
            this.parameters.put(paramName, paramValue);
            return this;
        }
    }


    public static class TokenRequestBuilder extends UAEPassOAuthClientRequest.OAuthRequestBuilder {
        public TokenRequestBuilder(String url) {
            super(url);
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setUiLocales(String ui_locales) {
            this.parameters.put("ui_locales",ui_locales);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setGrantType(GrantType grantType) {
            this.parameters.put("grant_type", grantType == null ? null : grantType.toString());
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setClientId(String clientId) {
            this.parameters.put("client_id", clientId);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setClientSecret(String secret) {
            this.parameters.put("client_secret", secret);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setUsername(String username) {
            this.parameters.put("username", username);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setPassword(String password) {
            this.parameters.put("password", password);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setScope(String scope) {
            this.parameters.put("scope", scope);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setCode(String code) {
            this.parameters.put("code", code);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setRedirectURI(String uri) {
            this.parameters.put("redirect_uri", uri);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setAssertion(String assertion) {
            this.parameters.put("assertion", assertion);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setAssertionType(String assertionType) {
            this.parameters.put("assertion_type", assertionType);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setRefreshToken(String token) {
            this.parameters.put("refresh_token", token);
            return this;
        }

        public UAEPassOAuthClientRequest.TokenRequestBuilder setParameter(String paramName, String paramValue) {
            this.parameters.put(paramName, paramValue);
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

        public UAEPassOAuthClientRequest buildQueryMessage() throws OAuthSystemException {
            UAEPassOAuthClientRequest request = new UAEPassOAuthClientRequest(this.url);
            this.applier = new QueryParameterApplier();
            return (UAEPassOAuthClientRequest)this.applier.applyOAuthParameters(request, this.parameters);
        }

        public UAEPassOAuthClientRequest buildBodyMessage() throws OAuthSystemException {
            UAEPassOAuthClientRequest request = new UAEPassOAuthClientRequest(this.url);
            this.applier = new BodyURLEncodedParametersApplier();
            return (UAEPassOAuthClientRequest)this.applier.applyOAuthParameters(request, this.parameters);
        }

        public UAEPassOAuthClientRequest buildHeaderMessage() throws OAuthSystemException {
            UAEPassOAuthClientRequest request = new UAEPassOAuthClientRequest(this.url);
            this.applier = new ClientHeaderParametersApplier();
            return (UAEPassOAuthClientRequest)this.applier.applyOAuthParameters(request, this.parameters);
        }
    }

}
