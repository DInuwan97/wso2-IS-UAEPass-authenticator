package org.wso2.carbon.identity.uae.pass.federated.authenticator;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.parameters.OAuthParametersApplier;
import org.apache.oltu.oauth2.common.parameters.QueryParameterApplier;

import java.util.HashMap;
import java.util.Map;


//TODO:CHANGE THE CLASS NAME INTO REQ WRAPPER
//TODO: create a model package for this
public class UAEPassOAuthClientRequestWrapper extends OAuthClientRequest{

    protected UAEPassOAuthClientRequestWrapper(String url) {
        super(url);
    }

    /**
     *
     * @param url
     * @return AuthenticationRequestBuilder
     */
    public static UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder authorizationLocationEndpoint(String url) {
        return new UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder(url);
    }

    public static class AuthenticationRequestBuilder extends UAEPassOAuthClientRequestWrapper.OAuthRequestBuilder {
        public AuthenticationRequestBuilder(String url) {
            super(url);
        }


        //TODO:remove hard code values
        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setResponseType(String type) {
            this.parameters.put("response_type", type);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setClientId(String clientId) {
            this.parameters.put("client_id", clientId);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setUiLocales(String ui_locales){
            this.parameters.put("ui_locales",ui_locales);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setAcrValues(String acr_values){
            this.parameters.put("acr_values",acr_values);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setRedirectURI(String uri) {
            this.parameters.put("redirect_uri", uri);
            return this;
        }
//explain the method
        public  UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setState(String state) {
            this.parameters.put("state", state);
            return this;
        }

        public UAEPassOAuthClientRequestWrapper.AuthenticationRequestBuilder setScope(String scope) {
            this.parameters.put("scope", scope);
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


        //TODO:change applier to meaningfull name
        public UAEPassOAuthClientRequestWrapper buildQueryMessage() throws OAuthSystemException {
            UAEPassOAuthClientRequestWrapper request = new UAEPassOAuthClientRequestWrapper(this.url);
            this.applier = new QueryParameterApplier();
            return (UAEPassOAuthClientRequestWrapper) this.applier.applyOAuthParameters(request, this.parameters);
        }
    }

}
