package org.wso2.carbon.identity.uae.pass.federated.authenticator.util;

public class PropertyData {

    public enum PropertyDisplayName {
        CLIENT_ID_DISPLAY_NAME("Client Id"),
        CLIENT_SECRET_DISPLAY_NAME("Client Secret"),
        CALLBACK_URL_DISPLAY_NAME("Callback URL"),
        AUTHORIZATION_EP_URL_DISPLAY_NAME("Authorization Endpoint URL"),
        TOKEN_EP_URL_DISPLAY_NAME("Token Endpoint URL"),
        LOCALES_DISPLAY_NAME("Locales"),
        ACR_VALUES_DISPLAY_NAME("ACR Values");

        private String propertyDisplayName;

        private PropertyDisplayName(String propertyDisplayName) {
            this.propertyDisplayName = propertyDisplayName;
        }

        public String toString() {
            return this.propertyDisplayName;
        }
    }


    public enum PropertyDescription {
        CLIENT_ID_DESCRIPTION("Enter OAuth2/OpenID Connect client identifier value"),
        CLIENT_SECRET_DESCRIPTION("Enter OAuth2/OpenID Connect client secret value"),
        CALLBACK_URL_DESCRIPTION("The callback URL used to partner identity provider credentials"),
        AUTHORIZATION_EP_URL_DESCRIPTION("Enter OAuth2/OpenID Connect authorization endpoint URL value"),
        TOKEN_EP_URL_DESCRIPTION("Enter OAuth2/OpenID Connect token endpoint URL value"),
        LOCALES_DESCRIPTION("Enter the en/ar to render English/Arabic Login Pages"),
        ACR_VALUES_DESCRIPTION("Enter the conditions for authenticating the user who must authorize the access");

        private String propertyDescriptionName;

        private PropertyDescription(String propertyDescriptionName) {
            this.propertyDescriptionName = propertyDescriptionName;
        }

        public String toString() {
            return this.propertyDescriptionName;
        }

    }

    public enum PropertyType {
        PROPERTY_TYPE_STRING("string");

        private String propertyType;

        private PropertyType(String propertyType) {
            this.propertyType = propertyType;
        }

        public String toString() {
            return this.propertyType;
        }
    }

}