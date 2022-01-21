package org.wso2.carbon.identity.uae.pass.federated.authenticator.util;

@SuppressWarnings("checkstyle:LocalVariableName")
public enum UAEPassFederatedAuthenticatorPropertyData {

    @SuppressWarnings("checkstyle:LocalVariableName")
    public enum PropertyType{
        STRING("string");

        private String propertyType;
        private PropertyType(String propertyType) { this.propertyType = propertyType; }
        public String toString() { return this.propertyType; }
   }

   @SuppressWarnings("checkstyle:LocalVariableName")
   public enum PropertyDisplayName{
        CLIENT_SECRET("Client Secret");

        private String propertyDisplayName;
        private PropertyDisplayName(String propertyDisplayName) { this.propertyDisplayName = propertyDisplayName; }
        public String toString() { return this.propertyDisplayName; }

   }




}
