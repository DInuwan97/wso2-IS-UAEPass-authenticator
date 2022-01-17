package org.wso2.carbon.identity.uae.pass.federated.authenticator;

public enum UAEPassGrantTypes {
    AUTHORIZATION_CODE("authorization_code"),
    ID_TOKEN("id_token"),
    ID_TOKEN_AND_ACCESS_TOKEN("refresh_token"),
    CLIENT_CREDENTIALS("client_credentials");


    private String grantType;

    private UAEPassGrantTypes(String grantType) {
        this.grantType = grantType;
    }

    public String toString() {
        return this.grantType;
    }
}
