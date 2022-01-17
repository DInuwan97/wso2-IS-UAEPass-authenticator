# WSO2 Identity Server-UAEPass Federated Authenticator
This a federated authenticator for WSO2 Identity Server which can be used in UAE Pass IdP. The entire federated authentication process can be denoted as just using 03 steps as follows.
1. Client app talks to IS1 SP
2. IS1 SP talks to IS1 IDP
3. IS1 IDP talks to IS2 SP

Bellow sequence diagram will eloborate how the request flow is going to happen with above created cutom federated authenticator. Any one can test this flow using browser's inspect to attached HAR file [here](https://gist.githubusercontent.com/DInuwan97/57f5828738ccf56d96e237a789d51f1c/raw/c90fd2223082c241c572a1a2cdad4e0970a8bf41/UAEPass-Federated-Authenticator.har)

![sequence_diagram_fed_auth_partner_is](https://user-images.githubusercontent.com/38750420/149746488-dafa4c06-de29-4796-bea8-fc8746ed900d.png)

## How to contribute

1. Fork the repo on GitHub.

2. Clone the project to your own machine.
```
git clone https://github.com/<YOUR_USERNAME>/wso2-IS-UAEPass-authenticator.git
```

3. Create a branch using the git checkout command.
```
git checkout -b <your-new-branch-name>`
```

4. Stage your changes and commit with a meaningful commit message.
```
git add .
git commit -m "<initial commit>"
```

5. Push your work back up to your fork.
```
git push origin <add-your-branch-name>
```

## How to run the project
1. Open the project using InteliJ IDE.
2. Browse to the InteliJ terminal.
3. Run the command as follows. Then maven dependecies will automatically installed.
```
mvn install
```
4. Browse into `<PROJECT HOME>/target`.
5. You may abel to sea the created JAR file as `org.wso2.carbon.identity.uae.pass.federated.authenticator-<VERSION>`

## Explanation of the Code

Refer the [`UAEPassFederatedAuthenticatorServiceComponent`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/main/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/internal/UAEPassFederatedAuthenticatorServiceComponent.java) class as well since the authenticator is written as OSGI service to deploy in the WSO2 Identity Server and register it as UAEPass Federated Authenticator.

The [`UAEPassAuthenticator`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/main/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java) should be written by extending the [`AbstractApplicationAuthenticator`](https://github.com/wso2/carbon-identity-framework/blob/v5.18.187/components/authentication-framework/org.wso2.carbon.identity.application.authentication.framework/src/main/java/org/wso2/carbon/identity/application/authentication/framework/AbstractApplicationAuthenticator.java) class and implementing the [FederatedApplicationAuthenticator](https://github.com/wso2/carbon-identity-framework/blob/master/components/authentication-framework/org.wso2.carbon.identity.application.authentication.framework/src/main/java/org/wso2/carbon/identity/application/authentication/framework/FederatedApplicationAuthenticator.java) interface.

| Class name            | Super class                       | Interface                         |
| --------------------- | --------------------------------- | --------------------------------- |
| UAEPassAuthenticator  | AbstractApplicationAuthenticator  | FederatedApplicationAuthenticator |

### Methods:

[`boolean canHandle(HttpServletRequest request)`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L56)
| Return        | Parameter           |
| ------------- | ------------------- |
| Boolean       | HttpServletRequest  |

Specifies whether this authenticator can handle the authentication response.

[`String getFriendlyName()`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L63)

This is the name which is going to appear as the display name of the custom federated authenticator. It will appear as `UAEPass Federated Authenticator Configuration` in WSO2 IS, `Identity Providers` → `Local and Outbound Authenticators` → `Federated Authentication` → `Custom Federated Authenticators`.

[`String getName()`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L70)

This name is going to appear as an unique identifier of the component. Once you spin up WSO2 IS, then open inspect elements. Now navigate to the federated authenticator’s custom user input fields. Then you may be able to see how the name and id of those input fields are listed as. Always starting as `UAEPassFederatedAuthenticator`.

[`String getClaimDialectURI()`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L77)

As usually it shows the claim dialect. Also can be configured as a custom user input field.

[`List Property getConfigurationProperties()`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L84)
  
List down all the custom user input fields of the federated authenticator. Those user inputs hold the values as key value pairs. Therefore having a HashMap is a must especially in this case. But within this method it is not going to take those values that the user already input. Just take the constant values which were set.

[`void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)`](https://github.com/DInuwan97/wso2-IS-UAEPass-authenticator/blob/0ee102a1314236c0b46157975c314a71b923e101/uae-pass-federated-authenticator/src/main/java/org/wso2/carbon/identity/uae/pass/federated/authenticator/UAEPassAuthenticator.java#L166)

| Return         | Parameter             |
| -------------- | --------------------- |
|                | HttpServletRequest    |
| List<Property> | HttpServletResponse   |                
|                | AuthenticationContext |

Redirects the user to the login page in order to authenticate. In this UAE Pass Authenticator plugin, the user is redirected to the login page of the application which is configured in the UAEPass side which acts as the external Identity Provider. Within this method, it's going to fetch out the exact data inserted in above user input fields in UAEPass Federated Authenticator. 

Once those user input fields are fetched, using Java builder design pattern the authorization request is going to be created. `authzRequest`.

Once an authorization request is created, it will be sent to the login screen while embedding a sessionDataKey. Here still no authorization code is created.



