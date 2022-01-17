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
3. Run the command `mvn install` Then maven dependecies will automatically installed.
4. Browse into `<PROJECT HOME>/target`.
5. You may abel to sea the created JAR file as `org.wso2.carbon.identity.uae.pass.federated.authenticator-<VERSION>`
