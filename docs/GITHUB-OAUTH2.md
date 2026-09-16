# GitHub OAuth2 Setup

###  1. Goto [GitHub Developer Apps](https://github.com/settings/developers)

### 2. Create a New Application
![GitHub Create Application](./imgs/github-create-application.png)

### 3. Add details
![GitHub Create Application Details](./imgs/github-create-application-details.png)

### 4. Get Client ID and Secrets
![GitHub Client ID And Secrets](./imgs/github-get-clientid-and-clientsecret.png)

### 5. Fill `.env` file

```dotenv
# GitHub Application Details for OAuth2
GITHUB_CLIENT_ID=<Client ID in step 4>
GITHUB_CLIENT_SECRET=<Client Secret in step 4>
ABANDON_AUTH_GITHUB_CALLBACK=http://localhost:3000/api/ui/github-callback
```
