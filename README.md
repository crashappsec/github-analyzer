[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/crashappsec/github-security-auditor/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ossf/scorecard/badge)](https://api.securityscorecards.dev/projects/github.com/crashappsec/github-security-auditor)
[![Go Report Card](https://goreportcard.com/badge/github.com/ossf/scorecard/v4)](https://goreportcard.com/report/github.com/crashappsec/github-security-auditor)

# Github Security Auditor

Audits a GitHub organization for potential security issues. The tool is currently in pre-alpha stage and only supports limited functionality, however we will be actively adding checks in the upcoming months, and welcome contributions from the community!


### Available Checks

|                       Name                      |               Category               |    Severity   | Resource Affected |
|:-----------------------------------------------:|:------------------------------------:|:-------------:|:-----------------:|
| Application restrictions disabled               |            Least Privilege           |     High      |    Organization   |
| Insecure Webhook payload URL                    |        Information Disclosure        |     High      |      Webhook      |
| Advanced security disabled for new repositories | Tooling and Automation Configuration |    Medium     |    Organization   |
| Secret scanning disabled for new repositories   | Tooling and Automation Configuration |    Medium     |    Organization   |
| Organization 2FA disabled                       |            Authentication            |    Medium     |    Organization   |
| Users without 2FA configured                    |            Authentication            |      Low      |    User Account   |
| Permissions overview for users                  |            Least Privilege           | Informational |    User Account   |
| OAuth application summary                       |            Least Privilege           | Informational |    Organization   |


### Sample Output
For each issue identified, a JSON with associated information will be generated. A sample output snippet is as follows:

```
...
 {
  "id": "CONFIG_AS_1",
  "name": "Secret scanning disabled for new repositories",
  "severity": 3,
  "category": "Information disclosure to untrusted parties",
  "tags": [
   "GitHub Advanced Security feature"
  ],
  "description": "Secret scanning disabled for org testorg",
  "resource": [
   {
    "id": "testorg",
    "kind": "Organization"
   }
  ],
  "cwes": [
   319
  ],
  "remediation": "Pleasee see https://docs.github.com/en/github-ae@latest/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories for how to enable secret scanning in your repositories"
 },
 {
  "id": "AUTH_2FA_2",
  "name": "Users without 2FA configured",
  "severity": 2,
  "category": "Authentication",
  "description": "The following collaborators have not enabled 2FA: testuser1, testuser2",
  "resource": [
   {
    "id": "testuser1",
    "kind": "UserAccount"
   },
   {
    "id": "testuser2",
    "kind": "UserAccount"
   }
  ],
  "cwes": [
   308
  ],
  "remediation": "Please see https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication for steps on how to configure 2FA for individual accounts"
 }
...
```

## How to run

You can see available options via the `--help` flag.

#### Running locally
* From the root of the directory run `make`
* Run `./bin/auditor --organization crashappsec --tokenName GIT_ADMIN`

#### Running using Docker

Run `docker compose run auditor --organization crahsappsec`

### Permissions

For **API-based based checks**, you need to pass in a personal access token (PAT) with the appropriate permissions. Example use:

`./bin/auditor --organization crashappsec --tokenName GIT_ADMIN`

See [our wiki](https://github.com/crashappsec/github-security-auditor/wiki/Setting-up-GitHub#creating-a-token) for instructions on setting up a token to be used with the auditor.


For **experimental scraping-based checks**, you need to pass in your username and password, as well your two factor authentication one-time-password, as needed. Example usage:

```shell
./bin/auditor --organization crashappsec --tokenName GIT_ADMIN --enableScraping --enableStats --username $GH_SECURITY_AUDITOR_USERNAME --password "$GH_SECURITY_AUDITOR_PASSWORD" --otpSeed "$GH_SECURITY_AUDITOR_OTP_SEED"

```
See [our wiki](https://github.com/crashappsec/github-security-auditor/wiki/Setting-up-GitHub#setting-up-2fa-experimental) for instructions on setting up a token to be used with the auditor.


# Credits

Project was originally ported from Mike de Libero's [auditor](https://github.com/CodeReconCo/githubsecurityauditor) with the author's permission.
