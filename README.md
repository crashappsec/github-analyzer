[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/crashappsec/github-analyzer/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ossf/scorecard/badge)](https://api.securityscorecards.dev/projects/github.com/crashappsec/github-analyzer)
[![Go Report Card](https://goreportcard.com/badge/github.com/ossf/scorecard/v4)](https://goreportcard.com/report/github.com/crashappsec/github-analyzer)

# Github Analyzer

Audits a GitHub organization for potential security issues. The tool is
currently in pre-alpha stage and only supports limited functionality, however
we will be actively adding checks in the upcoming months, and welcome
feature requests or contributions! Once the analysis is complete, a static HTML
with the summary of the results is rendered in localhost:3000 as shown below:

![gh-analyzer](https://user-images.githubusercontent.com/4614044/196647323-8138c053-644c-42a7-86f2-d94a7ce5e295.gif)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Available Checks](#available-checks)
- [Sample Output](#sample-output)
- [How to run](#how-to-run)
  - [Running locally](#running-locally)
  - [Running using Docker](#running-using-docker)
- [Permissions](#permissions)
- [Credits](#credits)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Available Checks

|                      Name                       |               Category               |   Severity    | Resource Affected |
| :---------------------------------------------: | :----------------------------------: | :-----------: | :---------------: |
|        Application restrictions disabled        |           Least Privilege            |     High      |   Organization    |
|          Insecure Webhook payload URL           |        Information Disclosure        |     High      |      Webhook      |
| Advanced security disabled for new repositories | Tooling and Automation Configuration |    Medium     |   Organization    |
|  Secret scanning disabled for new repositories  | Tooling and Automation Configuration |    Medium     |   Organization    |
|            Organization 2FA disabled            |            Authentication            |    Medium     |   Organization    |
|          Users without 2FA configured           |            Authentication            |      Low      |   User Account    |
|         Permissions overview for users          |           Least Privilege            | Informational |   User Account    |
|            OAuth application summary            |           Least Privilege            | Informational |   Organization    |

## Sample Output

For each issue identified, a JSON with associated information will be
generated. A sample output snippet is as follows:

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

### Running locally

- Install with:
  ```sh
  go install -v github.com/crashappsec/github-analyzer/cmd/github-analyzer@latest
  ```
- Run with:
  ```sh
  $GOPATH/bin/github-analyzer \
    --organization crashappsec \
    --token "$GH_SECURITY_AUDITOR_TOKEN" \
    --enableStats
  ```

### Running using Docker

- Build the container using:
  ```sh
  docker compose build --no-cache
  ```
- Run
  ```sh
  docker compose run \
      --rm \
      co-github-analyzer \
          --organization crashappsec \
          --output output \
          --token "$GH_SECURITY_AUDITOR_TOKEN" \
          --enableStats
  ```

## Permissions

For **API-based based checks**, you need to pass in GitHub Token
(either personal access token (PAT) or token derived from GitHub app installation)
with the appropriate permissions. Example usage:

```sh
github-analyzer \
    --organization crashappsec \
    --token "$GH_SECURITY_AUDITOR_TOKEN"
```

See [our wiki](https://github.com/crashappsec/github-analyzer/wiki/Setting-up-GitHub#creating-a-token)
for instructions on setting up a token to be used with the github-analyzer.

For **experimental scraping-based checks**, you need to pass in your username
and password, as well your two factor authentication one-time-password, as
needed. Example usage:

```shell
github-analyzer \
    --organization crashappsec \
    --token "$GH_SECURITY_AUDITOR_TOKEN" \
    --enableStats \
    --enableScraping \
    --username "$GH_SECURITY_AUDITOR_USERNAME" \
    --password "$GH_SECURITY_AUDITOR_PASSWORD" \
    --otpSeed "$GH_SECURITY_AUDITOR_OTP_SEED"
```

See [our wiki](https://github.com/crashappsec/github-analyzer/wiki/Setting-up-GitHub#setting-up-2fa-experimental)
for instructions on setting up a token to be used with the analyzer.

## Credits

Project was originally ported from Mike de Libero's
[auditor](https://github.com/CodeReconCo/githubsecurityauditor)
with the author's permission.
