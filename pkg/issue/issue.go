package issue

import (
	"fmt"
	"strings"

	"github.com/crashappsec/github-analyzer/pkg/issue/category"
	"github.com/crashappsec/github-analyzer/pkg/issue/resource"
	"github.com/crashappsec/github-analyzer/pkg/issue/severity"
	"github.com/crashappsec/github-analyzer/pkg/issue/tags"
)

type IssueID string

const (
	AUTH_2FA_ORG_DISABLED              IssueID = "AUTH_2FA_ORG_DISABLED"
	AUTH_2FA_USER_DISABLED                     = "AUTH_2FA_USER_DISABLED"
	AUTH_2FA_COLLABORATOR_DISABLED             = "AUTH_2FA_COLLABORATOR_DISABLED"
	INF_DISC_HTTP_WEBHOOK                      = "INF_DISC_HTTP_WEBHOOK"
	INF_DISC_SECRET_SCANNING_DISABLED          = "INF_DISC_SECRET_SCANNING_DISABLED"
	TOOLING_ADVANCED_SECURITY_DISABLED         = "TOOLING_ADVANCED_SECURITY_DISABLED"
	LEAST_PRIV_OAUTH_PERMS_DISABLED            = "LEAST_PRIV_OAUTH_PERMS_DISABLED"
	STATS_OAUTH_PERMS                          = "STATS_OAUTH_PERMS"
	STATS_USER_PERM                            = "STATS_USER_PERM"
)

var AvailableChecks = map[IssueID]string{
	AUTH_2FA_ORG_DISABLED:              "Organization 2FA settings",
	AUTH_2FA_USER_DISABLED:             "User 2FA settings",
	AUTH_2FA_COLLABORATOR_DISABLED:     "Collaborator 2FA settings",
	INF_DISC_HTTP_WEBHOOK:              "Webhook payload URL settings",
	INF_DISC_SECRET_SCANNING_DISABLED:  "Secret scanning settings for new repositories",
	TOOLING_ADVANCED_SECURITY_DISABLED: "Advanced security settings for new repositories",
	LEAST_PRIV_OAUTH_PERMS_DISABLED:    "Application restriction settings",
	STATS_USER_PERM:                    "Permissions overview for users",
	STATS_OAUTH_PERMS:                  "OAuth application summary",
}

type Issue struct {
	ID          IssueID             `json:"id"`
	Name        string              `json:"name"`
	Severity    severity.Severity   `json:"severity"`
	Category    category.Category   `json:"category"`
	Tags        []tags.Tag          `json:"tags,omitempty"`
	Description string              `json:"description"`
	Resources   []resource.Resource `json:"resource"`
	CWEs        []int               `json:"cwes,omitempty"`
	Remediation string              `json:"remediation"`
}

func Org2FADisabled(org string) Issue {
	return Issue{
		ID:       AUTH_2FA_ORG_DISABLED,
		Name:     AvailableChecks[AUTH_2FA_ORG_DISABLED],
		Severity: severity.Medium,
		Category: category.Authentication,
		Description: fmt.Sprintf(
			"Two-factor authentication requirement in organization '%s' is disabled",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Remediation: "Please see https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization for steps on how to configure 2FA for your organization",
	}
}

func UsersWithout2FA(
	usersLacking2FA []string,
	resources []resource.Resource,
) Issue {
	return Issue{
		ID:       AUTH_2FA_USER_DISABLED,
		Name:     AvailableChecks[AUTH_2FA_USER_DISABLED],
		Severity: severity.Low,
		Category: category.Authentication,
		CWEs:     []int{308},
		Description: fmt.Sprintf(
			"The following users have not enabled 2FA: %s",
			strings.Join(usersLacking2FA, ", "),
		),
		Resources:   resources,
		Remediation: "Please see https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication for steps on how to configure 2FA for individual accounts",
	}
}

func CollaboratorsWithout2FA(
	usersLacking2FA []string,
	resources []resource.Resource,
) Issue {
	return Issue{
		ID:       AUTH_2FA_COLLABORATOR_DISABLED,
		Name:     AvailableChecks[AUTH_2FA_COLLABORATOR_DISABLED],
		Severity: severity.Low,
		Category: category.Authentication,
		CWEs:     []int{308},
		Description: fmt.Sprintf(
			"The following collaborators have not enabled 2FA: %s",
			strings.Join(usersLacking2FA, ", "),
		),
		Resources:   resources,
		Remediation: "Please see https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication for steps on how to configure 2FA for individual accounts",
	}
}

func InsecureWebhookPayloadURL(url string) Issue {
	return Issue{
		ID:       INF_DISC_HTTP_WEBHOOK,
		Name:     AvailableChecks[INF_DISC_HTTP_WEBHOOK],
		Severity: severity.High,
		Category: category.InformationDisclosure,
		CWEs:     []int{319},
		Description: fmt.Sprintf(
			"Non-HTTPS webhook detected: %s",
			url,
		),
		Resources: []resource.Resource{
			{ID: url, Kind: resource.Webhook},
		},
		Remediation: "It is recommended to use HTTPS webhooks if data involved is sensitive and also enable SSL verification as outlined in https://docs.github.com/en/developers/webhooks-and-events/webhooks/creating-webhooks",
	}
}

func OrgAdvancedSecurityDisabled(org string) Issue {
	return Issue{
		ID:       TOOLING_ADVANCED_SECURITY_DISABLED,
		Name:     AvailableChecks[TOOLING_ADVANCED_SECURITY_DISABLED],
		Severity: severity.Medium,
		Category: category.ToolingAndAutomation,
		CWEs:     []int{319},
		Description: fmt.Sprintf(
			"Advanced security disabled for new repositories in organization '%s'",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Tags:        []tags.Tag{tags.AdvancedSecurity},
		Remediation: "Please see https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security for how to enable secret scanning in your repositories",
	}
}

func OrgSecretScanningDisabledForNewRepos(org string) Issue {
	return Issue{
		ID:       INF_DISC_SECRET_SCANNING_DISABLED,
		Name:     AvailableChecks[INF_DISC_SECRET_SCANNING_DISABLED],
		Severity: severity.Medium,
		Category: category.InformationDisclosure,
		CWEs:     []int{319},
		Description: fmt.Sprintf(
			"Secret scanning disabled for organization '%s'",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Tags:        []tags.Tag{tags.AdvancedSecurity},
		Remediation: "Please see https://docs.github.com/en/github-ae@latest/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories for how to enable secret scanning in your repositories",
	}
}

func UserPermissionStats(user string, permissions []string) Issue {
	return Issue{
		ID:       STATS_USER_PERM,
		Name:     AvailableChecks[STATS_USER_PERM],
		Severity: severity.Informational,
		Category: category.LeastPrivilege,
		Description: fmt.Sprintf(
			"User '%s' %v",
			user,
			strings.Join(permissions, ", and "),
		),
		Resources: []resource.Resource{
			{
				ID:   user,
				Kind: resource.UserAccount,
			},
		},
		Remediation: "Please examine if the permissions for the given user match your expectations",
	}
}

func ApplicationRestrictionsDisabled(org string) Issue {
	return Issue{
		ID:       LEAST_PRIV_OAUTH_PERMS_DISABLED,
		Name:     AvailableChecks[LEAST_PRIV_OAUTH_PERMS_DISABLED],
		Severity: severity.High,
		Category: category.LeastPrivilege,
		Description: fmt.Sprintf(
			"Application restrictions for organization '%s' is disabled. Without OAuth App access restrictions any App is automatically granted access to the organization account when any organization member installs and authorizes the App, even if they do so for a personal account. This can lead to untrusted apps accessing organization resources",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Remediation: "Please see https://docs.github.com/en/organizations/restricting-access-to-your-organizations-data/about-oauth-app-access-restrictions for steps on how to configure OAuth App access for your organization",
	}
}

func OAuthStats(org string, appinfo []string) Issue {
	return Issue{
		ID:       STATS_OAUTH_PERMS,
		Name:     AvailableChecks[STATS_OAUTH_PERMS],
		Severity: severity.Informational,
		Category: category.LeastPrivilege,
		Description: fmt.Sprintf(
			"OAuth apps for '%s': %s",
			org,
			strings.Join(appinfo, ", "),
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Remediation: "Please ensure the OAuth Apps installed in your organization meet your expectations",
	}
}
