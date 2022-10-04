package issue

import (
	"fmt"
	"strings"

	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/resource"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/issue/tags"
)

type IssueID string

const (
	AUTH_2FA_0    IssueID = "AUTH_2FA_0"
	AUTH_2FA_1            = "AUTH_2FA_1"
	AUTH_2FA_2            = "AUTH_2FA_2"
	WH_0                  = "WH_0"
	CONFIG_AS_0           = "CONFIG_AS_0"
	CONFIG_AS_1           = "CONFIG_AS_1"
	CONFIG_PERM_0         = "CONFIG_PERM_0"
)

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
		ID:       AUTH_2FA_0,
		Name:     "Organization 2FA disabled",
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
		ID:       AUTH_2FA_1,
		Name:     "Users without 2FA configured",
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
		ID:       AUTH_2FA_2,
		Name:     "Users without 2FA configured",
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
		ID:       WH_0,
		Name:     "Insecure webhook payload URL",
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
		ID:       CONFIG_AS_0,
		Name:     "Advanced security disabled for new repositories",
		Severity: severity.Medium,
		Category: category.ToolingAndAutomation,
		CWEs:     []int{319},
		Description: fmt.Sprintf(
			"Advanced security disabled for org %s",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Tags:        []tags.Tag{tags.AdvancedSecurity},
		Remediation: "Pleasee see https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security for how to enable secret scanning in your repositories",
	}
}

func OrgSecretScanningDisabledForNewRepos(org string) Issue {
	return Issue{
		ID:       CONFIG_AS_1,
		Name:     "Secret scanning disabled for new repositories",
		Severity: severity.Medium,
		Category: category.InformationDisclosure,
		CWEs:     []int{319},
		Description: fmt.Sprintf(
			"Secret scanning disabled for org %s",
			org,
		),
		Resources: []resource.Resource{
			{
				ID:   org,
				Kind: resource.Organization,
			},
		},
		Tags:        []tags.Tag{tags.AdvancedSecurity},
		Remediation: "Pleasee see https://docs.github.com/en/github-ae@latest/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories for how to enable secret scanning in your repositories",
	}
}

func UserPermissionStats(user string, permissions []string) Issue {
	return Issue{
		ID:       CONFIG_PERM_0,
		Name:     "Permissions overview for users",
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
