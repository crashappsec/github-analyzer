// package scraping is a wrapper over go-github's scrape package to export issues
// that can only be fetched via screen scraping
package scraping

import (
	"fmt"

	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/resource"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/scrape"
)

func AuditScraping(
	username, password, otpseed, org string,
) ([]issue.Issue, error) {
	var issues []issue.Issue

	client := scrape.NewClient(nil)
	if err := client.Authenticate(username, password, otpseed); err != nil {
		log.Logger.Error(err)
		return issues, nil
	}

	restrictedAccess, err := client.AppRestrictionsEnabled(org)
	if err != nil {
		log.Logger.Error(err)
	}
	if !restrictedAccess && err == nil {
		restr := issue.Issue{
			// FIXME we need a central definition of all of those
			ID:       "LP-0",
			Name:     "Application restrictions disabled",
			Severity: severity.High,
			Category: category.LeastPrivilege,
			Description: fmt.Sprintf(
				"Application restrictions for organization '%s' is disabled. Organization owners can enable OAuth App access restrictions to prevent untrusted apps from accessing the organization's resources while allowing organization members to use OAuth Apps for their personal accounts.",
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
		issues = append(issues, restr)
	}

	apps, err := client.ListOAuthApps(org)
	if err != nil {
		log.Logger.Error(err)
	}
	fmt.Printf("OAuth apps for %q: \n", org)
	for _, app := range apps {
		fmt.Printf("\t%+v\n", app)
	}
	return issues, nil
}
