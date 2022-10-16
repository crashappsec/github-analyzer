package scraping

import (
	"fmt"

	"github.com/crashappsec/github-security-auditor/pkg/issue"
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
		issues = append(issues, issue.ApplicationRestrictionsDisabled(org))
	}

	apps, err := client.ListOAuthApps(org)
	if err != nil {
		log.Logger.Error(err)
	}
	appinfo := make([]string, len(apps))
	for _, app := range apps {
		appinfo = append(appinfo, fmt.Sprintf("%+v", app))
	}
	issues = append(issues, issue.OAuthStats(org, appinfo))
	return issues, nil
}
