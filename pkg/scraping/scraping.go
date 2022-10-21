package scraping

import (
	"fmt"

	"path/filepath"

	"github.com/crashappsec/github-analyzer/pkg/futils"
	"github.com/crashappsec/github-analyzer/pkg/issue"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/google/go-github/scrape"
)

func AuditScraping(
	username, password, otpseed, org string,
) ([]issue.Issue, map[issue.IssueID]error, error) {
	var issues []issue.Issue
	execStatus := make(map[issue.IssueID]error, 1)

	client := scrape.NewClient(nil)
	if err := client.Authenticate(username, password, otpseed); err != nil {
		log.Logger.Error(err)
		execStatus[issue.LEAST_PRIV_OAUTH_PERMS_DISABLED] = err
		return issues, execStatus, nil
	}

	restrictedAccess, err := client.AppRestrictionsEnabled(org)
	execStatus[issue.LEAST_PRIV_OAUTH_PERMS_DISABLED] = err
	if err != nil {
		log.Logger.Error(err)
	}
	if !restrictedAccess && err == nil {
		issues = append(issues, issue.ApplicationRestrictionsDisabled(org))
	}

	apps, err := client.ListOAuthApps(org)
	execStatus[issue.STATS_OAUTH_PERMS] = err
	if err != nil {
		log.Logger.Error(err)
	}

	futils.SerializeFile(
		apps,
		filepath.Join(futils.MetadataDir, "oauthApps.json"),
	)
	var appinfo []string
	for _, app := range apps {
		appinfo = append(appinfo, fmt.Sprintf("%+v", app))
	}
	issues = append(issues, issue.OAuthStats(org, appinfo))
	return issues, execStatus, nil
}
