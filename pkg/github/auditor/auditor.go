package auditor

import (
	"context"
	"time"

	"github.com/crashappsec/github-analyzer/pkg/config"
	"github.com/crashappsec/github-analyzer/pkg/github/org"
	"github.com/crashappsec/github-analyzer/pkg/issue"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
	"golang.org/x/oauth2"
)

type GithubAuditor struct {
	client *github.Client
}

func NewGithubAuditor(token string) (*GithubAuditor, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	var client *github.Client
	var scmURL = config.ViperEnv.ScmURL
	if scmURL != "" {
		log.Logger.Infof(
			"Setting up an enteprise client for the source control management URL %s",
			scmURL,
		)

		var err error
		client, err = github.NewEnterpriseClient(scmURL, scmURL, tc)
		if err != nil {
			log.Logger.Error(err)
			return nil, err
		}
		return &GithubAuditor{client: client}, nil
	}

	return &GithubAuditor{client: github.NewClient(tc)}, nil
}

// AuditOrg runs a series of checks on a given organization and returns the
// issues found, execution state for each check run (whether it was successful
// or yielded in an error), and a generic overall error if audit fails overall
func (gs GithubAuditor) AuditOrg(
	name string,
	enableStats bool,
) ([]issue.Issue, map[issue.IssueID]error, error) {
	ctx := context.Background()
	back := &backoff.Backoff{
		Min:    30 * time.Second,
		Max:    10 * time.Minute,
		Jitter: true,
	}
	org, err := org.NewOrganization(ctx, gs.client, back, name)
	if err != nil {
		log.Logger.Error(err)
		return nil, nil, err
	}

	return org.Audit(ctx, enableStats)
}
