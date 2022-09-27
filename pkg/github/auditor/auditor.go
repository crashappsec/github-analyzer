package auditor

import (
	"context"

	"github.com/crashappsec/github-security-auditor/pkg/config"
	"github.com/crashappsec/github-security-auditor/pkg/github/org"
	"github.com/crashappsec/github-security-auditor/pkg/github/repo"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"golang.org/x/oauth2"
)

type GithubAuditor struct {
	client *github.Client
}

// FIXME remove this and return a AuditSummary defined in the issue pkg
type LegacyOrgSummary struct {
	Webhooks      []repo.Webhook
	Installs      []org.Install
	ActionRunners []org.Runner
	Repositories  []repo.Repository
	Stats         []interface{}
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
		log.Logger.Infof("Setting up an enteprise client for the source control management URL %s", scmURL)

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

func (gs GithubAuditor) AuditOrg(name string) (*LegacyOrgSummary, error) {
	// FIXME refactor, pass a common context and backoff, and possibly cancel handlers
	// in case of multiple failing operations
	ctx := context.Background()
	org, err := org.NewOrganization(ctx, gs.client, name)
	if err != nil {
		log.Logger.Error(err)
		return nil, err
	}

	summary := LegacyOrgSummary{}
	// FIXME wrap errors
	summary.ActionRunners, err = org.GetActionRunners(ctx)
	if err != nil {
		log.Logger.Error(err)
	}
	summary.Installs, err = org.GetInstalls(ctx)
	if err != nil {
		log.Logger.Error(err)
	}
	summary.Webhooks, err = org.GetWebhooks(ctx)
	if err != nil {
		log.Logger.Error(err)
	}
	summary.Repositories, err = org.GetRepositories(ctx)
	if err != nil {
		log.Logger.Error(err)
	}
	summary.Stats = []interface{}{org.CoreStats}
	return &summary, nil
}
