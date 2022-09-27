package auditor

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/crashappsec/github-security-auditor/pkg/config"
	"github.com/crashappsec/github-security-auditor/pkg/github/org"
	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"golang.org/x/oauth2"
)

type GithubAuditor struct {
	client *github.Client
}

func NewGithubAuditor() (*GithubAuditor, error) {
	token := os.Getenv(config.ViperEnv.TokenName)
	if token == "" {
		log.Logger.Fatalf("Github token not set - aborting")
	}

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
		return &GithubAuditor{client}, nil
	}

	return &GithubAuditor{github.NewClient(tc)}, nil
}

func (gs GithubAuditor) AuditOrg(name string) issue.AuditSummary {
	// TODO fix context
	ctx := context.Background()
	org, err := org.NewOrganization(ctx, gs.client, name)
	if err != nil {
		log.Logger.Fatal(err)
	}
	return org.Audit()
}

func (gs GithubAuditor) Audit() {
	results := gs.AuditOrg(config.ViperEnv.Organization)
	output, _ := json.MarshalIndent(results, "", " ")
	log.Logger.Infof("%s", output)
	_ = ioutil.WriteFile(config.ViperEnv.OutputFile, output, 0644)
}
