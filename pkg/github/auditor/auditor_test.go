package auditor

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/crashappsec/github-analyzer/pkg/github/org"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

var (
	client *github.Client

	// auth indicates whether tests are being run with an OAuth token.
	// Tests can use this flag to skip certain tests when run without auth.
	auth bool
)

func init() {
	token := os.Getenv("GH_SECURITY_AUDITOR_TOKEN")
	if token == "" {
		client = github.NewClient(nil)
	} else {
		tc := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		))
		client = github.NewClient(tc)
		auth = true
	}
}

func TestSampleOrg(t *testing.T) {
	auditor := &GithubAuditor{client: client}
	ctx := context.Background()
	back := &backoff.Backoff{
		Min:    30 * time.Second,
		Max:    3 * time.Minute,
		Jitter: true,
	}
	name := "github-security-auditor-test-org"
	org, err := org.NewOrganization(ctx, auditor.client, back, name)
	assert.Nil(t, err, "Could not create organization")
	assert.NotNil(t, org.CoreStats, "Could not fetch core stats")
	assert.Equal(t, name, *org.CoreStats.Login)
	assert.GreaterOrEqual(t, 1, org.CoreStats.TotalPrivateRepos)
	assert.NotNil(
		t,
		org.CoreStats.TwoFactorRequirementEnabled,
		"nil two factor auth",
	)
}
