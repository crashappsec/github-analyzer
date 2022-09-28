package org

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/github/repo"
	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/github/utils"
	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Organization struct {
	info    *github.Organization
	client  *github.Client
	backoff *backoff.Backoff

	CoreStats *types.OrgCoreStats
}

func NewOrganization(
	ctx context.Context,
	client *github.Client,
	backoff *backoff.Backoff,
	name string) (*Organization, error) {
	orgInfo, resp, err := client.Organizations.Get(ctx, name)

	if err != nil {
		if resp.StatusCode == 403 {
			log.Logger.Errorf("Unable to retrieve organization information. It appears the token being used doesn't have access to this information.")
		} else {
			log.Logger.Error(err)
		}
		return nil, err
	}

	// FIXME change to not use unmarshal w/ reflection or plain initializer
	var stats types.OrgCoreStats
	orgJson, _ := json.Marshal(orgInfo)
	_ = json.Unmarshal(orgJson, &stats)

	org := Organization{
		info:      orgInfo,
		client:    client,
		backoff:   backoff,
		CoreStats: &stats,
	}
	return &org, nil
}

func (org Organization) GetWebhooks(
	ctx context.Context) ([]types.Webhook, error) {
	return utils.GetOrgPaginatedResult(
		ctx,
		org.backoff,
		*org.info.Login,
		ctx, &github.ListOptions{PerPage: 100},
		org.client.Organizations.ListHooks,
		utils.WebhooksAggregator)
}

func (org Organization) GetInstalls(ctx context.Context) ([]types.Install, error) {
	return utils.GetOrgPaginatedResult(
		ctx,
		org.backoff,
		*org.info.Login,
		ctx, &github.ListOptions{PerPage: 100},
		org.client.Organizations.ListInstallations,
		utils.InstallsAggregator)
}

func (org *Organization) GetActionRunners(ctx context.Context) ([]types.Runner, error) {
	return utils.GetOrgPaginatedResult(
		ctx,
		org.backoff,
		*org.info.Login,
		ctx,
		&github.ListOptions{PerPage: 100},
		org.client.Actions.ListOrganizationRunners,
		utils.RunnersAggregator)
}

// FIXME due to some restrictions in generics as of 1.18 we cannot use the generic
// paginatedResult here
func (org *Organization) GetRepositories(ctx context.Context) (
	[]repo.Repository, error) {
	log.Logger.Debugf("Fetching repositories for %s\n", *org.info.Login)
	var repos []repo.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		ghRepositories, resp, err := org.client.Repositories.ListByOrg(ctx, *org.info.Login, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			d := org.backoff.Duration()
			log.Logger.Infoln("Hit rate limit, sleeping for %d", d)
			time.Sleep(d)
			continue
		}

		if err != nil {
			if resp.StatusCode == 403 {
				log.Logger.Infoln("It appears the token being used doesn't have access to this information")
			} else {
				log.Logger.Error(err)
			}
			return repos, err
		}

		org.backoff.Reset()
		for _, ghRepository := range ghRepositories {
			r, err := repo.NewRepository(ctx, org.client, org.backoff, ghRepository)
			if err != nil {
				log.Logger.Error(err)
				continue
			}
			repos = append(repos, *r)
		}

		if resp.NextPage == 0 {
			break
		}

		// As of today The Go compiler does not support accessing a struct field x.f where
		// x is of type parameter type even if all types in the type
		// parameter's type set have a field f.
		opt.Page = resp.NextPage
	}

	return repos, nil
}

func (org Organization) Audit2FA(
	ctx context.Context) ([]issue.Issue, error) {

	var issues []issue.Issue

	log.Logger.Debug("Checking if 2FA is required at org-level")
	if *org.CoreStats.TwoFactorRequirementEnabled {
		return issues, nil
	}

	missing2FA := issue.Issue{
		ID:          "org_2fa_disabled",
		Severity:    severity.Medium,
		Category:    category.Permissions,
		Description: fmt.Sprintf("Two-factor authentication requirement in organization '%s' is disabled", *org.info.Login),
		// FIXME we could be doing markdown / html / etc. both these and descriptions could ge tlong so we need something better
		Remediation: "Please see https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
	}

	issues = append(issues, missing2FA)
	return issues, nil
}

func (org Organization) Audit(
	ctx context.Context) ([]issue.Issue, error) {

	var allIssues []issue.Issue
	twoFactor, err := org.Audit2FA(ctx)
	if err != nil {
		log.Logger.Error(err)
	}

	allIssues = append(allIssues, twoFactor...)
	return allIssues, nil
}
