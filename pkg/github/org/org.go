package org

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/github/repo"
	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/github/utils"
	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/resource"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Organization struct {
	info    *github.Organization
	client  *github.Client
	backoff *backoff.Backoff

	CoreStats     *types.OrgCoreStats
	Users         []types.User
	Collaborators []types.User
	Repositories  []repo.Repository
	Webhooks      []types.Webhook
}

// TODO: check public gists
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
	if len(org.Webhooks) > 0 {
		return org.Webhooks, nil
	}

	hooks, err := utils.GetOrgPaginatedResult(
		ctx,
		org.backoff,
		*org.info.Login,
		ctx, &github.ListOptions{PerPage: 100},
		org.client.Organizations.ListHooks,
		utils.WebhooksAggregator)
	org.Webhooks = hooks
	return hooks, err
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

// GetUsers returns the users for a given org. Upon first call,
// it lazily updates the Organization with the user information
func (org *Organization) GetUsers(ctx context.Context) (
	[]types.User, error) {

	if len(org.Users) > 0 {
		return org.Users, nil
	}

	log.Logger.Debugf("Fetching users for %s\n", *org.info.Login)
	var users []types.User
	// XXX there exists a filter option for fetching only thouse with 2fa_disabled
	// but for users let's fetch all information
	opt := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		orgMembers, resp, err := org.client.Organizations.ListMembers(ctx, *org.info.Login, opt)

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
			return users, err
		}

		org.backoff.Reset()
		for _, m := range orgMembers {
			// FIXME this seems to return more information although in principle it should be the same
			// as in members - is there any param we could be missing?
			u, _, err := org.client.Users.Get(ctx, *m.Login)
			if err != nil {
				log.Logger.Error(err)
				continue
			}
			user := types.User{}
			// FIXME use reflection
			userJson, _ := json.Marshal(u)
			_ = json.Unmarshal(userJson, &user)
			users = append(users, user)
		}

		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}

	org.Users = users
	return users, nil
}

// GetUsers returns the users for a given org. Upon first call,
// it lazily updates the Organization with the user information
func (org *Organization) GetCollaborators(ctx context.Context) (
	[]types.User, error) {

	if len(org.Collaborators) > 0 {
		return org.Collaborators, nil
	}

	log.Logger.Debugf("Fetching collaborators for %s\n", *org.info.Login)
	var users []types.User
	// XXX there exists a filter option for fetching only thouse with 2fa_disabled
	// but for users let's fetch all information
	opt := &github.ListOutsideCollaboratorsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		orgMembers, resp, err := org.client.Organizations.ListOutsideCollaborators(ctx, *org.info.Login, opt)

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
			return users, err
		}

		org.backoff.Reset()
		for _, m := range orgMembers {
			// FIXME this seems to return more information although in principle it should be the same
			// as in members - is there any param we could be missing?
			u, _, err := org.client.Users.Get(ctx, *m.Login)
			if err != nil {
				log.Logger.Error(err)
				continue
			}
			user := types.User{}
			// FIXME use reflection
			userJson, _ := json.Marshal(u)
			_ = json.Unmarshal(userJson, &user)
			users = append(users, user)
		}

		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}

	org.Collaborators = users
	return users, nil
}

// GetRepositories returns the repositories for a given org. Upon first call,
// it lazily updates the Organization with the repository information
func (org *Organization) GetRepositories(ctx context.Context) (
	[]repo.Repository, error) {

	if len(org.Repositories) > 0 {
		return org.Repositories, nil
	}

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

	org.Repositories = repos
	return repos, nil
}

func (org Organization) Audit2FA(
	ctx context.Context) ([]issue.Issue, error) {

	var issues []issue.Issue

	log.Logger.Debug("Checking if 2FA is required at org-level")
	if !*org.CoreStats.TwoFactorRequirementEnabled {
		missing2FA := issue.Issue{
			// FIXME we need a central definition of all of those
			ID:          "2FA-0",
			Name:        "Organization 2FA disabled",
			Severity:    severity.Medium,
			Category:    category.Authentication,
			Description: fmt.Sprintf("Two-factor authentication requirement in organization '%s' is disabled", *org.info.Login),
			Resources: []resource.Resource{
				{
					ID:   *org.info.Login,
					Kind: resource.Organization,
				},
			},
			// FIXME we could be doing markdown / html / etc. both these and descriptions could ge tlong so we need something better
			Remediation: "Please see https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization for steps on how to configure 2FA for your organization",
		}

		issues = append(issues, missing2FA)

		usersLacking2FA := []string{}
		resources := []resource.Resource{}
		users, _ := org.GetUsers(ctx)
		for _, user := range users {
			if user.TwoFactorAuthentication == nil || !*user.TwoFactorAuthentication {
				usersLacking2FA = append(usersLacking2FA, *user.Login)
				resources = append(resources, resource.Resource{ID: *user.Login, Kind: resource.UserAccount})
			}
		}

		if len(usersLacking2FA) > 0 {
			usersMissing2FA := issue.Issue{
				ID:          "2FA-1",
				Name:        "Users without 2FA configured",
				Severity:    severity.Low,
				Category:    category.Authentication,
				CWEs:        []int{308},
				Description: fmt.Sprintf("The following users have not enabled 2FA: %s", strings.Join(usersLacking2FA, ", ")),
				Resources:   resources,
				Remediation: "Please see https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication for steps on how to configure 2FA for individual accounts",
			}
			issues = append(issues, usersMissing2FA)
		}
	}

	collaboratorsLacking2FA := []string{}
	collaborators, _ := org.GetCollaborators(ctx)
	resources := []resource.Resource{}
	for _, user := range collaborators {
		if user.TwoFactorAuthentication == nil || !*user.TwoFactorAuthentication {
			collaboratorsLacking2FA = append(collaboratorsLacking2FA, *user.Login)
			resources = append(resources, resource.Resource{ID: *user.Login, Kind: resource.UserAccount})
		}
	}

	if len(collaboratorsLacking2FA) > 0 {
		collaboratorsMissing2FA := issue.Issue{
			ID:          "2FA-2",
			Name:        "Collaborators without 2FA configured",
			Severity:    severity.Low,
			Category:    category.Authentication,
			Resources:   resources,
			CWEs:        []int{308},
			Description: fmt.Sprintf("The following collaborators have not enabled 2FA: %s", strings.Join(collaboratorsLacking2FA, ", ")),
			Remediation: "Please see https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication for steps on how to configure 2FA for individual accounts",
		}
		issues = append(issues, collaboratorsMissing2FA)
	}
	return issues, nil
}

func (org Organization) AuditWebhooks(
	ctx context.Context) ([]issue.Issue, error) {
	var issues []issue.Issue

	hooks, _ := org.GetWebhooks(ctx)
	for _, hook := range hooks {
		if !*hook.Active {
			continue
		}
		url, ok := hook.Config["url"]
		if !ok {
			continue
		}
		if strings.HasPrefix(url.(string), "http") {
			issues = append(issues, issue.Issue{
				ID:          "WH-0",
				Name:        "Insecure webhook payload URL",
				Severity:    severity.High,
				Category:    category.InformationDisclosure,
				CWEs:        []int{319},
				Description: fmt.Sprintf("Non-HTTPS webhook detected: %s", url.(string)),
				Resources:   []resource.Resource{{ID: url.(string), Kind: resource.Webhook}},
				Remediation: "It is recommended to use HTTPS webhooks if data involved is sensitive and also enable SSL verification as outlined in https://docs.github.com/en/developers/webhooks-and-events/webhooks/creating-webhooks",
			})
		}
	}
	return issues, nil
}

func (org Organization) Audit(
	ctx context.Context) ([]issue.Issue, error) {
	var allIssues []issue.Issue
	auditHooks := [](func(context.Context) ([]issue.Issue, error)){
		org.AuditWebhooks, org.Audit2FA,
	}

	for _, hook := range auditHooks {
		hookIssues, err := hook(ctx)
		if err != nil {
			log.Logger.Error(err)
		}
		allIssues = append(allIssues, hookIssues...)
	}

	return allIssues, nil
}
