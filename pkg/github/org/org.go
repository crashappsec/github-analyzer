package org

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/crashappsec/github-security-auditor/pkg/github/repo"
	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/github/utils"
	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/resource"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/issue/tags"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Organization struct {
	info           *github.Organization
	client         *github.Client
	backoff        *backoff.Backoff
	paginationSize int

	CoreStats *types.OrgCoreStats
	// FIXME change to maps of ids
	Users         map[types.UserLogin]types.User
	Collaborators map[types.UserLogin]types.User
	Repositories  map[types.RepoName]repo.Repository
	Webhooks      map[types.WebhookID]types.Webhook
	Installations map[types.InstallID]types.Install
	Runners       map[types.RunnerID]types.Runner
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
			log.Logger.Errorf(
				"Unable to retrieve organization information. It appears the token being used doesn't have access to this information.",
			)
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
		info:           orgInfo,
		client:         client,
		backoff:        backoff,
		paginationSize: 100,
		CoreStats:      &stats,
	}
	return &org, nil
}

// GetWebhook returns the webhooks for a given org. Upon first call,
// it lazily updates the Organization with the webhook information
func (org Organization) GetWebhooks(
	ctx context.Context) (map[types.WebhookID]types.Webhook, error) {
	if len(org.Webhooks) > 0 {
		return org.Webhooks, nil
	}

	opt := &github.ListOptions{PerPage: org.paginationSize}
	hooks, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		opt,
		func(opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
			return org.client.Organizations.ListHooks(ctx,
				*org.info.Login,
				opt,
			)
		},
		utils.WebhooksAggregator,
	)

	hookMap := make(map[types.WebhookID]types.Webhook, len(hooks))
	for _, h := range hooks {
		hookMap[types.WebhookID(*h.ID)] = h
	}
	org.Webhooks = hookMap
	return hookMap, err
}

func (org Organization) GetInstalls(
	ctx context.Context) (map[types.InstallID]types.Install, error) {
	if len(org.Installations) > 0 {
		return org.Installations, nil
	}

	opt := &github.ListOptions{PerPage: org.paginationSize}
	installs, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		opt,
		func(opts *github.ListOptions) (*github.OrganizationInstallations, *github.Response, error) {
			return org.client.Organizations.ListInstallations(
				ctx,
				*org.info.Login,
				opt,
			)
		},
		utils.InstallsAggregator,
	)

	installMap := make(map[types.InstallID]types.Install, len(installs))
	for _, i := range installs {
		installMap[types.InstallID(*i.ID)] = i
	}
	org.Installations = installMap
	return installMap, err
}

func (org Organization) GetActionRunners(
	ctx context.Context) (map[types.RunnerID]types.Runner, error) {
	if len(org.Runners) > 0 {
		return org.Runners, nil
	}

	opt := &github.ListOptions{PerPage: org.paginationSize}
	runners, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		opt,
		func(opts *github.ListOptions) (*github.Runners, *github.Response, error) {
			return org.client.Actions.ListOrganizationRunners(
				ctx,
				*org.info.Login,
				opt,
			)
		},
		utils.RunnersAggregator,
	)

	runnerMap := make(map[types.RunnerID]types.Runner, len(runners))
	for _, r := range runners {
		runnerMap[types.RunnerID(*r.ID)] = r
	}
	org.Runners = runnerMap
	return runnerMap, err
}

// GetUsers returns the users for a given org. Upon first call,
// it lazily updates the Organization with the user information
func (org *Organization) GetUsers(ctx context.Context) (
	map[types.UserLogin]types.User, error) {

	if len(org.Users) > 0 {
		return org.Users, nil
	}

	log.Logger.Debugf("Fetching users for %s\n", *org.info.Login)
	opt := &github.ListMembersOptions{
		ListOptions: github.ListOptions{PerPage: org.paginationSize},
	}
	users, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		&opt.ListOptions,
		func(opts *github.ListOptions) ([]*github.User, *github.Response, error) {
			return org.client.Organizations.ListMembers(
				ctx,
				*org.info.Login,
				opt,
			)
		},
		func(ghUsers []*github.User) []types.User {
			var users []types.User
			for _, m := range ghUsers {
				// XXX information from listing collborators is incomplete
				// we meed tp explicitly fetch user info
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
			return users
		},
	)
	if err != nil {
		log.Logger.Error(err)
	}

	members := make(map[types.UserLogin]types.User, len(users))
	for _, u := range users {
		members[types.UserLogin(*u.Login)] = u
	}
	org.Users = members
	return members, nil
}

// GetCollaborators returns the outside collaborators for a given org. Upon first call,
// it lazily updates the Organization with the user information
func (org *Organization) GetCollaborators(ctx context.Context) (
	map[types.UserLogin]types.User, error) {

	if len(org.Collaborators) > 0 {
		return org.Collaborators, nil
	}

	log.Logger.Debugf(
		"Fetching external collaborators for %s\n",
		*org.info.Login,
	)
	opt := &github.ListOutsideCollaboratorsOptions{
		ListOptions: github.ListOptions{PerPage: org.paginationSize},
	}
	users, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		&opt.ListOptions,
		func(opts *github.ListOptions) ([]*github.User, *github.Response, error) {
			return org.client.Organizations.ListOutsideCollaborators(
				ctx,
				*org.info.Login,
				opt,
			)
		},
		func(ghUsers []*github.User) []types.User {
			var users []types.User
			for _, m := range ghUsers {
				// XXX information from listing collborators is incomplete
				// we meed tp explicitly fetch user info
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
			return users
		},
	)
	if err != nil {
		log.Logger.Error(err)
	}

	collaborators := make(map[types.UserLogin]types.User, len(users))
	for _, u := range users {
		collaborators[types.UserLogin(*u.Login)] = u
	}
	org.Collaborators = collaborators
	return collaborators, nil
}

// GetRepositories returns the repositories for a given org. Upon first call,
// it lazily updates the Organization with the repository information
func (org *Organization) GetRepositories(ctx context.Context) (
	map[types.RepoName]repo.Repository, error) {

	if len(org.Repositories) > 0 {
		return org.Repositories, nil
	}

	log.Logger.Debugf("Fetching repositories for %s\n", *org.info.Login)
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: org.paginationSize},
	}
	ghRepos, err := utils.GetPaginatedResult(
		ctx,
		org.backoff,
		&opt.ListOptions,
		func(opts *github.ListOptions) ([]*github.Repository, *github.Response, error) {
			return org.client.Repositories.ListByOrg(
				ctx,
				*org.info.Login,
				opt,
			)
		},
		func(ghRepositories []*github.Repository) []repo.Repository {
			var repos []repo.Repository
			for _, ghRepository := range ghRepositories {
				// ghRepository has incomplete information at this stage wrt to Org
				ghRepo, _, err := org.client.Repositories.GetByID(
					ctx,
					*ghRepository.ID,
				)
				if err != nil {
					log.Logger.Error(err)
					continue
				}
				r, err := repo.NewRepository(
					ctx,
					org.client,
					org.backoff,
					ghRepo,
				)
				if err != nil {
					log.Logger.Error(err)
					continue
				}
				repos = append(repos, *r)
			}
			return repos
		},
	)
	if err != nil {
		log.Logger.Error(err)
	}

	repositories := make(map[types.RepoName]repo.Repository, len(ghRepos))
	for _, r := range ghRepos {
		repositories[types.RepoName(*r.CoreStats.Name)] = r
	}
	org.Repositories = repositories
	return repositories, nil
}

func (org Organization) Audit2FA(
	ctx context.Context) ([]issue.Issue, error) {

	var issues []issue.Issue

	log.Logger.Debug("Checking if 2FA is required at org-level")
	if !*org.CoreStats.TwoFactorRequirementEnabled {
		missing2FA := issue.Issue{
			// FIXME we need a central definition of all of those
			ID:       "2FA-0",
			Name:     "Organization 2FA disabled",
			Severity: severity.Medium,
			Category: category.Authentication,
			Description: fmt.Sprintf(
				"Two-factor authentication requirement in organization '%s' is disabled",
				*org.info.Login,
			),
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
			if user.TwoFactorAuthentication == nil ||
				!*user.TwoFactorAuthentication {
				usersLacking2FA = append(usersLacking2FA, *user.Login)
				resources = append(
					resources,
					resource.Resource{
						ID:   *user.Login,
						Kind: resource.UserAccount,
					},
				)
			}
		}

		if len(usersLacking2FA) > 0 {
			usersMissing2FA := issue.Issue{
				ID:       "2FA-1",
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
			issues = append(issues, usersMissing2FA)
		}
	}

	collaboratorsLacking2FA := []string{}
	collaborators, _ := org.GetCollaborators(ctx)
	resources := []resource.Resource{}
	for _, user := range collaborators {
		if user.TwoFactorAuthentication == nil ||
			!*user.TwoFactorAuthentication {
			collaboratorsLacking2FA = append(
				collaboratorsLacking2FA,
				*user.Login,
			)
			resources = append(
				resources,
				resource.Resource{ID: *user.Login, Kind: resource.UserAccount},
			)
		}
	}

	if len(collaboratorsLacking2FA) > 0 {
		collaboratorsMissing2FA := issue.Issue{
			ID:        "2FA-2",
			Name:      "Collaborators without 2FA configured",
			Severity:  severity.Low,
			Category:  category.Authentication,
			Resources: resources,
			CWEs:      []int{308},
			Description: fmt.Sprintf(
				"The following collaborators have not enabled 2FA: %s",
				strings.Join(collaboratorsLacking2FA, ", "),
			),
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
		if !strings.HasPrefix(url.(string), "https") {
			issues = append(issues, issue.Issue{
				ID:       "WH-0",
				Name:     "Insecure webhook payload URL",
				Severity: severity.High,
				Category: category.InformationDisclosure,
				CWEs:     []int{319},
				Description: fmt.Sprintf(
					"Non-HTTPS webhook detected: %s",
					url.(string),
				),
				Resources: []resource.Resource{
					{ID: url.(string), Kind: resource.Webhook},
				},
				Remediation: "It is recommended to use HTTPS webhooks if data involved is sensitive and also enable SSL verification as outlined in https://docs.github.com/en/developers/webhooks-and-events/webhooks/creating-webhooks",
			})
		}
	}
	return issues, nil
}

func (org Organization) AuditCoreStats(
	ctx context.Context) ([]issue.Issue, error) {
	var issues []issue.Issue

	if !*org.CoreStats.AdvancedSecurityEnabledForNewRepos {
		issues = append(issues, issue.Issue{
			ID:       "Config-AdvancedSecurity-0",
			Name:     "Advanced security disabled for new repositories",
			Severity: severity.Medium,
			Category: category.ToolingAndAutomation,
			CWEs:     []int{319},
			Description: fmt.Sprintf(
				"Advanced security disabled for org %s",
				*org.info.Login,
			),
			Resources: []resource.Resource{
				{
					ID:   *org.info.Login,
					Kind: resource.Organization,
				},
			},
			Tags:        []tags.Tag{tags.AdvancedSecurity},
			Remediation: "Pleasee see https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security for how to enable secret scanning in your repositories",
		})
	}

	if !*org.CoreStats.SecretScanningEnabledForNewRepos {
		issues = append(issues, issue.Issue{
			ID:       "Config-AdvancedSecurity-1",
			Name:     "Secret scanning disabled for new repositories",
			Severity: severity.Medium,
			Category: category.InformationDisclosure,
			CWEs:     []int{319},
			Description: fmt.Sprintf(
				"Secret scanning disabled for org %s",
				*org.info.Login,
			),
			Resources: []resource.Resource{
				{
					ID:   *org.info.Login,
					Kind: resource.Organization,
				},
			},
			Tags:        []tags.Tag{tags.AdvancedSecurity},
			Remediation: "Pleasee see https://docs.github.com/en/github-ae@latest/code-security/secret-scanning/configuring-secret-scanning-for-your-repositories for how to enable secret scanning in your repositories",
		})
	}
	return issues, nil
}

func (org Organization) AuditMemberPermissions(
	ctx context.Context) ([]issue.Issue, error) {
	var issues []issue.Issue

	repos, err := org.GetRepositories(ctx)
	if err != nil {
		log.Logger.Error(err)
		return issues, err
	}
	for _, r := range repos {
		log.Logger.Infoln(*r.CoreStats.Name)
		println("--------------------")
		collabs, _ := r.GetCollaborators(ctx)
		for _, u := range collabs {
			fmt.Println(github.Stringify(u))
			perms, _, err := org.client.Repositories.GetPermissionLevel(
				ctx,
				*org.info.Login,
				*r.CoreStats.Name,
				*u.Login,
			)
			fmt.Println(github.Stringify(perms))
			if err != nil {
				log.Logger.Error(err)
				continue
			}
		}
	}
	panic("dfasdfasdf")
	return issues, nil
}

func (org Organization) Audit(
	ctx context.Context) ([]issue.Issue, error) {
	var allIssues []issue.Issue
	auditHooks := [](func(context.Context) ([]issue.Issue, error)){
		// org.AuditMemberPermissions, org.AuditCoreStats, org.AuditWebhooks, org.Audit2FA,
		org.Audit2FA,
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
