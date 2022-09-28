package org

import (
	"context"
	"encoding/json"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/github/repo"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Runner struct {
	ID     *int64  `json:"id,omitempty"`
	Name   *string `json:"name,omitempty"`
	OS     *string `json:"os,omitempty"`
	Status *string `json:"status,omitempty"`
}

type Install struct {
	ID                     *int64                          `json:"id,omitempty"`
	AppID                  *int64                          `json:"app_id,omitempty"`
	TargetID               *int64                          `json:"target_id,omitempty"`
	Account                *github.User                    `json:"account,omitempty"`
	TargetType             *string                         `json:"target_type,omitempty"`
	RepositorySelection    *string                         `json:"repository_selection,omitempty"`
	Permissions            *github.InstallationPermissions `json:"permissions,omitempty"`
	CreatedAt              *github.Timestamp               `json:"created_at,omitempty"`
	HasMultipleSingleFiles *bool                           `json:"has_multiple_single_files,omitempty"`
	SuspendedBy            *github.User                    `json:"suspended_by,omitempty"`
	SuspendedAt            *github.Timestamp               `json:"suspended_at,omitempty"`
}

// CoreStats is the subset of Org attributes / statistics we care about from
// the github.Organization attributes
type CoreStats struct {
	Login                                          *string `json:"login,omitempty"`
	ID                                             *int64  `json:"id,omitempty"`
	Name                                           *string `json:"name,omitempty"`
	PublicRepos                                    *int    `json:"public_repos,omitempty"`
	PublicGists                                    *int    `json:"public_gists,omitempty"`
	Followers                                      *int    `json:"followers,omitempty"`
	Following                                      *int    `json:"following,omitempty"`
	TotalPrivateRepos                              *int    `json:"total_private_repos,omitempty"`
	OwnedPrivateRepos                              *int    `json:"owned_private_repos,omitempty"`
	PrivateGists                                   *int    `json:"private_gists,omitempty"`
	DiskUsage                                      *int    `json:"disk_usage,omitempty"`    // TODO code-smell disk usage from stale repos
	Collaborators                                  *int    `json:"collaborators,omitempty"` // TODO collaborator access
	TwoFactorRequirementEnabled                    *bool   `json:"two_factor_requirement_enabled,omitempty"`
	IsVerified                                     *bool   `json:"is_verified,omitempty"`
	HasOrganizationProjects                        *bool   `json:"has_organization_projects,omitempty"`
	HasRepositoryProjects                          *bool   `json:"has_repository_projects,omitempty"`
	DefaultRepoPermission                          *string `json:"default_repository_permission,omitempty"`
	DefaultRepoSettings                            *string `json:"default_repository_settings,omitempty"`
	MembersCanCreateRepos                          *bool   `json:"members_can_create_repositories,omitempty"`
	MembersCanCreatePublicRepos                    *bool   `json:"members_can_create_public_repositories,omitempty"`
	MembersCanCreatePrivateRepos                   *bool   `json:"members_can_create_private_repositories,omitempty"`
	MembersCanCreateInternalRepos                  *bool   `json:"members_can_create_internal_repositories,omitempty"`
	MembersCanForkPrivateRepos                     *bool   `json:"members_can_fork_private_repositories,omitempty"`
	MembersAllowedRepositoryCreationType           *string `json:"members_allowed_repository_creation_type,omitempty"`
	MembersCanCreatePages                          *bool   `json:"members_can_create_pages,omitempty"`
	MembersCanCreatePublicPages                    *bool   `json:"members_can_create_public_pages,omitempty"`
	MembersCanCreatePrivatePages                   *bool   `json:"members_can_create_private_pages,omitempty"`
	WebCommitSignoffRequired                       *bool   `json:"web_commit_signoff_required,omitempty"`
	AdvancedSecurityEnabledForNewRepos             *bool   `json:"advanced_security_enabled_for_new_repositories,omitempty"`
	DependabotAlertsEnabledForNewRepos             *bool   `json:"dependabot_alerts_enabled_for_new_repositories,omitempty"`
	DependabotSecurityUpdatesEnabledForNewRepos    *bool   `json:"dependabot_security_updates_enabled_for_new_repositories,omitempty"`
	DependencyGraphEnabledForNewRepos              *bool   `json:"dependency_graph_enabled_for_new_repositories,omitempty"`
	SecretScanningEnabledForNewRepos               *bool   `json:"secret_scanning_enabled_for_new_repositories,omitempty"`
	SecretScanningPushProtectionEnabledForNewRepos *bool   `json:"secret_scanning_push_protection_enabled_for_new_repositories,omitempty"`
}

type Organization struct {
	info    *github.Organization
	client  *github.Client
	backoff *backoff.Backoff

	CoreStats *CoreStats
}

func NewOrganization(ctx context.Context, client *github.Client, name string) (*Organization, error) {
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
	var stats CoreStats
	orgJson, _ := json.Marshal(orgInfo)
	_ = json.Unmarshal(orgJson, &stats)

	org := Organization{
		info:      orgInfo,
		client:    client,
		CoreStats: &stats,
		// FIXME have a global backoff passed as argument?
		backoff: &backoff.Backoff{
			Min:    10 * time.Second,
			Max:    1 * time.Hour,
			Jitter: true,
		},
	}
	return &org, nil
}

// FIXME refactor the below routines to do paging generically
func (org Organization) GetWebhooks(ctx context.Context) ([]repo.Webhook, error) {
	var webhooks []repo.Webhook
	// FIXME how many items is the max?
	opt := &github.ListOptions{PerPage: 100}
	for {
		hooks, resp, err := org.client.Organizations.ListHooks(ctx, *org.info.Login, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			d := org.backoff.Duration()
			log.Logger.Infoln("Hit rate limit, sleeping for %d", d)
			time.Sleep(d)
		}

		if err != nil {
			if resp.StatusCode == 403 {
				log.Logger.Infoln("It appears the token being used doesn't have access to this information")
			} else {
				log.Logger.Error(err)
			}
			return webhooks, err
		}

		org.backoff.Reset()
		for _, hook := range hooks {
			wh := repo.Webhook{
				URL:    hook.URL,
				ID:     hook.ID,
				Type:   hook.Type,
				Name:   hook.Name,
				Active: hook.Active,
			}
			webhooks = append(webhooks, wh)
		}

		if resp.NextPage == 0 {
			break
		}

		opt.Page = resp.NextPage
	}

	return webhooks, nil
}

func (org Organization) GetInstalls(ctx context.Context) ([]Install, error) {
	var orgInstalls []Install
	opt := &github.ListOptions{PerPage: 100}

	for {
		installs, resp, err := org.client.Organizations.ListInstallations(ctx, *org.info.Login, opt)

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
			return orgInstalls, err
		}

		org.backoff.Reset()
		for _, install := range installs.Installations {
			in := Install{
				ID:                     install.ID,
				AppID:                  install.AppID,
				TargetID:               install.TargetID,
				Account:                install.Account,
				TargetType:             install.TargetType,
				RepositorySelection:    install.RepositorySelection,
				Permissions:            install.Permissions,
				CreatedAt:              install.CreatedAt,
				HasMultipleSingleFiles: install.HasMultipleSingleFiles,
				SuspendedBy:            install.SuspendedBy,
				SuspendedAt:            install.SuspendedAt,
			}
			orgInstalls = append(orgInstalls, in)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return orgInstalls, nil
}

func (org *Organization) GetActionRunners(ctx context.Context) ([]Runner, error) {
	log.Logger.Debugf("Fetching action runners for %s\n", org.info.Login)

	var orgRunners []Runner
	opt := &github.ListOptions{PerPage: 10}

	for {
		runners, resp, err := org.client.Actions.ListOrganizationRunners(ctx, *org.info.Login, opt)

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
			return orgRunners, err
		}

		org.backoff.Reset()
		for _, runner := range runners.Runners {
			r := Runner{
				ID:     runner.ID,
				Name:   runner.Name,
				OS:     runner.OS,
				Status: runner.Status,
			}
			orgRunners = append(orgRunners, r)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return orgRunners, nil
}

func (org *Organization) GetRepositories(ctx context.Context) ([]repo.Repository, error) {
	log.Logger.Debugf("Fetching repositories for %s\n", *org.info.Login)
	var repos []repo.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 10},
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
			r, err := repo.NewRepository(ctx, org.client, ghRepository)
			if err != nil {
				log.Logger.Error(err)
				continue
			}
			repos = append(repos, *r)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return repos, nil
}
