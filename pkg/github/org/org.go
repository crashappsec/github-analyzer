package org

import (
	"context"
	"encoding/json"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
)

type ApplicationInstallationInfo struct {
	URL                 string
	TargetType          string
	RepositorySelection string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// CoreStats is the subset of Org attributes / statistics we care about from
// the github.Organization attributes
type CoreStats struct {
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
	info      *github.Organization
	client    *github.Client
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

	return &Organization{
		info:      orgInfo,
		client:    client,
		CoreStats: &stats,
	}, nil
}

func (o Organization) Audit() issue.AuditSummary {
	// TODO
	return issue.AuditSummary{
		Stats: *o.CoreStats,
	}
}
