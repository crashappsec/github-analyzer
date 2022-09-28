package types

import "github.com/google/go-github/v47/github"

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

// OrgCoreStats is the subset of Org attributes / statistics we care about from
// the github.Organization attributes
type OrgCoreStats struct {
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

type Webhook struct {
	URL    *string `json:"url,omitempty"`
	ID     *int64  `json:"id,omitempty"`
	Type   *string `json:"type,omitempty"`
	Name   *string `json:"name,omitempty"`
	Active *bool   `json:"active,omitempty"`
}

type Workflow struct {
	ID    *int64  `json:"id,omitempty"`
	Name  *string `json:"name,omitempty"`
	Path  *string `json:"path,omitempty"`
	State *string `json:"state,omitempty"`
	URL   *string `json:"url,omitempty"`
}

type RepoCoreStats struct {
	ID                        *int64                      `json:"id,omitempty"`
	Owner                     *github.User                `json:"owner,omitempty"`
	Name                      *string                     `json:"name,omitempty"`
	FullName                  *string                     `json:"full_name,omitempty"`
	CodeOfConduct             *github.CodeOfConduct       `json:"code_of_conduct,omitempty"`
	DefaultBranch             *string                     `json:"default_branch,omitempty"`
	MasterBranch              *string                     `json:"master_branch,omitempty"`
	CreatedAt                 *github.Timestamp           `json:"created_at,omitempty"`
	PushedAt                  *github.Timestamp           `json:"pushed_at,omitempty"`
	UpdatedAt                 *github.Timestamp           `json:"updated_at,omitempty"`
	Language                  *string                     `json:"language,omitempty"`
	Fork                      *bool                       `json:"fork,omitempty"`
	ForksCount                *int                        `json:"forks_count,omitempty"`
	NetworkCount              *int                        `json:"network_count,omitempty"`
	OpenIssuesCount           *int                        `json:"open_issues_count,omitempty"`
	OpenIssues                *int                        `json:"open_issues,omitempty"` // Deprecated: Replaced by OpenIssuesCount. For backward compatibility OpenIssues is still populated.
	StargazersCount           *int                        `json:"stargazers_count,omitempty"`
	SubscribersCount          *int                        `json:"subscribers_count,omitempty"`
	WatchersCount             *int                        `json:"watchers_count,omitempty"` // Deprecated: Replaced by StargazersCount. For backward compatibility WatchersCount is still populated.
	Watchers                  *int                        `json:"watchers,omitempty"`       // Deprecated: Replaced by StargazersCount. For backward compatibility Watchers is still populated.
	Size                      *int                        `json:"size,omitempty"`
	Permissions               map[string]bool             `json:"permissions,omitempty"`
	AllowRebaseMerge          *bool                       `json:"allow_rebase_merge,omitempty"`
	AllowUpdateBranch         *bool                       `json:"allow_update_branch,omitempty"`
	AllowSquashMerge          *bool                       `json:"allow_squash_merge,omitempty"`
	AllowMergeCommit          *bool                       `json:"allow_merge_commit,omitempty"`
	AllowAutoMerge            *bool                       `json:"allow_auto_merge,omitempty"`
	AllowForking              *bool                       `json:"allow_forking,omitempty"`
	DeleteBranchOnMerge       *bool                       `json:"delete_branch_on_merge,omitempty"`
	UseSquashPRTitleAsDefault *bool                       `json:"use_squash_pr_title_as_default,omitempty"`
	SquashMergeCommitTitle    *string                     `json:"squash_merge_commit_title,omitempty"`   // Can be one of: "PR_TITLE", "COMMIT_OR_PR_TITLE"
	SquashMergeCommitMessage  *string                     `json:"squash_merge_commit_message,omitempty"` // Can be one of: "PR_BODY", "COMMIT_MESSAGES", "BLANK"
	MergeCommitTitle          *string                     `json:"merge_commit_title,omitempty"`          // Can be one of: "PR_TITLE", "MERGE_MESSAGE"
	MergeCommitMessage        *string                     `json:"merge_commit_message,omitempty"`        // Can be one of: "PR_BODY", "PR_TITLE", "BLANK"
	Topics                    []string                    `json:"topics,omitempty"`
	Archived                  *bool                       `json:"archived,omitempty"`
	Disabled                  *bool                       `json:"disabled,omitempty"`
	License                   *github.License             `json:"license,omitempty"`
	Private                   *bool                       `json:"private,omitempty"`
	HasIssues                 *bool                       `json:"has_issues,omitempty"`
	HasWiki                   *bool                       `json:"has_wiki,omitempty"`
	HasPages                  *bool                       `json:"has_pages,omitempty"`
	HasProjects               *bool                       `json:"has_projects,omitempty"`
	HasDownloads              *bool                       `json:"has_downloads,omitempty"`
	IsTemplate                *bool                       `json:"is_template,omitempty"`
	LicenseTemplate           *string                     `json:"license_template,omitempty"`
	GitignoreTemplate         *string                     `json:"gitignore_template,omitempty"`
	SecurityAndAnalysis       *github.SecurityAndAnalysis `json:"security_and_analysis,omitempty"`
	Visibility                *string                     `json:"visibility,omitempty"`
	RoleName                  *string                     `json:"role_name,omitempty"`
}
