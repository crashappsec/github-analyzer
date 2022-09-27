package repo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

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

type CoreStats struct {
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

type Repository struct {
	info    *github.Repository
	client  *github.Client
	backoff *backoff.Backoff

	CoreStats *CoreStats
}

func NewRepository(ctx context.Context, client *github.Client, raw *github.Repository) (*Repository, error) {
	// FIXME change to not use unmarshal w/ reflection or plain initializer
	var stats CoreStats
	orgJson, _ := json.Marshal(raw)
	_ = json.Unmarshal(orgJson, &stats)

	return &Repository{
		info:      raw,
		client:    client,
		CoreStats: &stats,
		// FIXME have a global backoff passed as argument?
		backoff: &backoff.Backoff{
			Min:    10 * time.Second,
			Max:    1 * time.Hour,
			Jitter: true,
		},
	}, nil
}

func (repo *Repository) GetWebhooks(ctx context.Context) ([]Webhook, error) {
	var hooks []Webhook
	opt := &github.ListOptions{PerPage: 10}

	for {
		webhooks, resp, err := repo.client.Repositories.ListHooks(ctx, *repo.info.Organization.Name, *repo.info.Name, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			d := repo.backoff.Duration()
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
			return hooks, err
		}

		repo.backoff.Reset()
		for _, hook := range webhooks {
			wh := Webhook{
				URL:    hook.URL,
				ID:     hook.ID,
				Type:   hook.Type,
				Name:   hook.Name,
				Active: hook.Active,
			}
			hooks = append(hooks, wh)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return hooks, nil
}

func (repo *Repository) GetWorkflows(ctx context.Context) ([]Workflow, error) {
	var repoWorkflows []Workflow
	opt := &github.ListOptions{PerPage: 10}
	for {
		workflows, resp, err := repo.client.Actions.ListWorkflows(ctx, *repo.info.Organization.Name, *repo.info.Name, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			d := repo.backoff.Duration()
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
			return repoWorkflows, err
		}

		repo.backoff.Reset()
		for _, workflow := range workflows.Workflows {
			w := Workflow{
				ID:    workflow.ID,
				Name:  workflow.Name,
				Path:  workflow.Path,
				State: workflow.State,
				URL:   workflow.URL,
			}
			repoWorkflows = append(repoWorkflows, w)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return repoWorkflows, nil
}
