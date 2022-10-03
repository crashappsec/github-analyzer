package repo

import (
	"context"
	"encoding/json"

	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/github/utils"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Repository struct {
	info           *github.Repository
	client         *github.Client
	backoff        *backoff.Backoff
	paginationSize int

	CoreStats     *types.RepoCoreStats
	Webhooks      map[types.WebhookID]types.Webhook
	Workflows     map[types.WorkflowID]types.Workflow
	Collaborators map[types.UserLogin]types.User
}

func NewRepository(
	ctx context.Context,
	client *github.Client,
	backoff *backoff.Backoff,
	raw *github.Repository) (*Repository, error) {
	// FIXME change to not use unmarshal w/ reflection or plain initializer
	var stats types.RepoCoreStats
	orgJson, _ := json.Marshal(raw)
	_ = json.Unmarshal(orgJson, &stats)

	return &Repository{
		info:           raw,
		client:         client,
		backoff:        backoff,
		paginationSize: 100,
		CoreStats:      &stats,
	}, nil
}

func (repo *Repository) GetWebhooks(
	ctx context.Context) (map[types.WebhookID]types.Webhook, error) {
	if len(repo.Webhooks) > 0 {
		return repo.Webhooks, nil
	}

	opt := &github.ListOptions{PerPage: repo.paginationSize}
	hooks, err := utils.GetPaginatedResult(
		ctx,
		repo.backoff,
		opt,
		func(opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
			return repo.client.Repositories.ListHooks(ctx,
				*repo.info.Organization.Login,
				*repo.info.Name,
				opt,
			)
		},
		utils.WebhooksAggregator,
	)

	hookMap := make(map[types.WebhookID]types.Webhook, len(hooks))
	for _, h := range hooks {
		hookMap[types.WebhookID(*h.ID)] = h
	}
	repo.Webhooks = hookMap
	return hookMap, err
}

func (repo *Repository) GetWorkflows(
	ctx context.Context) (map[types.WorkflowID]types.Workflow, error) {
	if len(repo.Workflows) > 0 {
		return repo.Workflows, nil
	}

	opt := &github.ListOptions{PerPage: repo.paginationSize}
	workflows, err := utils.GetPaginatedResult(
		ctx,
		repo.backoff,
		opt,
		func(opts *github.ListOptions) (*github.Workflows, *github.Response, error) {
			return repo.client.Actions.ListWorkflows(
				ctx,
				*repo.info.Organization.Login,
				*repo.info.Name,
				opt,
			)
		},
		utils.WorkflowsAggregator,
	)

	wfMap := make(map[types.WorkflowID]types.Workflow, len(workflows))
	for _, w := range workflows {
		wfMap[types.WorkflowID(*w.ID)] = w
	}
	repo.Workflows = wfMap
	return wfMap, err
}

// GetCollaborators returns the outside collaborators for a given org. Upon first call,
// it lazily updates the Organization with the user information
func (repo *Repository) GetCollaborators(ctx context.Context) (
	map[types.UserLogin]types.User, error) {

	if len(repo.Collaborators) > 0 {
		return repo.Collaborators, nil
	}

	log.Logger.Debugf(
		"Fetching external collaborators for %s",
		*repo.info.Name,
	)
	opt := &github.ListCollaboratorsOptions{
		ListOptions: github.ListOptions{PerPage: repo.paginationSize},
	}
	users, err := utils.GetPaginatedResult(
		ctx,
		repo.backoff,
		&opt.ListOptions,
		func(opts *github.ListOptions) ([]*github.User, *github.Response, error) {
			return repo.client.Repositories.ListCollaborators(
				ctx,
				*repo.info.Organization.Login,
				*repo.info.Name,
				opt,
			)
		},
		func(ghUsers []*github.User) []types.User {
			var users []types.User
			for _, m := range ghUsers {
				// XXX information from listing collborators is incomplete
				// we meed tp explicitly fetch user info
				u, _, err := repo.client.Users.Get(ctx, *m.Login)
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
	repo.Collaborators = collaborators
	return collaborators, nil
}
