package repo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/github/utils"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

type Repository struct {
	info           *github.Repository
	client         *github.Client
	backoff        *backoff.Backoff
	paginationSize int

	CoreStats *types.RepoCoreStats
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
	ctx context.Context) ([]types.Webhook, error) {

	return utils.GetRepoPaginatedResult(
		ctx,
		repo.backoff,
		*repo.info.Organization.Name,
		*repo.info.Name,
		ctx,
		&github.ListOptions{PerPage: repo.paginationSize},
		repo.client.Repositories.ListHooks,
		utils.WebhooksAggregator)
}

func (repo *Repository) GetWorkflows(
	ctx context.Context) ([]types.Workflow, error) {
	return utils.GetRepoPaginatedResult(
		ctx,
		repo.backoff,
		*repo.info.Organization.Name,
		*repo.info.Name,
		ctx,
		&github.ListOptions{PerPage: repo.paginationSize},
		repo.client.Actions.ListWorkflows,
		utils.WorkflowsAggregator)
}
