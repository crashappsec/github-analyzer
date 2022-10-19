package utils

import (
	"context"
	"time"

	"github.com/crashappsec/github-security-auditor/pkg/github/types"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

func RunnersAggregator(runners *github.Runners) []types.Runner {
	var orgRunners []types.Runner
	for _, runner := range runners.Runners {
		r := types.Runner{
			ID:     runner.ID,
			Name:   runner.Name,
			OS:     runner.OS,
			Status: runner.Status,
		}
		orgRunners = append(orgRunners, r)
	}
	return orgRunners
}

func InstallsAggregator(
	installs *github.OrganizationInstallations,
) []types.Install {
	var orgInstalls []types.Install

	for _, install := range installs.Installations {
		in := types.Install{
			ID:                     install.ID,
			AppID:                  install.AppID,
			AppSlug:                install.AppSlug,
			NodeID:                 install.NodeID,
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
	return orgInstalls
}

func WebhooksAggregator(hooks []*github.Hook) []types.Webhook {
	var webhooks []types.Webhook
	for _, hook := range hooks {
		wh := types.Webhook{
			URL:     hook.URL,
			ID:      hook.ID,
			Type:    hook.Type,
			Name:    hook.Name,
			TestURL: hook.TestURL,
			PingURL: hook.PingURL,
			Config:  hook.Config,
			Active:  hook.Active,
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks
}

func WorkflowsAggregator(workflows *github.Workflows) []types.Workflow {
	var repoWorkflows []types.Workflow
	for _, workflow := range workflows.Workflows {
		w := types.Workflow{
			ID:    workflow.ID,
			Name:  workflow.Name,
			Path:  workflow.Path,
			State: workflow.State,
			URL:   workflow.URL,
		}
		repoWorkflows = append(repoWorkflows, w)
	}
	return repoWorkflows
}

func GetPaginatedResult[T any, K any](
	ctx context.Context,
	backoff *backoff.Backoff,
	callOpts *github.ListOptions,
	githubCall func(opts *github.ListOptions) (K, *github.Response, error),
	aggregator func(K) []T,
) ([]T, error) {

	var results []T
	for {
		raw, resp, err := githubCall(callOpts)

		if _, ok := err.(*github.RateLimitError); ok {
			d := backoff.Duration()
			log.Logger.Infoln("Hit rate limit, sleeping for %d", d)
			time.Sleep(d)
			continue
		}

		if err != nil {
			if resp.StatusCode == 403 {
				log.Logger.Infoln(
					"It appears the token being used doesn't have access to this information",
				)
			} else {
				log.Logger.Error(err)
			}
			return results, err
		}

		backoff.Reset()
		for _, res := range aggregator(raw) {
			results = append(results, res)
		}

		if resp.NextPage == 0 {
			break
		}

		callOpts.Page = resp.NextPage
	}

	return results, nil
}
