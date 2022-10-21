package utils

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"time"

	"github.com/crashappsec/github-analyzer/pkg/github/types"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/google/go-github/v47/github"
	"github.com/jpillora/backoff"
)

var PermissionsError = fmt.Errorf("Permissions error")

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
	globalBackoff *backoff.Backoff,
	callOpts *github.ListOptions,
	githubCall func(opts *github.ListOptions) (K, *github.Response, error),
	aggregator func(K) []T,
) ([]T, error) {

	var results []T
	retries := 0

	var back *backoff.Backoff
	if globalBackoff != nil {
		back = &backoff.Backoff{
			Min:    globalBackoff.Min,
			Max:    globalBackoff.Max,
			Jitter: globalBackoff.Jitter,
		}
	} else {
		back = &backoff.Backoff{
			Min:    30 * time.Second,
			Max:    10 * time.Minute,
			Jitter: true,
		}
	}

	for {
		raw, resp, err := githubCall(callOpts)

		_, ok := err.(*github.RateLimitError)
		if ok || resp == nil {
			d := back.Duration()
			log.Logger.Infof("Hit rate limit, sleeping for %v", d)
			time.Sleep(d)
			if resp == nil {
				retries += 1
				if retries > 5 {
					return results, fmt.Errorf(
						"Aborting after 5 failed retries",
					)
				}
			}
			continue
		}

		retries = 0
		if err != nil && resp != nil {
			if resp.StatusCode == 403 {
				log.Logger.Debugf(
					"It appears the token being used doesn't have access to call %v",
					runtime.FuncForPC(reflect.ValueOf(githubCall).Pointer()).
						Name(),
				)
				log.Logger.Errorf(
					"The token used does not have premissions to make this API call",
				)
			} else {
				log.Logger.Error(err)
			}
			return results, err
		}

		back.Reset()
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
