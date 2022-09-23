/*
Copyright © 2020 Mike de Libero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v32/github"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"io/ioutil"
	"os"
	"time"
)

type ScannerResults struct {
	TwoFactorAuthEnabled     bool
	NumberPrivateRepos       int
	NumberPublicRepos        int
	Webhooks                 []Webhook
	ApplicationInstallations []Install
	ActionRunners            []Runner
	Repositories             []RepositoryInformation
}

type RepositoryInformation struct {
	Name                       string
	URL                        string
	IsPrivate                  bool
	Webhooks                   []Webhook
	HasWiki                    bool
	VulnerabilityAlertsEnabled bool
	Workflows                  []Workflow
}

type Webhook struct {
	URL    string
	Active bool
}

type Workflow struct {
	URL   string
	State string
	Name  string
	Path  string
}

type Install struct {
	URL                 string
	TargetType          string
	RepositorySelection string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Runner struct {
	Name   string
	Status string
}

type GithubScanner struct {
	client *github.Client
}

var cfgFile string
var Organization string
var OutputFile string
var ScmURL string
var TokenName string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "githubsecurityauditor",
	Short: "A tool to collect and highlight potential security issues with a GitHub org",
	Long: `A tool to collect and highlight potential security issues with a GitHub org. It looks 
	at things like:
	* Webhooks
	* User configuration
	* Number of guests
	* Repo and Organization-level settings`,
	Run: func(cmd *cobra.Command, args []string) {
		scanner := GithubScanner{}
		scanner.runScan()
	},
}

func (gs GithubScanner) RetrieveRepoWebhooks(ctx context.Context, org, repo string) []Webhook {
	var hooks []Webhook
	opt := &github.ListOptions{PerPage: 10}

	for {
	request:
		webhooks, resp, err := gs.client.Repositories.ListHooks(ctx, org, repo, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			if resp.StatusCode == 403 {
				fmt.Println("It appears the token being used doesn't have access to this information")
			} else {
				fmt.Println(err)
			}
			return hooks
		}

		for _, hook := range webhooks {
			wh := Webhook{}
			wh.URL = hook.Config["url"].(string)
			wh.Active = *hook.Active
			hooks = append(hooks, wh)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return hooks
}

func (gs GithubScanner) RetrieveOrgWebhooks(ctx context.Context, org *string) []Webhook {
	var webhooks []Webhook
	opt := &github.ListOptions{PerPage: 10}
	for {
	request:
		hooks, resp, err := gs.client.Organizations.ListHooks(ctx, *org, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			if resp.StatusCode == 403 {
				fmt.Println("It appears the token being used doesn't have access to this information")
			} else {
				fmt.Println(err)
			}
			return webhooks
		}

		for _, hook := range hooks {
			wh := Webhook{}
			wh.URL = hook.Config["url"].(string)
			wh.Active = *hook.Active
			webhooks = append(webhooks, wh)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return webhooks
}

func (gs GithubScanner) RetrieveOrgInstalls(ctx context.Context, org *string) []Install {
	var orgInstalls []Install
	opt := &github.ListOptions{PerPage: 10}

	for {
	request:
		installs, resp, err := gs.client.Organizations.ListInstallations(ctx, *org, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			if resp.StatusCode == 403 {
				fmt.Println("It appears the token being used doesn't have access to this information")
			} else {
				fmt.Println(err)
			}
			return orgInstalls
		}

		for _, install := range installs.Installations {
			in := Install{}
			in.URL = *install.HTMLURL
			in.TargetType = *install.TargetType
			in.RepositorySelection = *install.RepositorySelection
			in.CreatedAt = install.CreatedAt.Time
			in.UpdatedAt = install.UpdatedAt.Time
			orgInstalls = append(orgInstalls, in)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return orgInstalls
}

func (gs GithubScanner) RetrieveRepoWorkflows(ctx context.Context, org, repo string) []Workflow {
	var repoWorkflows []Workflow
	opt := &github.ListOptions{PerPage: 10}
	for {
	request:
		workflows, resp, err := gs.client.Actions.ListWorkflows(ctx, org, repo, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			if resp.StatusCode == 403 {
				fmt.Println("It appears the token being used doesn't have access to this information")
			} else {
				fmt.Println(err)
			}
			return repoWorkflows
		}

		for _, workflow := range workflows.Workflows {
			w := Workflow{}
			w.Name = *workflow.Name
			w.URL = *workflow.URL
			w.Path = *workflow.Path
			w.State = *workflow.State

			repoWorkflows = append(repoWorkflows, w)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return repoWorkflows
}

func (gs GithubScanner) RetrieveOrgActionRunners(ctx context.Context, org *string) []Runner {
	var orgRunners []Runner
	opt := &github.ListOptions{PerPage: 10}

	for {
	request:
		runners, resp, err := gs.client.Actions.ListOrganizationRunners(ctx, *org, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			if resp.StatusCode == 403 {
				fmt.Println("It appears the token being used doesn't have access to this information")
			} else {
				fmt.Println(err)
			}
			return orgRunners
		}

		for _, runner := range runners.Runners {
			r := Runner{}
			r.Name = *runner.Name
			r.Status = *runner.Status
			orgRunners = append(orgRunners, r)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return orgRunners
}

func (gs GithubScanner) RetrieveRepositoryInformation(ctx context.Context, org *string) []RepositoryInformation {
	var repoInfo []RepositoryInformation

	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	}

	for {
	request:
		repos, resp, err := gs.client.Repositories.ListByOrg(ctx, *org, opt)

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
			goto request
		}

		if err != nil {
			fmt.Println(err)
			return repoInfo
		}

		for _, repo := range repos {
			ri := RepositoryInformation{}
			ri.Name = *repo.Name
			ri.URL = *repo.HTMLURL
			ri.IsPrivate = *repo.Private
			ri.HasWiki = *repo.HasWiki
			ri.Webhooks = gs.RetrieveRepoWebhooks(ctx, *org, ri.Name)
			enabled, _, _ := gs.client.Repositories.GetVulnerabilityAlerts(ctx, *org, *repo.Name)
			ri.VulnerabilityAlertsEnabled = enabled
			ri.Workflows = gs.RetrieveRepoWorkflows(ctx, *org, ri.Name)
			repoInfo = append(repoInfo, ri)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return repoInfo
}

func (gs GithubScanner) RetrieveOrgSettings(ctx context.Context, org *string, results ScannerResults) ScannerResults {
	orgInfo, resp, err := gs.client.Organizations.Get(ctx, *org)

	if err != nil {
		if resp.StatusCode == 403 {
			fmt.Println("Unable to retrieve organization information. It appears the token being used doesn't have access to this information.")
		} else {
			fmt.Println(err)
		}
		return results
	}
	results.TwoFactorAuthEnabled = *orgInfo.TwoFactorRequirementEnabled
	results.NumberPublicRepos = *orgInfo.PublicRepos
	results.NumberPrivateRepos = *orgInfo.TotalPrivateRepos
	results.Webhooks = gs.RetrieveOrgWebhooks(ctx, org)
	results.ApplicationInstallations = gs.RetrieveOrgInstalls(ctx, org)
	results.ActionRunners = gs.RetrieveOrgActionRunners(ctx, org)
	results.Repositories = gs.RetrieveRepositoryInformation(ctx, org)

	return results
}

func (gs GithubScanner) runScan() {
	token := os.Getenv(TokenName)
	if token == "" {
		fmt.Println(TokenName + " is empty")
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	if ScmURL != "" {
		var clientErr error
		gs.client, clientErr = github.NewEnterpriseClient(ScmURL, ScmURL, tc)

		if clientErr != nil {
			fmt.Println(clientErr)
			return
		}
	} else {
		gs.client = github.NewClient(tc)
	}
	var results ScannerResults
	results = gs.RetrieveOrgSettings(ctx, &Organization, results)

	output, _ := json.MarshalIndent(results, "", " ")
	_ = ioutil.WriteFile(OutputFile, output, 0644)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.Flags().StringVarP(&cfgFile, "config", "", "", "config file (default is $HOME/.githubsecurityauditor.yaml)")
	rootCmd.Flags().StringVarP(&Organization, "organization", "", "", "The organization we want to check the security on")
	rootCmd.Flags().StringVarP(&OutputFile, "output", "", "githubsecurity.json", "The file that should have the output recorded to")
	rootCmd.Flags().StringVarP(&ScmURL, "scmUrl", "", "", "The API URL for the source control management software you want to check")
	rootCmd.Flags().StringVarP(&TokenName, "tokenName", "", "GIT_TOKEN", "The environment variable name we should retrieve the token for API authentication")

	rootCmd.MarkFlagRequired("organization")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".githubsecurityauditor" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".githubsecurityauditor")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
