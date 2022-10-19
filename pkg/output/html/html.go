package html

import (
	"bytes"
	"encoding/json"
	"sort"

	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/crashappsec/github-analyzer/pkg/github/org"
	"github.com/crashappsec/github-analyzer/pkg/issue"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/google/go-github/scrape"
	"github.com/google/go-github/v47/github"
)

type WrappedOAuthApp struct {
	App   scrape.OAuthApp
	State string
}

type WrappedIssue struct {
	Issue       issue.Issue
	SeverityStr template.HTML
	Description template.HTML
	Remediation template.HTML
	CWEs        template.HTML
}

// normalizeLinks converts any raw http links to hrefs
func normalizeLinks(input string) string {
	sep := strings.Split(input, " ")
	for i, s := range sep {
		if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
			sep[i] = fmt.Sprintf(
				"<a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">here</a>",
				s,
			)
		}
	}
	return strings.Join(sep, " ")
}

func getSeverity(sev string) string {
	switch sev {
	case "Informational":
		return "<span style=\"color:#ff3acd; font-weight:bold;\">[INFO]</span>"
	case "Low":
		return "<span style=\"color:#b3ff00; font-weight:bold;\">[LOW]</span>"
	case "Medium":
		return "<span style=\"color:yellow; font-weight:bold;\">[MEDIUM]</span>"
	case "High":
		return "<span style=\"color:#da0a0a; font-weight:bold;\">[HIGH]</span>"
	case "Critical":
		return "<span style=\"color:#bf0000; font-weight:bold;\">[CRITICAL]</span>"
	}
	return sev
}

func getOauthAppState(s int) string {
	if s == 1 {
		return "Requested"
	}
	if s == 2 {
		return "Approved"
	}
	if s == 3 {
		return "Denied"
	}
	return "Unknown"
}

func parseStats(statsJson string) (string, error) {
	var stats org.OrgStats

	jsonFile, err := os.Open(statsJson)
	defer jsonFile.Close()
	if err != nil {
		return "", err
	}
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", err
	}
	json.Unmarshal(jsonBytes, &stats)

	const tmpl = `
  {{ $stats := .Stats }}
  {{ $installations := .Installations }}
  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        Org Info
      </div>
    </div>
  </div>

  <div>
    <div class="shortlist">
      <ul>
        <li><b>Name:</b> {{$stats.CoreStats.Name}}</li>
        <li><b>ID:</b> {{$stats.CoreStats.ID}}</li>
         <li> <b>Organization is verified:</b> {{$stats.CoreStats.IsVerified}}</li>
        <li> <b>Web commit Signoff Required:</b> {{$stats.CoreStats.WebCommitSignoffRequired}}</li>
         <li> <b>Number of public repos:</b> {{$stats.CoreStats.PublicRepos}}</li>
         <li> <b>Number of private repos:</b> {{$stats.CoreStats.TotalPrivateRepos}}</li>
         <li> <b>Number of public gists:</b> {{$stats.CoreStats.PublicGists}}</li>
         <li> <b>Number of private gists:</b> {{$stats.CoreStats.PrivateGists}}</li>
         <!-- <li> <b>Number of collaborators:</b> {{$stats.CoreStats.Collaborators}}</li> -->
         <li> <b>Number of webhooks:</b> {{$.TotalWebhooks}}</li>
         <li> <b>Number of installations:</b> {{$.TotalInstallations}}</li>
         <li> <b>Number of runners:</b> {{$.TotalRunners}}</li>
         <li> <b>Members can create public repositories:</b> {{$stats.CoreStats.MembersCanCreatePublicRepos}}</li>
         <li> <b>Members can create private repositories:</b> {{$stats.CoreStats.MembersCanCreatePrivateRepos}}</li>
         <li> <b>Members can create internal repositories:</b> {{$stats.CoreStats.MembersCanCreateInternalRepos}}</li>
      </ul>
    </div>
  </div>

  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        Dependency and Secret Scanning
      </div>
    </div>
  </div>
  <div>
    <div class="shortlist">
      <ul>
        <li> <b>Advanced Security alerts enabled for new repos:</b> {{$stats.CoreStats.AdvancedSecurityEnabledForNewRepos}}</li>
        <li> <b>Dependabot alerts enabled for new repos:</b> {{$stats.CoreStats.DependabotAlertsEnabledForNewRepos}}</li>
        <li> <b>Dependabot security updates enabled for new repos:</b> {{$stats.CoreStats.DependabotSecurityUpdatesEnabledForNewRepos}}</li>
        <li> <b>Dependency graph enabled for new repos:</b> {{$stats.CoreStats.DependencyGraphEnabledForNewRepos}}</li>
        <li> <b>Secret scanning enabled for new repos:</b> {{$stats.CoreStats.SecretScanningEnabledForNewRepos}}</li>
        <li> <b>Secret scanning push protection enabled for new repos:</b> {{$stats.CoreStats.SecretScanningPushProtectionEnabledForNewRepos}}</li>
      </ul>
    </div>
  </div>

  {{if $installations}}
  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        Installations
      </div>
    </div>
  </div>
  <div>
    <ul>
      {{range $install := $installations}}
      <li>
        <div class="issuetitle">
        {{$install.Name}} (ID: {{$install.ID}})
        </div>
      <b> Permissions </b> : {{$install.Permissions}}
      </li>
      {{end}}
    </ul>
  </div>
  {{end}}
  `
	t, err := template.New("stats").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	type InstallationInfo struct {
		Name        string
		ID          int64
		Permissions string
	}
	type PageData struct {
		Stats              org.OrgStats
		TotalRunners       int
		TotalInstallations int
		TotalWebhooks      int
		Installations      []InstallationInfo
	}

	var wrappedInstallations []InstallationInfo
	for _, i := range stats.Installations {
		perm := strings.Split(github.Stringify(i.Permissions), "{")
		description := strings.Split(strings.Split(perm[1], "}")[0], ", ")
		sort.Strings(description)
		finalPerm := strings.Join(description, ", ")
		wrappedInstallations = append(wrappedInstallations,
			InstallationInfo{
				ID:          *i.ID,
				Name:        *i.AppSlug,
				Permissions: finalPerm,
			})
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Stats:              stats,
			Installations:      wrappedInstallations,
			TotalRunners:       len(stats.Runners),
			TotalWebhooks:      len(stats.Webhooks),
			TotalInstallations: len(stats.Installations),
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func parseOauthApps(appJson string) (string, error) {
	var apps []scrape.OAuthApp

	jsonFile, err := os.Open(appJson)
	defer jsonFile.Close()
	if err != nil {
		return "", err
	}
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", err
	}
	json.Unmarshal(jsonBytes, &apps)

	var wrappedApps []WrappedOAuthApp
	for _, app := range apps {
		wrappedApps = append(wrappedApps,
			WrappedOAuthApp{App: app, State: getOauthAppState(int(app.State))})
	}
	const tmpl = `
  {{ $apps := .Apps }}
  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        OAuth App Statistics
      </div>
    </div>
  </div>

  <div>
    <div class="issuelist">
      <ul>
        {{range $app := $apps}}
        <li>
          <div class="issue">
            <div class="issuetitle">
              {{$app.App.Name}} (ID: {{$app.App.ID}})
            </div>
            {{if $app.App.Description}}
            <div class="description">
              <b>Description:</b> {{$app.App.Description}}
            </div>
            {{end}}
            <div class="state">
              <b>Status:</b> {{$app.State}}
            </div>
          </div>
          {{if $app.App.RequestedBy}}
          <div class="requester">
            <b>Requested By:</b> {{$app.App.RequestedBy}}
          </div>
          {{end}}
        </li>
        {{end}}
      </ul>
    </div>
  </div>
  `
	t, err := template.New("oauthAppsList").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	type PageData struct {
		Apps []WrappedOAuthApp
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Apps: wrappedApps,
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func parsePermissions(permJson string) (string, error) {
	type userRepoPermissions map[string]([]string)
	var permissionSummary map[string]userRepoPermissions

	jsonFile, err := os.Open(permJson)
	defer jsonFile.Close()
	if err != nil {
		return "", err
	}
	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(jsonBytes, &permissionSummary)

	allPerms := map[string]bool{}
	allUsers := map[string]bool{}
	for u, perms := range permissionSummary {
		allUsers[u] = true
		for perm := range perms {
			allPerms[perm] = true
		}
	}
	var permissions []string
	for p := range allPerms {
		permissions = append(permissions, p)
	}
	var users []string
	for p := range allUsers {
		users = append(users, p)
	}
	sort.Strings(permissions)
	sort.Strings(users)

	finalSummary := map[string]map[string]string{}
	/// Make sure we fill everything up
	for _, u := range users {
		finalSummary[u] = map[string]string{}
		for _, perm := range permissions {
			_, ok := permissionSummary[u][perm]
			if !ok {
				finalSummary[u][perm] = ""
			} else {
				sort.Strings(permissionSummary[u][perm])
				finalSummary[u][perm] = strings.Join(permissionSummary[u][perm], ", ")
			}
		}
	}

	const tmpl = `
  {{ $users := .Users }}
  {{ $permissions := .Permissions }}
  {{ $summary := .Summary }}

  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        User Permission Statistics
      </div>
    </div>
  </div>
  <table class="table table-hover">
    <thead>
      <tr>
        <th scope="col">User</th>
        {{range $permissions}}
        <th scope="col">{{.}}</th>
        {{end}}
      </tr>
    </thead>
    <tbody>
      {{range $user := $users}}
      <tr>
        <th scope="row">{{$user}}</th>
        {{range $perm := $permissions}}
        <td>{{index $summary $user $perm}}</td>
        {{end}}
      </tr>
      {{end}}
    </tbody>
  </table>
  `
	t, err := template.New("permissionsTable").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	type PageData struct {
		Permissions []string
		Users       []string
		Summary     map[string]map[string]string
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Permissions: permissions,
			Users:       users,
			Summary:     finalSummary,
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func parseIssues(execStatusPath, issuesPath string) (string, error) {
	const tmpl = `
  {{ $issues := .Issues }}
  {{ $passed := .ChecksPassed }}
  <div class="page-header">
    <div class="row">
      <div class="col-lg-12">
        Issues detected
      </div>
    </div>
  </div>

  {{if $issues}}
    <div class="issuelist">
      <ul>
        {{range $issue := $issues}}
        <li>
          <div class="issue">
            <div class="issuetitle">
              {{$issue.SeverityStr}} {{$issue.Issue.Name}}
            </div>
            <div class="cwes">
              <b>Related CWEs:</b> {{$issue.CWEs}}
            </div>
            <div class="description">
              <b>Description:</b> {{$issue.Description}}
            </div>
            <div class="remediation">
              <b>Remediation:</b> {{$issue.Remediation}}
            </div>
            <span class="abstract">
              [vulnerable resources]
              <div class="full_abstract">
                {{$issue.Issue.Resources}}
              </div>
            </span>
          </div>
        </li>
        {{end}}
      </ul>
    </div>
  {{end}}

  {{if $passed}}
    <div class="page-header">
      <div class="row">
        <div class="col-lg-12">
          Checks Passed
        </div>
      </div>
    </div>
    <div>
      <ul>
        {{range $issue := $passed}}
        <li>
          <div class="issue">
            <div class="issuetitle">
              {{$issue}} <svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
                <path class="checkmark__check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
              </svg>
            </div>
        </li>
        {{end}}
      </ul>
    </div>
  {{end}}
  `

	t, err := template.New("resultsPage").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}

	var checks map[issue.IssueID]error

	jsonFile, err := os.Open(execStatusPath)
	if err != nil {
		jsonFile.Close()
		return "", err
	}
	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(jsonBytes, &checks)
	jsonFile.Close()

	var issues []issue.Issue

	jsonFile, err = os.Open(issuesPath)
	if err != nil {
		jsonFile.Close()
		return "", err
	}
	jsonBytes, _ = ioutil.ReadAll(jsonFile)
	json.Unmarshal(jsonBytes, &issues)
	jsonFile.Close()

	var wrappedIssues []WrappedIssue

	// order by severity in descending order
	sort.Slice(issues, func(i, j int) bool {
		return issues[i].Severity > issues[j].Severity
	})
	for _, i := range issues {
		delete(checks, i.ID)
		if strings.HasPrefix(string(i.ID), "STATS") {
			continue
		}
		var cweStrings []string
		for _, cwe := range i.CWEs {
			cweStrings = append(
				cweStrings,
				fmt.Sprintf(
					"<a href=\"https://cwe.mitre.org/data/definitions/%d.html\" target=\"_blank\" rel=\"noopener noreferrer\">%d</a>",
					cwe,
					cwe,
				),
			)
		}
		wrappedIssues = append(wrappedIssues,
			WrappedIssue{
				Issue:       i,
				SeverityStr: template.HTML(getSeverity(i.Severity.String())),
				Description: template.HTML(normalizeLinks(i.Description)),
				Remediation: template.HTML(normalizeLinks(i.Remediation)),
				CWEs:        template.HTML(strings.Join(cweStrings, ",")),
			})
	}

	type PageData struct {
		Issues       []WrappedIssue
		ChecksPassed []string
	}

	var passed []string
	for ch := range checks {
		if strings.HasPrefix(string(ch), "STATS") {
			continue
		}
		passed = append(passed, issue.AvailableChecks[ch])
	}
	sort.Strings(passed)

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Issues:       wrappedIssues,
			ChecksPassed: passed,
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func staticHtml(
	org, stats, issues, permissionStats, appInfo string,
) (string, error) {

	const tmpl = `
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>
      Report for {{.Org}}
    </title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link rel="stylesheet" href="./bootstrap.css" media="screen" type="text/css">
    <link rel="stylesheet" href="./font-awesome.min.css" type="text/css">
    <link rel="stylesheet" href="./plain.css" type="text/css">
    <link rel="shortcut icon" href="./favicon.webp">
  </head>

  <body>
  <div class="container">
    <div class="scantitle">
      Summary for {{.Org}}
    </div>

    {{.IssueStats}}

    {{if .HasNonIssueStats }}
      <div class="sectiontitle">
        {{.Org}} Misc Stats
      </div>

      {{.OrgStats}}

      {{.AppStats}}

      {{.PermissionStats}}
    {{end}}
  </div>
  </body>

  </html>
  `

	t, err := template.New("finalPage").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}

	type PageData struct {
		Org              string
		IssueStats       template.HTML
		HasNonIssueStats bool
		OrgStats         template.HTML
		AppStats         template.HTML
		PermissionStats  template.HTML
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Org:              org,
			HasNonIssueStats: (stats != "" || permissionStats != "" || appInfo != ""),
			OrgStats:         template.HTML(stats),
			IssueStats:       template.HTML(issues),
			PermissionStats:  template.HTML(permissionStats),
			AppStats:         template.HTML(appInfo),
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func Serve(
	org, orgStatsPath, permissionsPath, oauthAppPath, execStatusPath, issuesPath string,
	htmlDir string,
	port int,
) {
	perms, err := parsePermissions(permissionsPath)
	if err != nil {
		log.Logger.Error(err)
	}

	appInfo, err := parseOauthApps(oauthAppPath)
	if err != nil {
		log.Logger.Error(err)
	}

	issues, err := parseIssues(execStatusPath, issuesPath)
	if err != nil {
		log.Logger.Error(err)
	}

	stats, err := parseStats(orgStatsPath)
	if err != nil {
		log.Logger.Error(err)
	}

	f, err := os.Create(filepath.Join(htmlDir, "index.html"))
	defer f.Close()

	html, err := staticHtml(org, stats, issues, perms, appInfo)
	if err != nil {
		log.Logger.Error(err)
	}

	_, err = f.WriteString(html)
	if err != nil {
		log.Logger.Error(err)
	}
	http.Handle("/", http.FileServer(http.Dir(htmlDir)))

	log.Logger.Infoln(
		"See the output/ directory for raw JSON files with analysis metadata",
	)
	log.Logger.Infof("Server with HTML summary started at localhost:%d\n", port)

	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
