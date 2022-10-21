package html

import (
	"encoding/json"
	"sort"

	"embed"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/crashappsec/github-analyzer/pkg/github/org"
	"github.com/crashappsec/github-analyzer/pkg/issue"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/google/go-github/scrape"
	"github.com/google/go-github/v47/github"
)

//go:embed templates
var indexHTML embed.FS

//go:embed static
var staticFiles embed.FS

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

type InstallationInfo struct {
	Name        string
	ID          int64
	Permissions string
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

func parseStats(statsJson string) (org.OrgStats, []InstallationInfo, error) {
	var stats org.OrgStats

	jsonFile, err := os.Open(statsJson)
	defer jsonFile.Close()
	if err != nil {
		return stats, nil, err
	}
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return stats, nil, err
	}
	json.Unmarshal(jsonBytes, &stats)

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
	return stats, wrappedInstallations, nil
}

func parseOauthApps(appJson string) ([]WrappedOAuthApp, error) {
	var apps []scrape.OAuthApp

	jsonFile, err := os.Open(appJson)
	defer jsonFile.Close()
	if err != nil {
		return nil, err
	}
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(jsonBytes, &apps)

	var wrappedApps []WrappedOAuthApp
	for _, app := range apps {
		wrappedApps = append(wrappedApps,
			WrappedOAuthApp{App: app, State: getOauthAppState(int(app.State))})
	}
	return wrappedApps, nil
}

func parsePermissions(
	permJson string,
) ([]string, []string, map[string]map[string]string, error) {
	type userRepoPermissions map[string]([]string)
	var permissionSummary map[string]userRepoPermissions

	jsonFile, err := os.Open(permJson)
	defer jsonFile.Close()
	if err != nil {
		return nil, nil, nil, err
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

	return permissions, users, finalSummary, nil
}

func parseIssues(
	execStatusPath, issuesPath string,
) ([]WrappedIssue, []string, []string, error) {
	var checks map[issue.IssueID]string
	jsonFile, err := os.Open(execStatusPath)
	if err != nil {
		jsonFile.Close()
		return nil, nil, nil, err
	}
	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(jsonBytes, &checks)
	jsonFile.Close()

	var issues []issue.Issue

	jsonFile, err = os.Open(issuesPath)
	if err != nil {
		jsonFile.Close()
		return nil, nil, nil, err
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

	var passed []string
	var failed []string
	for ch, hadError := range checks {
		if strings.HasPrefix(string(ch), "STATS") {
			continue
		}
		if hadError != "" {
			failed = append(failed, issue.AvailableChecks[ch])
		} else {
			passed = append(passed, issue.AvailableChecks[ch])
		}
	}
	sort.Strings(passed)
	sort.Strings(failed)
	return wrappedIssues, passed, failed, nil
}

func Serve(
	orgName, orgStatsPath, permissionsPath, oauthAppPath, execStatusPath, issuesPath string,
	htmlDir string,
	port int,
) {
	perms, users, permissionSummary, err := parsePermissions(permissionsPath)
	if err != nil {
		log.Logger.Error(err)
	}

	wrappedIssues, checksPassed, checksFailed, err := parseIssues(
		execStatusPath,
		issuesPath,
	)
	if err != nil {
		log.Logger.Error(err)
	}

	stats, wrappedInstallations, err := parseStats(orgStatsPath)
	if err != nil {
		log.Logger.Error(err)
	}

	apps, err := parseOauthApps(oauthAppPath)
	if err != nil {
		log.Logger.Error(err)
	}

	var staticFS = http.FS(staticFiles)
	fs := http.FileServer(staticFS)

	type PageData struct {
		Org                string
		HasNonIssueStats   bool
		Stats              org.OrgStats
		TotalRunners       int
		TotalInstallations int
		TotalWebhooks      int
		Apps               []WrappedOAuthApp
		Issues             []WrappedIssue
		Installations      []InstallationInfo
		ChecksPassed       []string
		ChecksFailed       []string
		Permissions        []string
		Users              []string
		PermissionSummary  map[string]map[string]string
	}

	t, err := template.ParseFS(indexHTML, "templates/index.html.tmpl")
	if err != nil {
		log.Logger.Error(err)
	}
	http.Handle("/static/", fs)
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "text/html")
		t.Execute(w,
			PageData{
				Org:                orgName,
				HasNonIssueStats:   true,
				Apps:               apps,
				Stats:              stats,
				TotalRunners:       len(stats.Runners),
				TotalInstallations: len(stats.Installations),
				TotalWebhooks:      len(stats.Webhooks),
				Issues:             wrappedIssues,
				Installations:      wrappedInstallations,
				ChecksPassed:       checksPassed,
				ChecksFailed:       checksFailed,
				Permissions:        perms,
				Users:              users,
				PermissionSummary:  permissionSummary,
			})

	})

	log.Logger.Infof(
		"Server with HTML summary starting at 0.0.0.0:%d\n",
		port,
	)
	fmt.Println(
		"\n\n\t Analysis complete! Visit localhost:3000 using your browser to see results",
	)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Logger.Error(err)
	}
}
