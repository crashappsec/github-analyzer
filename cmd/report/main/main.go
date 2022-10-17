package main

import (
	"bytes"
	"encoding/json"
	"sort"

	// "github.com/crashappsec/github-security-auditor/pkg/futils"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	// "path/filepath"
)

type WrappedIssue struct {
	Issue       issue.Issue
	SeverityStr template.HTML
	Description template.HTML
	Remediation template.HTML
	CWEs        template.HTML
}

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
		return "<span style=\"color:#ff3a3a; font-weight:bold;\">[HIGH]</span>"
	case "Critical":
		return "<span style=\"color:#af0000; font-weight:bold;\">[CRITICAL]</span>"
	}
	return sev
}
func parsePermissions(permJson string) (string, error) {
	type userRepoPermissions map[string]([]string)
	var permissionSummary map[string]userRepoPermissions

	jsonFile, err := os.Open(permJson)
	if err != nil {
		return "", err
	}
	defer jsonFile.Close()
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

      <div class="page-header" id="banner">
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

func staticHtml(org, permissionStats string) (string, error) {

	const tmpl = `
  {{ $issues := .Issues }}
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>
      Report for {{.Org}}
    </title>
    <script src="./jquery-1.11.2.min.js"></script>
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

      <div class="page-header" id="banner">
        <div class="row">
          <div class="col-lg-12">
                Issues detected
          </div>
        </div>
      </div>

      <div id="publications">
        <div class="paperlist">
          <ul>
          {{range $issue := $issues}}
            <li>
              <div class="paper">
                <div class="papertitle">
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
                  [resources]
                  <div class="full_abstract">
                  {{$issue.Issue.Resources}}
                  </div>
                </span>
              </div>
            </li>
          {{end}}
          </ul>
        </div>
      </div>

    {{.PermissionStats}}
    </div>
  </body>

  </html>
  `

	t, err := template.New("resultsPage").Parse(tmpl)
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}

	var issues []issue.Issue

	jsonFile, err := os.Open(
		"/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/issues/issues.json",
	)
	if err != nil {
		return "", err
	}
	defer jsonFile.Close()
	jsonBytes, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(jsonBytes, &issues)

	var wrappedIssues []WrappedIssue
	for _, i := range issues {
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
		Org             string
		PermissionStats template.HTML
		Issues          []WrappedIssue
		Stats           []WrappedIssue
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Org:             org,
			PermissionStats: template.HTML(permissionStats),
			Issues:          wrappedIssues,
			Stats:           wrappedIssues,
		})
	if err != nil {
		log.Logger.Error(err)
		return "", err
	}
	return tmpBuff.String(), nil
}

func main() {
	org := "crashappsec"
	perms, err := parsePermissions(
		"/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/metadata/permissions.json",
	)
	if err != nil {
		log.Logger.Error(err)
	}
	f, err := os.Create(
		"/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/cmd/report/main/static/index.html",
	)
	defer f.Close()
	html, err := staticHtml(org, perms)
	if err != nil {
		log.Logger.Error(err)
	}
	_, err = f.WriteString(html)
	if err != nil {
		log.Logger.Error(err)
	}
	http.Handle(
		"/",
		http.FileServer(
			http.Dir(
				"/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/cmd/report/main/static",
			),
		),
	)
	http.ListenAndServe(":3000", nil)
}
