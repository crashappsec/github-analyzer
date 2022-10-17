package main

import (
	"bytes"
	"encoding/json"
	"sort"

	// "github.com/crashappsec/github-security-auditor/pkg/futils"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/crashappsec/github-security-auditor/pkg/log"
	// "path/filepath"
)

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

      <div class="page-header" id="banner">
        <div class="row">
          <div class="col-lg-12">
            <h1>
              <center>
                Summary for {{.Org}} GitHub Org
              </center>
            </h1>
          </div>
        </div>
      </div>

      <div id="publications">
        <div class="paperlist">
          <ol>
            <li>
              <div class="paper">
                <div class="papertitle">
                  TODO
                </div>
                TODO2
                <span class="abstract">
                  [abstract]
                  <div class="full_abstract">
                    contents
                  </div>
                </span>
              </div>
            </li>
          </ol>
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
	type PageData struct {
		Org             string
		PermissionStats template.HTML
	}

	var tmpBuff bytes.Buffer
	err = t.Execute(&tmpBuff,
		PageData{
			Org:             org,
			PermissionStats: template.HTML(permissionStats),
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
