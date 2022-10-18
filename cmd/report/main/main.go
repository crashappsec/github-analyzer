package main

import (
	"github.com/crashappsec/github-security-auditor/pkg/output/html"
)

func main() {
	org := "crashappsec"
	execStatus := "/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/metadata/execStatus.json"
	permissionsPath := "/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/metadata/permissions.json"
	appPath := "/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/metadata/oauthApps.json"
	issues := "/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/issues/issues.json"
	html.Serve(org, permissionsPath, appPath, execStatus, issues, 3000)
}
