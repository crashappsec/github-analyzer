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
	stats := "/Users/nettrino/go/src/github.com/crashappsec/github-security-auditor/output/stats/orgCoreStats.json"
	html.Serve(org, stats, permissionsPath, appPath, execStatus, issues, 3000)
}
