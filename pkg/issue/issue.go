package issue

import (
	"github.com/crashappsec/github-security-auditor/pkg/issue/category"
	"github.com/crashappsec/github-security-auditor/pkg/issue/severity"
	"github.com/crashappsec/github-security-auditor/pkg/issue/tags"
)

type Issue struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Severity    severity.Severity `json:"severity"`
	Category    category.Category `json:"category"`
	Tags        []tags.Tag        `json:"tags,omitempty"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation"`
}
