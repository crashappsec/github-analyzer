package issue

type Severity int

const (
	Hygiene Severity = iota
	Low
	Medium
	High
	Critical
)

type Category string

const (
	Code        Category = "code"
	Permissions          = "permissions"
	CICD                 = "cicd"
	Actions              = "actions"
	Workflows            = "workflows"
)

type Issue struct {
	Severity    Severity
	Category    Category
	Description string
	Remediation string
	// TODO use weight when assigning scores cumulatively
	Weight int
}

type AuditSummary struct {
	Issues []Issue
	Stats  interface{}
}
