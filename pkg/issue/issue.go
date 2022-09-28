package issue

// TODO define issues / statistics in a uniform way
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
	// TODO use weight when assigning scores for healthcheck of a repo / org
	Weight int
}
