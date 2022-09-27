package repo

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

type Runner struct {
	Name   string
	Status string
}

type Repository struct {
	ActionRunners              []Runner
	HasWiki                    bool
	IsPrivate                  bool
	Name                       string
	URL                        string
	VulnerabilityAlertsEnabled bool
	Webhooks                   []Webhook
	Workflows                  []Workflow
}
