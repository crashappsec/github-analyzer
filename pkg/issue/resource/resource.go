package resource

type Kind string

const (
	UserAccount  Kind = "UserAccount"
	Organization      = "Organization"
	Webhook           = "Webhook"
)

type Resource struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
}
