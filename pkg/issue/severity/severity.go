package severity

type Severity int

const (
	Informational Severity = iota
	Hygiene
	Low
	Medium
	High
	Critical
)
