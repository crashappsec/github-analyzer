package severity

type Severity int

const (
	Hygiene Severity = iota
	Low
	Medium
	High
	Critical
)
