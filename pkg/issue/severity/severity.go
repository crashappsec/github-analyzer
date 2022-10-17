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

func (s Severity) String() string {
	switch s {
	case Informational:
		return "Informational"
	case Hygiene:
		return "Hygiene"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	}
	return "Unknown"
}
