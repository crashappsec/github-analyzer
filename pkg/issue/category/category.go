package category

type Category string

const (
	Code                  Category = "Code"
	LeastPrivilege                 = "Least Privilege"
	Authentication                 = "Authentication"
	Authorization                  = "Authorization"
	InformationDisclosure          = "Information disclosure to untrusted parties"
)
