package config

const (
	ConfigFileBasename = "github-security-auditor"

	ViperEnvPrefix = "GH_SECURITY_AUDITOR"
)

type ViperEnvVars struct {
	CfgFile        string `mapstructure:"CFG_FILE"`
	Organization   string `mapstructure:"ORGANIZATION"`
	OutputFile     string `mapstructure:"OUTPUT_FILE"`
	EnableScraping bool   `mapstructure:"ENABLE_SCRAPING"`
	Username       string `mapstructure:"USERNAME"`
	Password       string `mapstructure:"PASSWORD"`
	OtpSeed        string `mapstructure:"OTP_SEED"`
	ScmURL         string `mapstructure:"SCM_URL"`
	TokenName      string `mapstructure:"TOKEN_NAME"`
}

var ViperEnv ViperEnvVars
