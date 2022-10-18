package config

const (
	ConfigFileBasename = "github-security-auditor"

	ViperEnvPrefix = "GH_SECURITY_AUDITOR"
)

type ViperEnvVars struct {
	CfgFile        string `mapstructure:"CFG_FILE"`
	EnableScraping bool   `mapstructure:"ENABLE_SCRAPING"`
	EnableStats    bool   `mapstructure:"ENABLE_STATS"`
	Organization   string `mapstructure:"ORGANIZATION"`
	OtpSeed        string `mapstructure:"OTP_SEED"`
	OutputDir      string `mapstructure:"OUTPUT_DIR"`
	Password       string `mapstructure:"PASSWORD"`
	Port           int    `mapstructure:"PORT"`
	ScmURL         string `mapstructure:"SCM_URL"`
	TokenName      string `mapstructure:"TOKEN_NAME"`
	Username       string `mapstructure:"USERNAME"`
}

var ViperEnv ViperEnvVars
