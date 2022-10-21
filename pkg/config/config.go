package config

const (
	ConfigFileBasename = "github-analyzer"

	ViperEnvPrefix = "GH_SECURITY_AUDITOR"
)

type ViperEnvVars struct {
	CfgFile             string `mapstructure:"CFG_FILE"`
	EnableScraping      bool   `mapstructure:"ENABLE_SCRAPING"`
	UserPermissionStats bool   `mapstructure:"USER_PERMISSION_STATS"`
	Version             bool   `mapstructure:"VERSION"`
	Organization        string `mapstructure:"ORGANIZATION"`
	OtpSeed             string `mapstructure:"OTP_SEED"`
	OutputDir           string `mapstructure:"OUTPUT_DIR"`
	Password            string `mapstructure:"PASSWORD"`
	Port                int    `mapstructure:"PORT"`
	ScmURL              string `mapstructure:"SCM_URL"`
	Token               string `mapstructure:"TOKEN"`
	Username            string `mapstructure:"USERNAME"`
}

var ViperEnv ViperEnvVars
