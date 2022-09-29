package main

import (
	"fmt"
	"os"
	"strings"

	"encoding/json"
	"io/ioutil"

	"github.com/crashappsec/github-security-auditor/pkg/config"
	"github.com/crashappsec/github-security-auditor/pkg/github/auditor"
	"github.com/crashappsec/github-security-auditor/pkg/issue"
	"github.com/crashappsec/github-security-auditor/pkg/log"
	"github.com/crashappsec/github-security-auditor/pkg/scraping"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		log.Logger.Errorf("Scan completed with errors", err)
		os.Exit(1)
	}
}

func runCmd() {
	var issues []issue.Issue

	if config.ViperEnv.EnableScraping {
		sissues, err := scraping.AuditScraping(
			config.ViperEnv.Username,
			config.ViperEnv.Password,
			config.ViperEnv.Otp,
			config.ViperEnv.Organization)
		if err != nil {
			log.Logger.Error(err)
		}
		issues = append(issues, sissues...)
	}

	token := os.Getenv(config.ViperEnv.TokenName)
	if token == "" {
		log.Logger.Error(fmt.Errorf("Github token not set"))
	} else {
		auditor, err := auditor.NewGithubAuditor(token)
		if err != nil {
			log.Logger.Error(err)
			return
		}
		results, err := auditor.AuditOrg(config.ViperEnv.Organization)
		if err != nil {
			log.Logger.Error(err)
		}
		issues = append(issues, results...)
	}

	output, _ := json.MarshalIndent(issues, "", " ")
	// XXX remove this
	log.Logger.Infof("%s", output)
	_ = ioutil.WriteFile(config.ViperEnv.OutputFile, output, 0644)

}

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "github-security-auditor",
		Short: "A tool to collect and highlight potential security issues with a GitHub org",
		Long: `A tool to collect and highlight potential security issues with a GitHub org. It looks
	at things like:
	* Webhooks
	* User configuration
	* Number of guests
	* Repo and Organization-level settings`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initializeConfig(cmd)
		},
		Run: func(cmd *cobra.Command, args []string) {
			runCmd()
		},
	}
	// FIXME change the command line flags to allow auditing an org / repo etc
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Organization, "organization", "", "", "The organization we want to check the security on")
	rootCmd.MarkFlagRequired("organization")

	rootCmd.Flags().
		StringVarP(&config.ViperEnv.CfgFile, "config", "c", "", "config file (default is $HOME/.github-security-auditor.yaml)")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.OutputFile, "output", "o", "githubsecurity.json", "The file that should have the output recorded to")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.ScmURL, "scmUrl", "", "", "The API URL for the source control management software you want to check")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.TokenName, "tokenName", "", "GH_SECURITY_AUDITOR_TOKEN", "The environment variable name we should retrieve the token for API authentication")

	rootCmd.Flags().
		BoolVarP(&config.ViperEnv.EnableScraping, "enableScraping", "", false, "Enable experimental checks that rely on screen scraping")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Username, "username", "u", "", "Username (required if enableScraping is set)")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Password, "password", "p", "", "Password (required if enableScraping is set)")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Otp, "otp", "", "", "One Time Password (required if enableScraping is set)")
	// rootCmd.MarkFlagsRequiredTogether(
	// 	"enableScraping",
	// 	"username",
	// 	"password",
	// 	"otp",
	// )

	return rootCmd
}

func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()
	// TODO add a file-based config
	v.SetConfigName(config.ConfigFileBasename)
	v.AddConfigPath(".")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	v.SetEnvPrefix(config.ViperEnvPrefix)
	v.AutomaticEnv()
	bindFlags(cmd, v)

	return nil
}

// bindFlags binds cobra flags to viper environment variables
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// env variables have no dashes
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(
				strings.ReplaceAll(f.Name, "-", "_"),
			)
			v.BindEnv(
				f.Name,
				fmt.Sprintf("%s_%s", config.ViperEnvPrefix, envVarSuffix),
			)
		}

		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}
