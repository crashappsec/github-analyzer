package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	_ "embed"
	"path/filepath"

	"github.com/crashappsec/github-analyzer/pkg/config"
	"github.com/crashappsec/github-analyzer/pkg/futils"
	"github.com/crashappsec/github-analyzer/pkg/github/auditor"
	"github.com/crashappsec/github-analyzer/pkg/issue"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/crashappsec/github-analyzer/pkg/output/html"
	"github.com/crashappsec/github-analyzer/pkg/scraping"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

//go:generate sh version.sh
//go:embed version.txt
var version string

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		log.Logger.Errorf("Scan completed with errors", err)
		os.Exit(1)
	}
}

func runCmd() {
	var issues []issue.Issue
	var stats []issue.Issue
	var checkStatuses map[issue.IssueID]error

	futils.Init()

	if config.ViperEnv.EnableScraping {
		if config.ViperEnv.Username == "" ||
			config.ViperEnv.Password == "" ||
			config.ViperEnv.OtpSeed == "" {
			log.Logger.Fatalf(
				"The following flags are required for scraping --username, --password, --otp",
			)
		}
		sissues, execStatus, err := scraping.AuditScraping(
			config.ViperEnv.Username,
			config.ViperEnv.Password,
			config.ViperEnv.OtpSeed,
			config.ViperEnv.Organization)
		if err != nil {
			log.Logger.Error(err)
		}
		issues = append(issues, sissues...)
		checkStatuses = execStatus
	}

	if config.ViperEnv.Token == "" {
		log.Logger.Errorf("Github token not set")
	} else {
		auditor, err := auditor.NewGithubAuditor(config.ViperEnv.Token)
		if err != nil {
			log.Logger.Error(err)
			return
		}
		results, execStatus, err := auditor.AuditOrg(config.ViperEnv.Organization, config.ViperEnv.UserPermissionStats)
		if err != nil {
			log.Logger.Error(err)
		}
		for _, r := range results {
			if strings.HasPrefix(string(r.ID), "STATS") {
				stats = append(stats, r)
			} else {
				issues = append(issues, r)
			}
		}

		// update the map of what has executed if we have info from scraping
		if len(checkStatuses) > 0 {
			for id, err := range execStatus {
				prevError, ok := checkStatuses[id]
				if !ok {
					// this is the first time we see this check
					checkStatuses[id] = err
					continue
				}
				// if we have additional errors just merge them for now
				if err != nil {
					if prevError != nil {
						checkStatuses[id] = errors.New(err.Error() + prevError.Error())
					}
				}
			}
		} else {
			checkStatuses = execStatus
		}
	}

	errors := map[issue.IssueID]string{}
	for k, v := range checkStatuses {
		if v == nil {
			errors[k] = ""
			continue
		}
		errors[k] = fmt.Sprintf("%v", v)
	}
	issuesPath := filepath.Join(futils.IssuesDir, "issues.json")
	auditStatsPath := filepath.Join(futils.StatsDir, "auditStats.json")
	execStatusPath := filepath.Join(futils.MetadataDir, "execStatus.json")
	oauthPath := filepath.Join(futils.MetadataDir, "oauthApps.json")
	permissionsPath := filepath.Join(futils.MetadataDir, "permissions.json")
	orgStatsPath := filepath.Join(futils.StatsDir, "orgCoreStats.json")

	futils.SerializeFile(issues, issuesPath)
	futils.SerializeFile(stats, auditStatsPath)
	futils.SerializeFile(errors, execStatusPath)

	html.Serve(
		config.ViperEnv.Organization,
		orgStatsPath,
		permissionsPath,
		oauthPath,
		execStatusPath,
		issuesPath,
		futils.HtmlDir,
		config.ViperEnv.Port,
	)
}

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: fmt.Sprintf(
			"github-analyzer (%s)",
			strings.TrimSuffix(version, "\n"),
		),
		Short: "A tool to collect statistics and highlight potential security issues within a GitHub org",
		Long:  "A tool to collect statistics and highlight potential security issues within a GitHub org",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
			return initializeConfig(cmd)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			onlyPrintVersion, _ := cmd.Flags().GetBool("version")
			if onlyPrintVersion {
				fmt.Println(version)
				os.Exit(0)
			}
			cmd.MarkFlagRequired("organization")
		},
		Run: func(cmd *cobra.Command, args []string) {
			runCmd()
		},
	}
	// TODO allow auditing a repo/user account only
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Organization, "organization", "", "", "the GitHub organization to be analyzed")

	rootCmd.Flags().
		StringVarP(&config.ViperEnv.CfgFile, "config", "c", "", "config file (default is $HOME/.github-analyzer.yaml)")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.OutputDir, "output", "o", "output", "the directory containing the artifacts of the analysis")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.ScmURL, "scmUrl", "", "", "the API URL for the source control management software you want to check")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Token, "token", "", "", fmt.Sprintf("the github token for API authentication (default is $%s_TOKEN)", config.ViperEnvPrefix))

	rootCmd.Flags().
		BoolVarP(&config.ViperEnv.Version, "version", "", false, "print version and exit")
	rootCmd.Flags().
		BoolVarP(&config.ViperEnv.UserPermissionStats, "userPermissionStats", "", false, "enable user permission statistics (might be slow in large orgs due to throttling limits)")

	rootCmd.Flags().
		BoolVarP(&config.ViperEnv.EnableScraping, "enableScraping", "", false, "enable experimental checks that rely on screen scraping")
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Username, "username", "u", "", fmt.Sprintf("username (required if enableScraping is set) (default is $%s_USERNAME)", config.ViperEnvPrefix))
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.Password, "password", "p", "", fmt.Sprintf("password (required if enableScraping is set) (default is $%s_PASSWORD)", config.ViperEnvPrefix))
	rootCmd.Flags().
		StringVarP(&config.ViperEnv.OtpSeed, "otpSeed", "", "", fmt.Sprintf("one Time Password (required if enableScraping is set) (default is $%s_OTP_SEED)", config.ViperEnvPrefix))

	rootCmd.Flags().
		IntVarP(&config.ViperEnv.Port, "port", "", 3000, "port for local http server used to display HTML with summary of findings (if you are using docker you will need to override the default port appropriately)")
	return rootCmd
}

func initializeConfig(cmd *cobra.Command) error {
	v := viper.New()
	v.SetDefault("Verbose", true)
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
