package futils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/crashappsec/github-analyzer/pkg/config"
	"github.com/crashappsec/github-analyzer/pkg/log"
)

var IssuesDir, StatsDir, MetadataDir, HtmlDir string

func Init() {
	IssuesDir = filepath.Join(config.ViperEnv.OutputDir, "issues")
	StatsDir = filepath.Join(config.ViperEnv.OutputDir, "stats")
	MetadataDir = filepath.Join(config.ViperEnv.OutputDir, "metadata")

	CreateDir(config.ViperEnv.OutputDir)
	CreateDir(IssuesDir)
	CreateDir(StatsDir)
	CreateDir(MetadataDir)
}

func CreateDir(path string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, os.ModePerm)
		if err != nil {
			log.Logger.Fatal(
				"Could not create directories in %s. Please ensure you have write permissions for this directory",
				path,
			)
		}
	}
}

func SerializeFile(raw interface{}, writeLoc string) error {
	output, err := json.MarshalIndent(raw, "", " ")
	if err != nil {
		log.Logger.Error(err)
		return err
	}
	return ioutil.WriteFile(writeLoc, output, 0644)
}
