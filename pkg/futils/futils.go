package futils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/crashappsec/github-security-auditor/pkg/config"
)

var IssuesDir, StatsDir, MetadataDir string

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
		_ = os.Mkdir(path, os.ModePerm)
	}
}

func SerializeFile(raw interface{}, writeLoc string) error {
	output, err := json.MarshalIndent(raw, "", " ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(writeLoc, output, 0644)
}
