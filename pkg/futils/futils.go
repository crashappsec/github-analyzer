package futils

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/crashappsec/github-analyzer/pkg/config"
	"github.com/crashappsec/github-analyzer/pkg/log"
	"github.com/otiai10/copy"
)

var IssuesDir, StatsDir, MetadataDir, HtmlDir string

func Init() {
	IssuesDir = filepath.Join(config.ViperEnv.OutputDir, "issues")
	StatsDir = filepath.Join(config.ViperEnv.OutputDir, "stats")
	MetadataDir = filepath.Join(config.ViperEnv.OutputDir, "metadata")
	HtmlDir = filepath.Join(config.ViperEnv.OutputDir, "html")

	CreateDir(config.ViperEnv.OutputDir)
	CreateDir(IssuesDir)
	CreateDir(StatsDir)
	CreateDir(MetadataDir)
	CreateDir(HtmlDir)
	if err := copy.Copy("./pkg/output/html/static", HtmlDir); err != nil {
		log.Logger.Error(err)
	}
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
