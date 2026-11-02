package local

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/zorgzerg/traefik-s3-proxy-plugin/log"
)

type Local struct {
	directory string
}

func New(directory string) *Local {
	return &Local{
		directory: directory,
	}
}

func (local *Local) Get(_ context.Context, name, _ string, rw http.ResponseWriter) ([]byte, error) {
	filePath := fmt.Sprintf("%s/%s", local.directory, name)
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Error(err.Error())
		http.Error(rw, "unable to read object", http.StatusInternalServerError)
		return nil, err
	}
	log.Debug(fmt.Sprintf("%q read", filePath))
	return content, nil
}
