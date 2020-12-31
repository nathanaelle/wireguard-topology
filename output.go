package topology // import "github.com/nathanaelle/wireguard-topology"

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type (
	Output interface {
		AddFolder(name ...string) error
		AddEntry(name ...string) (io.WriteCloser, error)
	}

	tgzOutput struct {
	}
	tgzEntry struct {
	}

	dirOutput struct {
		rootDir string
	}
)

var _ Output = &dirOutput{}

func NewDirOutput(rootDir string) Output {
	return &dirOutput{
		rootDir: rootDir,
	}
}

func (do *dirOutput) AddFolder(name ...string) error {
	destDir := filepath.Join(do.rootDir, filepath.Join(name...))
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return fmt.Errorf("cant create %q : %v", destDir, err)
	}
	return nil
}

func (do *dirOutput) AddEntry(name ...string) (io.WriteCloser, error) {
	filename := filepath.Join(do.rootDir, filepath.Join(name...))
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("can't create file %q : %v", filename, err)
	}
	return file, nil
}

//func NewTgzOutput(file string) Output {
//	return &tgzOutput{}
//}
