package io

import (
	"io/ioutil"
	"log"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
)

// GetContents returns the contents of a filepath, by reading it from the provided filesystem.
func GetContents(fs afero.Fs, filename string) ([]byte, error) {
	handle, err := fs.Open(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain a file handle")
	}

	defer func() {
		err := handle.Close()
		if err != nil {
			log.Println("failed to close file handle")
		}
	}()

	contents, err := ioutil.ReadAll(handle)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file contents")
	}

	return contents, nil
}
