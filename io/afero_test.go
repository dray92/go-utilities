package io

import (
	"bytes"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestGetContents(t *testing.T) {
	tests := []struct {
		description          string
		filename             string
		createFile           func(t *testing.T, fs afero.Fs, filename string)
		assertOnExpectations func(t *testing.T, contents []byte, err error)
	}{
		{
			description: "file exists, read is successful",
			filename:    "foo/bar/baz.txt",
			createFile: func(t *testing.T, fs afero.Fs, filename string) {
				err := afero.WriteFile(fs, filename, []byte("words"), 0644)
				require.NoError(t, err)
			},
			assertOnExpectations: func(t *testing.T, contents []byte, err error) {
				require.NoError(t, err)
				require.True(t, bytes.Equal([]byte("words"), contents))
			},
		},
		{
			description: "file doesn't exist",
			filename:    "foo/bar/baz.txt",
			createFile: func(t *testing.T, fs afero.Fs, filename string) {
			},
			assertOnExpectations: func(t *testing.T, contents []byte, err error) {
				require.Error(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			test.createFile(t, fs, test.filename)

			contents, err := GetContents(fs, test.filename)
			test.assertOnExpectations(t, contents, err)
		})
	}
}
