//go:build !unix

package doctor

import "errors"

func uidOpener(exe string) func(int, []string) ([]string, error) {
	return func(int, []string) ([]string, error) { return nil, errors.New("unsupported platform") }
}
