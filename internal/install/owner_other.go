//go:build !unix

package install

import "errors"

func ownerOf(string) (string, string, error) {
	return "", "", errors.New("ownership is not readable on this platform")
}
