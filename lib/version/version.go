// Package version is used to record the version information of the current nps
package version

// VERSION is the version of the current nps
const VERSION = "0.26.44"

// LINK is the link of the current nps github
const LINK = "https://github.com/ehang-io/nps"

// BUILD_TIME is the time when the current nps binary is built
var BUILD_TIME string

// GO_VERSION is the go version used to compile the current nps binary
var GO_VERSION string

// GIT_HASH is the git hash when the current nps binary is built
var GIT_HASH string

// ALL_CONFIG is all config of the current nps binary
var ALL_CONFIG string

// Compulsory minimum version, Minimum downward compatibility to this version
func GetVersion() string {
	return "0.26.0"
}