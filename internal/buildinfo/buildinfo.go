// Package buildinfo reports which connector build is running.
package buildinfo

import "runtime/debug"

// version is set at build time:
//
//	-ldflags "-X github.com/InteractionLabs/traversal-connector/internal/buildinfo.version=v1.2.3"
var version string

// Version is the connector's release version, such as "v0.9.0". Builds
// without a stamped version report the VCS revision, or "dev".
func Version() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return "dev-" + s.Value[:min(12, len(s.Value))]
			}
		}
	}
	return "dev"
}
