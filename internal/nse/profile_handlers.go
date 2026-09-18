package nse

import (
	"net/http"
	"regexp"
	"time"
)

var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// handleProfileExport builds a cnMaestro-compatible NSE Group profile
// snapshot from the live device and returns it as a downloadable JSON
// file — the same schema as cnMaestro's own "Export" button, so profiles
// built here are interchangeable with cnMaestro's profile library. This
// is read-only: nothing here ever touches the device.
func (s *Server) handleProfileExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cloud, err := FetchCloudConfig(s.Client, 20*time.Second)
	if err != nil {
		writeSettingsError(w, http.StatusBadGateway, err.Error())
		return
	}
	cfgRaw, ok := s.cli(w, "show config", 25*time.Second)
	if !ok {
		return
	}
	// cloud-json-config carries feature_license inline; the `show config`
	// fallback can't, so fill it from its own command rather than exporting
	// a profile that silently claims every licensed feature is off.
	if cloud.FeatureLicense == nil {
		if lic, err := s.currentLicense(); err == nil {
			cloud.FeatureLicense = lic.AsMap()
		}
	}

	lan := ParseLANConfig(cfgRaw)
	groups := ParseGroupsConfig(cfgRaw)
	profile := BuildGroupProfile(cloud, groups, lan, cfgRaw)

	filename := unsafeFilenameChars.ReplaceAllString(cloud.SystemName, "_")
	if filename == "" {
		filename = "NSE_Group"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`-export.json"`)
	writeJSON(w, profile)
}
