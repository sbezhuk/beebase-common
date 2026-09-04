// Package medialink builds the public URL a client uses to fetch or
// display a media item's content, so apiary-service, hive-service, and
// media-service share one definition of that URL shape instead of each
// reimplementing it.
package medialink

import (
	"strings"

	"github.com/google/uuid"
)

// DownloadURL returns the public, authenticated URL for mediaID's
// content: baseURL + media-service's stable download route
// ("/api/v1/media/{id}/download", reverse-proxied by the gateway).
// baseURL must be the gateway's externally reachable base URL (e.g.
// "https://api.beebase.app"), not an internal service-to-service
// address - the URL is handed to clients, not called server-side.
func DownloadURL(baseURL string, mediaID uuid.UUID) string {
	return strings.TrimRight(baseURL, "/") + "/api/v1/media/" + mediaID.String() + "/download"
}
