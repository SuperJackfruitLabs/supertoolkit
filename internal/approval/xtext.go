package approval

import (
	"html"
	"regexp"
	"strings"
)

var (
	xWebScheme = regexp.MustCompile(`https?://`)
	xMediaURL  = regexp.MustCompile(`/status/([^/]+)/((photo)|(video))/[0-9]+(?:$|[?#])`)
)

type xURLEntity struct {
	URL         string `json:"url"`
	ExpandedURL string `json:"expanded_url"`
	MediaKey    string `json:"media_key"`
}

type xEntities struct {
	URLs []xURLEntity `json:"urls"`
}

type xNoteTweet struct {
	Text     string    `json:"text"`
	Entities xEntities `json:"entities"`
}

func normalizeXText(text string, entities []xURLEntity, postID string) string {
	normalized := html.UnescapeString(text)
	for _, entity := range entities {
		if entity.URL == "" {
			continue
		}
		mediaMatch := xMediaURL.FindStringSubmatch(entity.ExpandedURL)
		if entity.MediaKey != "" || (len(mediaMatch) > 1 && mediaMatch[1] == postID) {
			normalized = strings.ReplaceAll(normalized, " "+entity.URL, "")
			normalized = strings.ReplaceAll(normalized, entity.URL+" ", "")
			normalized = strings.ReplaceAll(normalized, entity.URL, "")
			continue
		}
		if entity.ExpandedURL != "" {
			normalized = strings.ReplaceAll(normalized, entity.URL, entity.ExpandedURL)
		}
	}
	return strings.TrimSpace(xWebScheme.ReplaceAllString(normalized, ""))
}

func normalizeApprovedXText(text string) string {
	return strings.TrimSpace(xWebScheme.ReplaceAllString(text, ""))
}

func normalizeXPost(text string, entities xEntities, note xNoteTweet, postID string) string {
	if note.Text != "" {
		return normalizeXText(note.Text, note.Entities.URLs, postID)
	}
	return normalizeXText(text, entities.URLs, postID)
}
