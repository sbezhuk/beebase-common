// Package pagination holds the page/limit parameters, response envelope,
// and metadata shared by every collection endpoint across the BeeBase
// services, so each service implements page/limit parsing, bounds
// checking, and response shape exactly once.
package pagination

import (
	"math"
	"net/http"
	"strconv"
)

// Defaults and bounds applied when a client omits page/limit, or when
// ParseParams rejects a value outside these bounds.
const (
	DefaultPage  = 1
	DefaultLimit = 20
	MaxLimit     = 100
)

// Field validation error codes, shaped to feed directly into
// httpx.WriteValidationError's fields map.
const (
	CodeInvalidPage  = "invalid_page"
	CodeInvalidLimit = "invalid_limit"
)

// Params is a page/limit pagination request, already validated and
// defaulted by ParseParams.
type Params struct {
	Page  int
	Limit int
}

// Offset is the number of rows to skip to reach Page, given Limit rows per
// page.
func (p Params) Offset() int {
	return (p.Page - 1) * p.Limit
}

// ParseParams reads "page" and "limit" from r's query string. A missing
// value falls back to DefaultPage/DefaultLimit. A present value that isn't
// a positive integer, or a limit above MaxLimit, is reported in the
// returned fields map (keyed "page"/"limit") instead of being silently
// clamped — the caller should treat a non-empty map as a 400.
func ParseParams(r *http.Request) (Params, map[string]string) {
	fields := map[string]string{}

	page := DefaultPage
	if raw := r.URL.Query().Get("page"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			fields["page"] = CodeInvalidPage
		} else {
			page = v
		}
	}

	limit := DefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 || v > MaxLimit {
			fields["limit"] = CodeInvalidLimit
		} else {
			limit = v
		}
	}

	if len(fields) > 0 {
		return Params{}, fields
	}

	return Params{Page: page, Limit: limit}, nil
}

// Meta is the pagination metadata returned alongside a page of items.
type Meta struct {
	Page        int  `json:"page"`
	Limit       int  `json:"limit"`
	Total       int  `json:"total"`
	TotalPages  int  `json:"totalPages"`
	HasNext     bool `json:"hasNext"`
	HasPrevious bool `json:"hasPrevious"`
}

// NewMeta builds the metadata for a page of total total rows requested
// with p.
func NewMeta(p Params, total int) Meta {
	totalPages := 0
	if total > 0 {
		totalPages = int(math.Ceil(float64(total) / float64(p.Limit)))
	}

	return Meta{
		Page:        p.Page,
		Limit:       p.Limit,
		Total:       total,
		TotalPages:  totalPages,
		HasNext:     p.Page < totalPages,
		HasPrevious: p.Page > 1,
	}
}

// Response is the standard envelope every paginated collection endpoint
// returns: the requested page of items alongside its metadata.
type Response[T any] struct {
	Items      []T  `json:"items"`
	Pagination Meta `json:"pagination"`
}

// NewResponse builds a Response for items, the page requested by p, out of
// total matching rows.
func NewResponse[T any](items []T, p Params, total int) Response[T] {
	return Response[T]{Items: items, Pagination: NewMeta(p, total)}
}
