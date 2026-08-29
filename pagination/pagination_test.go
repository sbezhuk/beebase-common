package pagination_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbezhuk/beebase-common/pagination"
)

func TestParseParams_Defaults(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/things", nil)

	p, fields := pagination.ParseParams(r)
	if len(fields) != 0 {
		t.Fatalf("fields = %v, want empty", fields)
	}
	if p.Page != pagination.DefaultPage {
		t.Errorf("Page = %d, want %d", p.Page, pagination.DefaultPage)
	}
	if p.Limit != pagination.DefaultLimit {
		t.Errorf("Limit = %d, want %d", p.Limit, pagination.DefaultLimit)
	}
}

func TestParseParams_ValidValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/things?page=3&limit=50", nil)

	p, fields := pagination.ParseParams(r)
	if len(fields) != 0 {
		t.Fatalf("fields = %v, want empty", fields)
	}
	if p.Page != 3 || p.Limit != 50 {
		t.Errorf("Params = %+v, want Page=3 Limit=50", p)
	}
}

func TestParseParams_MaxLimitIsAllowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/things?limit=100", nil)

	p, fields := pagination.ParseParams(r)
	if len(fields) != 0 {
		t.Fatalf("fields = %v, want empty", fields)
	}
	if p.Limit != 100 {
		t.Errorf("Limit = %d, want 100", p.Limit)
	}
}

func TestParseParams_InvalidPage(t *testing.T) {
	cases := []string{"0", "-1", "abc", "1.5"}
	for _, raw := range cases {
		r := httptest.NewRequest(http.MethodGet, "/things?page="+raw, nil)
		_, fields := pagination.ParseParams(r)
		if fields["page"] != pagination.CodeInvalidPage {
			t.Errorf("page=%q: fields[page] = %q, want %q", raw, fields["page"], pagination.CodeInvalidPage)
		}
	}
}

func TestParseParams_InvalidLimit(t *testing.T) {
	cases := []string{"0", "-1", "abc", "101"}
	for _, raw := range cases {
		r := httptest.NewRequest(http.MethodGet, "/things?limit="+raw, nil)
		_, fields := pagination.ParseParams(r)
		if fields["limit"] != pagination.CodeInvalidLimit {
			t.Errorf("limit=%q: fields[limit] = %q, want %q", raw, fields["limit"], pagination.CodeInvalidLimit)
		}
	}
}

func TestParams_Offset(t *testing.T) {
	cases := []struct {
		page, limit, want int
	}{
		{1, 20, 0},
		{2, 20, 20},
		{3, 10, 20},
	}
	for _, tc := range cases {
		p := pagination.Params{Page: tc.page, Limit: tc.limit}
		if got := p.Offset(); got != tc.want {
			t.Errorf("Params{%d,%d}.Offset() = %d, want %d", tc.page, tc.limit, got, tc.want)
		}
	}
}

func TestNewMeta(t *testing.T) {
	cases := []struct {
		name      string
		params    pagination.Params
		total     int
		wantPages int
		wantNext  bool
		wantPrev  bool
	}{
		{"first page, more after", pagination.Params{Page: 1, Limit: 20}, 125, 7, true, false},
		{"middle page", pagination.Params{Page: 4, Limit: 20}, 125, 7, true, true},
		{"last page", pagination.Params{Page: 7, Limit: 20}, 125, 7, false, true},
		{"empty result", pagination.Params{Page: 1, Limit: 20}, 0, 0, false, false},
		{"page beyond available data", pagination.Params{Page: 9, Limit: 20}, 125, 7, false, true},
		{"exact multiple", pagination.Params{Page: 1, Limit: 25}, 125, 5, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := pagination.NewMeta(tc.params, tc.total)
			if m.Total != tc.total {
				t.Errorf("Total = %d, want %d", m.Total, tc.total)
			}
			if m.TotalPages != tc.wantPages {
				t.Errorf("TotalPages = %d, want %d", m.TotalPages, tc.wantPages)
			}
			if m.HasNext != tc.wantNext {
				t.Errorf("HasNext = %v, want %v", m.HasNext, tc.wantNext)
			}
			if m.HasPrevious != tc.wantPrev {
				t.Errorf("HasPrevious = %v, want %v", m.HasPrevious, tc.wantPrev)
			}
		})
	}
}

func TestNewResponse(t *testing.T) {
	items := []string{"a", "b"}
	p := pagination.Params{Page: 1, Limit: 20}

	resp := pagination.NewResponse(items, p, 2)
	if len(resp.Items) != 2 {
		t.Fatalf("Items = %v, want length 2", resp.Items)
	}
	if resp.Pagination.Total != 2 {
		t.Errorf("Pagination.Total = %d, want 2", resp.Pagination.Total)
	}
}
