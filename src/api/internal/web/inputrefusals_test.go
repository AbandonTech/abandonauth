package web

import (
	"fmt"
	"strings"

	inputs "github.com/abandontech/abandonauth/src/api/internal/web/request"
)

// refusals summarises what an endpoint refused as "where why", which is what a
// client is told. It never carries the value that was refused, so a failing
// test cannot print a credential a request was rejected for.
func refusals(given *inputs.Inputs) []string {
	summaries := make([]string, 0, len(given.Failures()))

	for _, failure := range given.Failures() {
		located := make([]string, 0, len(failure.Location))
		for _, part := range failure.Location {
			located = append(located, fmt.Sprintf("%v", part))
		}

		summaries = append(summaries, strings.Join(located, ".")+" "+failure.Type)
	}

	return summaries
}
