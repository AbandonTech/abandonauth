package adoption

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/abandontech/abandonauth/src/api/internal/database"
)

//go:embed schemafingerprint.sql
var fingerprintQuery string

//go:embed schemafingerprint.txt
var expectedFingerprint string

// FingerprintDifference is one line that the database and the expected shape do
// not agree on.
type FingerprintDifference struct {
	// Line is the description of a table, column, constraint, index or sequence.
	// It describes the shape of the schema and holds no row data.
	Line string
	// InDatabase reports whether the line was found in the database and missing
	// from the expected shape, rather than the other way round.
	InDatabase bool
}

func (d FingerprintDifference) String() string {
	if d.InDatabase {
		return "unexpected: " + d.Line
	}

	return "missing: " + d.Line
}

// ReadSchemaFingerprint describes the account schema as a sorted list of lines.
func ReadSchemaFingerprint(ctx context.Context, conn database.Conn) ([]string, error) {
	rows, err := conn.QueryContext(ctx, fingerprintQuery)
	if err != nil {
		return nil, fmt.Errorf("describing the schema: %w", err)
	}
	defer rows.Close()

	var lines []string

	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("describing the schema: %w", err)
		}

		lines = append(lines, line)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("describing the schema: %w", err)
	}

	return lines, nil
}

// ExpectedSchemaFingerprint is the shape the account schema must have before the
// service will take ownership of it, and the shape the baseline migration
// produces on a new database.
func ExpectedSchemaFingerprint() []string {
	var lines []string

	for _, line := range strings.Split(expectedFingerprint, "\n") {
		line = strings.TrimRight(line, "\r")

		// The file documents itself. Its commentary is not part of the shape.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lines = append(lines, line)
	}

	return lines
}

// CompareSchemaFingerprint reports every way the given shape differs from the
// expected one.
func CompareSchemaFingerprint(actual []string) []FingerprintDifference {
	expected := ExpectedSchemaFingerprint()

	inExpected := make(map[string]int, len(expected))
	for _, line := range expected {
		inExpected[strings.TrimRight(line, "\r")]++
	}

	inActual := make(map[string]int, len(actual))
	for _, line := range actual {
		inActual[strings.TrimRight(line, "\r")]++
	}

	var differences []FingerprintDifference

	for _, line := range expected {
		line = strings.TrimRight(line, "\r")
		if inActual[line] < inExpected[line] {
			differences = append(differences, FingerprintDifference{Line: line})
			inActual[line] = inExpected[line]
		}
	}

	for _, line := range actual {
		line = strings.TrimRight(line, "\r")
		if inExpected[line] < inActual[line] {
			differences = append(differences, FingerprintDifference{Line: line, InDatabase: true})
			inExpected[line] = inActual[line]
		}
	}

	return differences
}
