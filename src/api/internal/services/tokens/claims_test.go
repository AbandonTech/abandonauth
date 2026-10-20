package tokens

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestClaimsExposeRegisteredValues(t *testing.T) {
	expiresAt := int64(1788004800)
	issuedAt := int64(1788001200)
	notBefore := int64(1788001140)

	body := claims{
		Subject:   "placeholder-subject",
		Issuer:    "https://issuer.example.test",
		Audience:  "placeholder-audience",
		IssuedAt:  &issuedAt,
		NotBefore: &notBefore,
		ExpiresAt: &expiresAt,
	}

	dates := []struct {
		name string
		get  func() (*jwt.NumericDate, error)
		want int64
	}{
		{"exp", body.GetExpirationTime, expiresAt},
		{"iat", body.GetIssuedAt, issuedAt},
		{"nbf", body.GetNotBefore, notBefore},
	}

	for _, date := range dates {
		t.Run(date.name, func(t *testing.T) {
			got, err := date.get()
			if err != nil {
				t.Fatalf("reading %s: %v", date.name, err)
			}
			if got == nil {
				t.Fatalf("%s is absent, want %d", date.name, date.want)
			}
			if got.Unix() != date.want {
				t.Errorf("%s is %d, want %d", date.name, got.Unix(), date.want)
			}
			if got.Location() != time.UTC {
				t.Errorf("%s is in %v, want UTC", date.name, got.Location())
			}
		})
	}

	gotIssuer, err := body.GetIssuer()
	if err != nil {
		t.Fatalf("reading the issuer: %v", err)
	}
	if gotIssuer != body.Issuer {
		t.Errorf("the issuer is %q, want %q", gotIssuer, body.Issuer)
	}

	gotSubject, err := body.GetSubject()
	if err != nil {
		t.Fatalf("reading the subject: %v", err)
	}
	if gotSubject != body.Subject {
		t.Errorf("the subject is %q, want %q", gotSubject, body.Subject)
	}

	gotAudience, err := body.GetAudience()
	if err != nil {
		t.Fatalf("reading the audience: %v", err)
	}
	if len(gotAudience) != 1 || gotAudience[0] != body.Audience {
		t.Errorf("the audience is %q, want exactly [%q]", gotAudience, body.Audience)
	}
}

func TestClaimsKeepMissingRegisteredValuesAbsent(t *testing.T) {
	var body claims

	dates := []struct {
		name string
		get  func() (*jwt.NumericDate, error)
	}{
		{"exp", body.GetExpirationTime},
		{"iat", body.GetIssuedAt},
		{"nbf", body.GetNotBefore},
	}

	for _, date := range dates {
		t.Run(date.name, func(t *testing.T) {
			got, err := date.get()
			if err != nil {
				t.Fatalf("reading %s: %v", date.name, err)
			}
			if got != nil {
				t.Errorf("%s is %v, want absent", date.name, got)
			}
		})
	}

	gotIssuer, err := body.GetIssuer()
	if err != nil {
		t.Fatalf("reading the issuer: %v", err)
	}
	if gotIssuer != "" {
		t.Errorf("the issuer is %q, want empty", gotIssuer)
	}

	gotSubject, err := body.GetSubject()
	if err != nil {
		t.Fatalf("reading the subject: %v", err)
	}
	if gotSubject != "" {
		t.Errorf("the subject is %q, want empty", gotSubject)
	}

	gotAudience, err := body.GetAudience()
	if err != nil {
		t.Fatalf("reading the audience: %v", err)
	}
	if gotAudience != nil {
		t.Errorf("the audience is %q, want absent", gotAudience)
	}
}
