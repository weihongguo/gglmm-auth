package auth

import (
	"net/http"
	"testing"
)

type AuthTest uint64

func (id AuthTest) Info() *Info {
	return &Info{
		Subject: &Subject{
			UserType: "testType",
			UserID:   uint64(id),
		},
	}
}

func TestAuthorization(t *testing.T) {
	authTest := AuthTest(1)
	info := authTest.Info()
	token, _, err := generateToken(info.Subject, JWTExpires, "testSecret")
	if err != nil {
		t.Fatal(err)
	}

	r1, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r1.Header.Add("Authorization", "Bearer "+token)

	token = authorizationToken(r1)
	_, _, err = parseToken(token, "testSecret")
	if err != nil {
		t.Fatal(err)
	}

	r2 := withSubject(r1, info.Subject)
	id, err := UserID(r2, "testType")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatal(id)
	}
}
