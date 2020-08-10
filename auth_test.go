package auth

import (
	"net/http"
	"testing"
)

type UserID uint64

func (id UserID) Info() *Info {
	return &Info{
		Subject: &Subject{
			UserType: "testType",
			UserID:   uint64(id),
		},
	}
}

func TestAuthorization(t *testing.T) {
	userID := UserID(1)
	info := userID.Info()
	token, _, err := GenerateToken(info.Subject, JWTExpires, "testSecret")
	if err != nil {
		t.Fatal(err)
	}

	r1, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r1.Header.Add("Authorization", "Bearer "+token)

	token = TokenFrom(r1)
	_, _, err = ParseToken(token, "testSecret")
	if err != nil {
		t.Fatal(err)
	}

	r2 := WithSubject(r1, info.Subject)
	id, err := UserIDFrom(r2, "testType")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatal(id)
	}
}
