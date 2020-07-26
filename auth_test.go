package auth

import (
	"net/http"
	"testing"
)

type UserID int64

func (id UserID) AuthInfo() *Info {
	return &Info{
		Type: "testType",
		ID:   int64(id),
	}
}

func TestAuthorization(t *testing.T) {
	userID := UserID(1)
	token, _, err := GenerateToken(userID.AuthInfo(), JWTExpires, "testSecret")
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

	r2 := RequestWithInfo(r1, userID.AuthInfo())
	id, err := IDFrom(r2, "testType")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatal(id)
	}
}
