package main

import (
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	payload := struct{
		Id int64 `json:"id"`
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}{
		Id:  1,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(time.Hour * 10).Unix(),
	}

	var secret Secret = []byte("secret")

	token, err := Encode(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
	decode := struct{
		Id int64 `json:"id"`
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}{}
	err = Decode(token, &decode)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Verify(token, secret)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("not ok found")
	}

	ok, err = IsNotExpired(payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("not ok found")
	}
}