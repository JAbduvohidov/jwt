package main

import (
	"strings"
	"testing"
	"time"
)

type Payload struct {
	Id  int64 `json:"id"`
	Iat int64 `json:"iat"`
	Exp int64 `json:"exp"`
}

var payload = Payload {
	Id:  1,
	Iat: time.Now().Unix(),
	Exp: time.Now().Add(time.Hour * 10).Unix(),
}

var decode = Payload {}

var secret = Secret("secret")

func TestVerifyEncodeAndDecodeOK(t *testing.T) {
	token, err := Encode(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
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

func TestDecode_Err_BadTokenHeader(t *testing.T) {
	if Decode("some.crazy.token", &decode) == nil {
		t.Fatal("error mustn't be nil, while decoding bad token header")
	}
}

func TestDecode_Err_BadTokenPayload(t *testing.T) {
	if Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.crazy.token", &decode) == nil {
		t.Fatal("error mustn't be nil, while decoding bad token header")
	}
}

func TestEncodeDecode_Err_PartsToken(t *testing.T) {
	token, err := Encode(payload, secret)
	if err != nil {
		t.Fatalf("must be nil, while encode: %v", err)
	}

	testTokens := strings.Split(token, ".")
	token = testTokens[0] + testTokens[2]

	if Decode(token, &decode) == nil {
		t.Fatalf("must be err: %v", err)
	}
}

func TestDecode_Err_BadTokenPayloadNoStruct(t *testing.T) {
	token, err := Encode(payload, secret)
	if err != nil {
		t.Fatalf("must be nil, while encode: %v", err)
	}

	if Decode(token, "payload") == nil {
		t.Fatal("must be err, while decode bad token header no struct")
	}
}