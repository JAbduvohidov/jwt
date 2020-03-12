package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	jsonTag = "json"
	expTag = "exp"
)

func Encode(payload interface{}, secret string) (token string, err error) {
	type Header = struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	jHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	eHeader := base64.RawURLEncoding.EncodeToString(jHeader)
	jPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(jPayload)
	signatureValue := eHeader + "." + encodedPayload
	return signatureValue + "." + hash(signatureValue, secret), nil
}

func Decode(token string, payload interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token: token should contain header, payload and secret")
	}

	decodedPayload, PayloadErr := base64.RawURLEncoding.DecodeString(parts[1])
	if PayloadErr != nil {
		return fmt.Errorf("invalid payload: %s", PayloadErr.Error())
	}

	ParseErr := json.Unmarshal(decodedPayload, &payload)
	if ParseErr != nil {
		return fmt.Errorf("invalid payload: %s", ParseErr.Error())
	}

	return nil
}

func Verify(payload interface{}, token, secret string) error {
	reflectType := reflect.TypeOf(payload)
	reflectValue := reflect.ValueOf(payload)
	if reflectType.Kind() == reflect.Ptr {
		reflectType = reflectType.Elem()
		reflectValue = reflectValue.Elem()
	}

	if reflectType.Kind() != reflect.Struct {
		panic(errors.New("give me struct or pointer to it"))
	}

	fieldCount := reflectType.NumField()
	for i := 0; i < fieldCount; i++ {
		field := reflectType.Field(i)
		tag, ok := field.Tag.Lookup(jsonTag)
		if !ok {
			continue
		}
		if tag == expTag {
			value := reflectValue.Field(i)
			if value.Kind() != reflect.Int64 {
				panic(errors.New("exp should be int64"))
			}
			exp := value.Interface().(int64)

			if exp != 0 && time.Now().Unix() > exp {
				return errors.New("expired")
			}

			parts := strings.Split(token, ".")
			signatureValue := parts[0] + "." + parts[1]


			if validMAC(token, signatureValue, secret) == false {
				return errors.New("invalid token")
			}
		}
	}
	return nil
}

func validMAC(jwt, signatureValue, key string) bool {

	signatureValue = signatureValue + "." + hash(signatureValue, key)

	return hmac.Equal([]byte(jwt), []byte(signatureValue))
}

func hash(src string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}