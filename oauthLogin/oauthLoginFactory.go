package oauthLogin

import (
	"errors"
	"os"
)

func GetLoginChannel(loginChannel string) (oauthLogin, error) {
	if loginChannel == "kakao" {
		ol := newKakaoOauth(os.Getenv("KAKAO_CLIENT_ID"), os.Getenv("KAKAO_CLIENT_SECRET"), "http://localhost:8080/oauth/kakao/callback")
		return ol, nil
	} else {
		return nil, errors.New("not available login channel")
	}

}
