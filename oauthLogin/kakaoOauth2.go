package oauthLogin

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gyarang/golang-oauth/model"
	"golang.org/x/oauth2"
)

type kakaoMemberResponse struct {
	ID           json.Number  `json:"id"`
	KakaoAccount kakaoAccount `json:"kakao_account"`
}

type kakaoProfile struct {
	Nickname          string `json:"nickname"`
	ThumbnailImageURL string `json:"thumbnail_image_url"`
	ProfileImageURL   string `json:"profile_image_url"`
	IsDefaultImage    bool   `json:"is_default_image"`
}

type kakaoAccount struct {
	ProfileNeedsAgreement  bool         `json:"profile_needs_agreement"`
	Profile                kakaoProfile `json:"profile"`
	NameNeedsAgreement     bool         `json:"name_needs_agreement"`
	Name                   string       `json:"name"`
	EmailNeedsAgreement    bool         `json:"email_needs_agreement"`
	IsEmailValid           bool         `json:"is_email_valid"`
	IsEmailVerified        bool         `json:"is_email_verified"`
	Email                  string       `json:"email"`
	AgeRangeNeedsAgreement bool         `json:"age_range_needs_agreement"`
	AgeRange               string       `json:"age_range"`
	BirthdayNeedsAgreement bool         `json:"birthday_needs_agreement"`
	Birthday               string       `json:"birthday"`
	GenderNeedsAgreement   bool         `json:"gender_needs_agreement"`
	Gender                 string       `json:"gender"`
}

type kakaoOauth struct {
	clientId     string
	clientSecret string
	redirectUrl  string
	config       oauth2.Config
}

func newKakaoOauth(clientId string, clientSecret string, redirectUrl string) *kakaoOauth {
	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://kauth.kakao.com/oauth/authorize",
			TokenURL: "https://kauth.kakao.com/oauth/token",
		},
		RedirectURL: redirectUrl,
	}

	o := &kakaoOauth{clientId: clientId, clientSecret: clientSecret, redirectUrl: redirectUrl, config: *config}
	return o
}

func (auth *kakaoOauth) GetLoginUrl(state string) string {
	return auth.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (auth *kakaoOauth) getToken(ctx context.Context, code string) (string, error) {
	token, err := auth.config.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func (auth *kakaoOauth) getMemberData(token string) (model.User, error) {
	apiUrl := "https://kapi.kakao.com/v2/user/me"

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return model.User{}, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return model.User{}, err
	}
	defer res.Body.Close()

	bytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return model.User{}, err
	}

	var memberInfo kakaoMemberResponse
	if err := json.Unmarshal(bytes, &memberInfo); err != nil {
		return model.User{}, err
	}

	user := model.User{
		SnsId: string(memberInfo.ID),
		Name:  memberInfo.KakaoAccount.Name,
		Email: memberInfo.KakaoAccount.Email,
	}

	return user, nil
}

func (auth *kakaoOauth) GetMemberDataWithCode(ctx context.Context, code string) (model.User, error) {
	token, err := auth.getToken(ctx, code)
	if err != nil {
		return model.User{}, err
	}

	member, err := auth.getMemberData(token)
	if err != nil {
		return model.User{}, err
	}

	return member, nil
}
