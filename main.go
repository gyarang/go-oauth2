package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type KakaoMemberResponse struct {
	ID           int          `json:"id"`
	KakaoAccount KakaoAccount `json:"kakao_account"`
}

type KakaoProfile struct {
	Nickname          string `json:"nickname"`
	ThumbnailImageURL string `json:"thumbnail_image_url"`
	ProfileImageURL   string `json:"profile_image_url"`
	IsDefaultImage    bool   `json:"is_default_image"`
}

type KakaoAccount struct {
	ProfileNeedsAgreement  bool         `json:"profile_needs_agreement"`
	Profile                KakaoProfile `json:"profile"`
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

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := gin.Default()

	r.LoadHTMLGlob("*.html")
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	r.GET("/success", func(c *gin.Context) {
		c.HTML(http.StatusOK, "success.html", gin.H{})
	})

	state := "state-code"
	conf := &oauth2.Config{
		ClientID:     os.Getenv("KAKAO_CLIENT_ID"),
		ClientSecret: os.Getenv("KAKAO_CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://kauth.kakao.com/oauth/authorize",
			TokenURL: "https://kauth.kakao.com/oauth/token",
		},
		RedirectURL: "http://localhost:8080/oauth/kakao/callback",
	}

	r.GET("/oauth/kakao", func(c *gin.Context) {
		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
		c.Redirect(http.StatusFound, url)
	})

	r.GET("/oauth/kakao/callback", func(c *gin.Context) {
		s := c.Query("state")
		if s != state {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "state code error",
			})
		}

		// 코드를 통해 인증 서버에서 토큰 획득
		code := c.Query("code")
		token, err := conf.Exchange(c, code)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}

		// 토큰을 통해 리소스 서버에서 사용자 정보 획득
		req, err := http.NewRequest("GET", "https://kapi.kakao.com/v2/user/me", nil)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}

		req.Header.Add("Authorization", "Bearer "+token.AccessToken)

		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}
		defer res.Body.Close()

		bytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}

		var memberInfo KakaoMemberResponse
		if err := json.Unmarshal(bytes, &memberInfo); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}

		// do stuff with memberInfo and get token
		fmt.Println(memberInfo)
		c.SetCookie("token", "new jwt token", 0, "/", "localhost:8080", true, true)
		c.Redirect(http.StatusFound, "/success")
	})

	r.Run()
}
