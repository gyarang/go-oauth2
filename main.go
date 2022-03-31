package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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

func RandString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("session", store))

	r.LoadHTMLGlob("*.html")
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{})
	})

	r.GET("/success", func(c *gin.Context) {
		c.HTML(http.StatusOK, "success.html", gin.H{})
	})

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
		state, err := RandString(32)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"message": err.Error(),
			})
		}

		session := sessions.Default(c)
		session.Set("oauth2-state", state)
		session.Save()

		url := conf.AuthCodeURL(state)
		c.Redirect(http.StatusFound, url)
	})

	r.GET("/oauth/kakao/callback", func(c *gin.Context) {
		session := sessions.Default(c)
		state := c.Query("state")
		if session.Get("oauth2-state") != state {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "state code error",
			})
		}
		session.Clear()
		session.Save()

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
		c.SetCookie("token", "tokenLikeString", 3000, "/", "localhost:8080", true, false)
		c.Redirect(http.StatusFound, "/success")
	})

	r.Run()
}
