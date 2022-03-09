package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gyarang/golang-oauth/oauthLogin"
	"github.com/joho/godotenv"
)

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

	r.GET("/oauth/:ch", func(c *gin.Context) {
		lc, err := oauthLogin.GetLoginChannel(c.Params.ByName("ch"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"err": err.Error()})
		}
		url := lc.GetLoginUrl(state)
		c.Redirect(http.StatusFound, url)
	})

	r.GET("/oauth/:ch/callback", func(c *gin.Context) {
		s := c.Query("state")
		if s != state {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "state code error",
			})
		}

		code := c.Query("code")

		lc, err := oauthLogin.GetLoginChannel(c.Params.ByName("ch"))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"err": err.Error()})
		}

		member, err := lc.GetMemberDataWithCode(c, code)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"err": err.Error(),
			})
		}

		// do stuff with memberInfo and get token
		fmt.Println(member)
		c.SetCookie("token", "tokenLikeString", 3000, "/", "localhost:8080", true, false)
		c.Redirect(http.StatusFound, "/success")
	})

	r.Run()
}
