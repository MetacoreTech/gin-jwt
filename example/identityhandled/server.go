package main

import (
	"log"
	"net/http"
	"os"
	"time"
	"fmt"

	"github.com/gabbottron/gin-jwt"
	"github.com/gin-gonic/gin"
)

// This is the identifier for the user in claims/context
var USER_ID_KEY 	= "id"
var USER_TYPE_KEY 	= "usertype"

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func helloHandler(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	c.JSON(200, gin.H{
		"userID": claims["id"],
		"text":   "Hello World.",
	})
}

// User demo
type User struct {
	UserID  	uint64
	UserType 	string
}

type NotUser struct {
	UserName int
	Hat		string
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8000"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: USER_ID_KEY,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					USER_ID_KEY: 	v.UserID,
					USER_TYPE_KEY: 	v.UserType,
				}
			}
			return jwt.MapClaims{}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			if err := c.ShouldBind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password

			if (userID == "admin" && password == "admin") || (userID == "test" && password == "test") {
				return &User{
					UserID:  1,
					UserType:  "coolkid",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			fmt.Println("In Authorizator")
			if v, ok := data.(*User); ok {
				// Do your identity lookups here or at least check that
				// the user type is correct for the requested resource!
				fmt.Println(v.UserID)
				return true
			}

			return false
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			fmt.Println("In IdentityHandler")
			claims := jwt.ExtractClaims(c)
			log.Printf("IdentityHandler claims: %#v\n", claims)
			
			return &User{
				// TODO: Trying to interpret numbers as integers fails 
				//       because all numbers are encoded as float64 in JSON
				//       I have a few options:
				// https://github.com/dgrijalva/jwt-go/issues/224
				// This should be fine because no decimal precision will be taking
				// up space when it's encoded. Maybe check back on this later.
				// TODO: Try/catch this or otherwise do error handling / checking
					UserID: uint64(claims[USER_ID_KEY].(float64)),
					UserType: claims[USER_TYPE_KEY].(string),
				}
			//return claims["id"]
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		auth.GET("/hello", helloHandler)
		auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
