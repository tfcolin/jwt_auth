package main

import (
      "fmt"
      "os"
      "log"
      "context"
      "time"
      "net/http"
      "github.com/gin-gonic/gin"
      "gitee.com/tfcolin/jwt_auth"
)

type TestJson struct {
      Title string `json:"title"`
}

type IdJson struct {
      Id int      `json:"id"`
}

type UserAddJson struct {
      Id int      `json:"id"`
      UserName string   `json:"username"`
      PubKey string     `json:"pubkey"`
}

type UserPrintJson struct {
      Id int                  `json:"id"`
      UserName string         `json:"username"`
      AccTime int             `json:"acc_time"`
      AccLimit int            `json:"acc_limit"`
}

var (
      user_path string 
      admin_pubkey_path string
      quit_sig chan struct{}
)

const (
      ACCESS_TIME_LIMIT  = 100
)

func auth_api_mw (c *gin.Context) {
      token_str := c.GetHeader("Authorization")
      if len(token_str) == 0 {
            c.IndentedJSON(401, gin.H{"error": "request does not contain an access token"})
            c.Abort()
            return
      }
      if jwt_auth.UserAccess(token_str) == jwt_auth.AS_SUCCESS {
            c.Next()
      } else {
            c.IndentedJSON(401, gin.H{"error": "access denied"})
            c.Abort()
      }
}

func auth_admin_mw (c *gin.Context) {
      token_str := c.GetHeader("Authorization")
      if len(token_str) == 0 {
            c.IndentedJSON(401, gin.H{"error": "request does not contain an admin access token"})
            c.Abort()
            return
      }

      id, _, uname := jwt_auth.ValidateJWT(token_str, jwt_auth.Users[0].PubKey)
      if id == 0 && uname == "admin" {
            c.Next()
      } else {
            c.IndentedJSON(401, gin.H{"error": "admin access denied"})
            c.Abort()
      }
}

func api_test_cb (c *gin.Context) {
      c.IndentedJSON (http.StatusOK, TestJson{Title: "TestABC"})
}

func admin_list_user_cb (c *gin.Context) {
      ulist := make([]UserPrintJson, 0)
      jwt_auth.ListUsers (func (id int, u jwt_auth.User) {
            up := UserPrintJson {
                  Id: id,
                  UserName: u.UserName,
                  AccTime: u.AccTime,
                  AccLimit: u.AccLimit,
            }
            ulist = append (ulist, up)
      })
      c.IndentedJSON (http.StatusOK, ulist)
}

func admin_get_new_id_cb (c *gin.Context) {
      c.IndentedJSON (http.StatusOK, IdJson{Id: jwt_auth.NewUserId()})
}

func admin_add_user_cb (c *gin.Context) {
      var ua_input UserAddJson 
      if err := c.BindJSON(&ua_input); err != nil {
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "commmand format error"})
            return
      }
      st := jwt_auth.UserAdd (ua_input.Id, ua_input.UserName, ACCESS_TIME_LIMIT, ([]byte)(ua_input.PubKey), user_path)
      switch (st) {
      case jwt_auth.UAS_SUCCESS:
            c.IndentedJSON(http.StatusOK, gin.H{"result": "Success"})
      case jwt_auth.UAS_KEY_PARSE_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error" : "PubKey parse error."})
      case jwt_auth.UAS_KEY_WRITE_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "PubKey save error."})
      case jwt_auth.UAS_ID_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Wrong id included in your token."})
      }
}

func admin_remove_user_cb (c *gin.Context) {
      var ur_input IdJson
      if err := c.BindJSON(&ur_input); err != nil {
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "commmand format error"})
            return
      }
      st := jwt_auth.UserRemove (ur_input.Id, user_path)
      switch (st) {
      case jwt_auth.UAS_SUCCESS:
            c.IndentedJSON(http.StatusOK, gin.H{"result": "Success"})
      case jwt_auth.UAS_KEY_PARSE_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "PubKey parse error."})
      case jwt_auth.UAS_KEY_WRITE_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "PubKey remove error."})
      case jwt_auth.UAS_ID_ERR:
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Wrong id."})
      }
}

func admin_clear_access_time_cb (c *gin.Context) {
      if jwt_auth.ClearAccessTime() {
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "server status error."})
      }
}

func admin_quit_cb (c *gin.Context) {
      if jwt_auth.SaveUserInfo(user_path) {
            c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "server status error."})
            return
      }
      c.IndentedJSON(http.StatusOK, gin.H{"result": "user info is saved: quit safely."})
      quit_sig <- struct{}{}
}

func main() {
      if len(os.Args) < 3 {
            fmt.Println ("Usage: server user_info_path admin_pubkey_path")
            return
      }

      user_path = os.Args[1]
      admin_pubkey_path = os.Args[2]

      jwt_auth.JWTAuthInit()
      jwt_auth.LoadUserInfo (user_path, admin_pubkey_path)

      quit_sig = make (chan struct{},1)

      router := gin.Default()
      api := router.Group("/api")
      admin := router.Group("/admin")

      api_auth := api.Use(auth_api_mw)
      admin_auth := admin.Use(auth_admin_mw)

      api_auth.GET("/test", api_test_cb)

      admin_auth.GET("/list_user", admin_list_user_cb)
      admin_auth.GET("/get_new_id", admin_get_new_id_cb)
      admin_auth.POST("/add_user", admin_add_user_cb)
      admin_auth.POST("/remove_user", admin_remove_user_cb)
      admin_auth.POST("/clear_access_time", admin_clear_access_time_cb)
      admin_auth.POST("/save_and_quit", admin_quit_cb)

      srv := &http.Server{
            Addr:    ":8080",
            Handler: router,
	}

      go func () {
            if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                  log.Fatalf("listen: %s\n", err)
            }
      } ()
      
      <- quit_sig

      ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
      defer cancel()
      if err := srv.Shutdown(ctx); err != nil {
            log.Fatal("Server Shutdown:", err)
      }
      fmt.Println("Server exiting")

}
