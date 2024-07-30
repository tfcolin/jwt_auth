package main

/* Usage:
* generator user_id user_name email rsa_key_path
*     output token to stdout
*/

import (
      "fmt"
      "os"
      "strconv"
      "gitee.com/tfcolin/jwt_auth"
      "encoding/json"
)

type UserAddJson struct {
      Token string      `json:"token"`
      AccLimit int      `json:"acc_limit"`
      PubKey string     `json:"pubkey"`
}

const MAX_ACCESS_TIME = 15 

func main() {

      if len(os.Args) < 6 {
            fmt.Println ("Usage: generator user_id(int) user_name email rsa_key_path rsa_pubkey_path")
      }
      id, err := strconv.Atoi(os.Args[1])
      if (err != nil) {
            fmt.Println ("Usage: generator user_id(int) user_name email rsa_key_path rsa_pubkey_path")
      }

      uname := os.Args[2]
      email := os.Args[3]
      rsa_key_path := os.Args[4]
      rsa_pubkey_path := os.Args[5]

      token := jwt_auth.GenerateJWT (id, uname, email, rsa_key_path)
      pubkey := jwt_auth.LoadRsaPublicKey (rsa_pubkey_path)
      if len(token) == 0 {
            panic ("fail to parse rsa_key_file")
      }
      if pubkey == nil {
            panic ("fail to parse rsa_pubkey_file")
      }
      pubkey_str, _ := os.ReadFile (rsa_pubkey_path)

      out := UserAddJson {
            Token : token,
            PubKey : string(pubkey_str),
            AccLimit : MAX_ACCESS_TIME,
      }

      out_json, err := json.MarshalIndent (out, "", "      ")
      if err != nil {
            panic ("fail to marshall json output")
      }

      fmt.Println (string(out_json))
}
