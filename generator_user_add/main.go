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
      PubKey string     `json:"pubkey"`
}

func main() {
      if len(os.Args) < 5 {
            fmt.Println ("Usage: generator user_id(int) user_name rsa_key_path rsa_pubkey_path")
            return
      }
      id, err := strconv.Atoi(os.Args[1])
      if (err != nil) {
            fmt.Println ("Usage: generator user_id(int) user_name rsa_key_path rsa_pubkey_path")
            return
      }

      uname := os.Args[2]
      rsa_key_path := os.Args[3]
      rsa_pubkey_path := os.Args[4]

      token := jwt_auth.GenerateJWT (id, 0, uname, rsa_key_path)
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
      }

      out_json, err := json.MarshalIndent (out, "", "      ")
      if err != nil {
            panic ("fail to marshall json output")
      }

      fmt.Println (string(out_json))
}
