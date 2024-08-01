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
      Id int      `json:"id"`
      UserName string   `json:"username"`
      PubKey string     `json:"pubkey"`
}

func main() {
      if len(os.Args) < 4 {
            fmt.Println ("Usage: generator_user_add user_id(int) user_name rsa_pubkey_path")
            return
      }
      id, err := strconv.Atoi(os.Args[1])
      if (err != nil) {
            fmt.Println ("Usage: generator_user_add user_id(int) user_name rsa_pubkey_path")
            return
      }

      uname := os.Args[2]
      rsa_pubkey_path := os.Args[3]

      pubkey := jwt_auth.LoadRsaPublicKey (rsa_pubkey_path)
      if pubkey == nil {
            panic ("fail to parse rsa_pubkey_file")
      }
      pubkey_str, _ := os.ReadFile (rsa_pubkey_path)

      out := UserAddJson {
            Id : id,
            UserName : uname,
            PubKey : string(pubkey_str),
      }

      out_json, err := json.MarshalIndent (out, "", "      ")
      if err != nil {
            panic ("fail to marshall json output")
      }

      fmt.Println (string(out_json))
}
