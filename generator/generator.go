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
      if len(os.Args) < 8 {
            fmt.Println ("Usage: generator user_id(int) user_name email rsa_key_path rsa_pubkey_path output_user_add_json output_user_header")
            return
      }
      id, err := strconv.Atoi(os.Args[1])
      if (err != nil) {
            fmt.Println ("Usage: generator user_id(int) user_name email rsa_key_path rsa_pubkey_path output_user_add_json output_user_header")
            return
      }

      uname := os.Args[2]
      email := os.Args[3]
      rsa_key_path := os.Args[4]
      rsa_pubkey_path := os.Args[5]

      fua, err := os.Create (os.Args[6])
      if (err != nil) {
            panic ("cannot create json file for user adding")
      }
      fh, err := os.Create (os.Args[7])
      if (err != nil) {
            panic ("cannot create header file for the new user")
      }

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

      fmt.Fprintln (fua, string(out_json))
      fmt.Fprintln (fh, "Content-Type: application/json")
      fmt.Fprintf (fh, "Authorization: %s\n", token)

      fua.Close()
      fh.Close()
}
