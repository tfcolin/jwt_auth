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
)

type UserAddJson struct {
      Token string      `json:"token"`
      AccLimit int      `json:"acc_limit"`
      PubKey string     `json:"pubkey"`
}

func main() {
      if len(os.Args) < 5 {
            fmt.Println ("Usage: generator user_id(int) comm_seq user_name rsa_key_path")
            return
      }
      id, err := strconv.Atoi(os.Args[1])
      if (err != nil) {
            fmt.Println ("Usage: generator user_id(int) comm_seq user_name rsa_key_path")
            return
      }
      seq, err := strconv.Atoi(os.Args[2])
      if (err != nil) {
            fmt.Println ("Usage: generator user_id(int) comm_seq user_name rsa_key_path")
            return
      }

      uname := os.Args[3]
      rsa_key_path := os.Args[4]

      token := jwt_auth.GenerateJWT (id, seq, uname, rsa_key_path)
      if len(token) == 0 {
            panic ("fail to parse rsa_key_file")
      }

      fmt.Println ("Content-Type: application/json")
      fmt.Printf ("Authorization: %s\n", token)
}
