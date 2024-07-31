package jwt_auth

import (
      "fmt"
      "os"
      "strconv"
      "crypto/rsa"
      // "golang.org/x/crypto/ssh"
      "github.com/golang-jwt/jwt/v5"
      "gitee.com/tfcolin/dsg"
)

type JWTClaim struct {
      jwt.RegisteredClaims
      UserName string `json:"username"`
      UserId   int    `json:"uid"`
      CommSeq     int `json:"seq"`
}

type AccessStatus int
const (
      AS_SUCCESS AccessStatus = 0
      AS_FAIL AccessStatus = 1
      AS_INVALID_ID AccessStatus = 2
      AS_EXCEED_LIMIT AccessStatus = 3
      AS_QUIT_ERROR AccessStatus = -1
      AS_LOCK AccessStatus = -2
)

type UserAddStatus int
const (
      UAS_SUCCESS UserAddStatus = 0
      UAS_KEY_PARSE_ERR UserAddStatus = 1
      UAS_KEY_WRITE_ERR UserAddStatus = 2
      UAS_ID_ERR UserAddStatus = 3
      UAS_QUIT_ERROR UserAddStatus = -1
      UAS_LOCK UserAddStatus = -2
)

const (
      MAX_ID = 4096
      MAX_AUTH_RUN = 5
)

type User struct {
      PubKey * rsa.PublicKey       
      UserName string
      AccTime int      
      AccLimit int     
}

var (
      Users []User
      id_pool * dsg.LinkSet
      id_used * dsg.LinkSet
      admin_on bool

      lock_lock chan struct{}
      admin_lock chan struct{} 
      auth_lock chan struct{}
)

func JWTAuthInit () {
      /* initialize admin lock */
      admin_lock = make (chan struct{}, 1)
      admin_lock <- struct{}{}
}

func AdminLock () {
      <- admin_lock 
}

func AdminUnlock () {
      admin_lock <- struct{}{}
}

func LoadRsaPublicKey (key_path string) *rsa.PublicKey {
      bytes, err := os.ReadFile(key_path)
      if (err != nil) {
            return nil
      }
      key, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
      // 也可使用 ssh 的 parse 函数 
      if (err != nil) {
            return nil
      }
      return key
}

func LoadRsaPrivateKey (key_path string) *rsa.PrivateKey {
      bytes, err := os.ReadFile(key_path)
      if (err != nil) {
            return nil
      }
      key, err := jwt.ParseRSAPrivateKeyFromPEM(bytes)
      // 也可使用 ssh 的 parse 函数 
      if (err != nil) {
            return nil
      }
      return key
}

func LoadUserInfo (user_dir string, admin_pubkey_path string) {
      if admin_on { return }
      AdminLock ()
      defer AdminUnlock()

      files, err := os.ReadDir(user_dir)
      if err != nil {
            panic ("load key directory error")
      }
      facc, err := os.Open(user_dir + "/user_acc.dat")
      if err != nil {
            panic ("cannot open user info record file")
      }
      admin_pubkey := LoadRsaPublicKey(admin_pubkey_path)
      if admin_pubkey == nil {
            panic ("cannot parse admin public key")
      }

      Users = make ([]User, MAX_ID)

      for {
            var id, n, acc, acc_limit int
            var uname string
            n, _ = fmt.Fscan (facc, &id, &uname, &acc, &acc_limit) 
            if n != 4 {
                  break
            }
            if (id < 0 || id >= MAX_ID) {
                  panic ("read user info record file error")
            }
            Users[id] = User {
                  UserName: uname,
                  AccTime: acc,
                  AccLimit: acc_limit,
            }
      }

      for _, file := range files {
            if file.IsDir() {
                  continue
            }

            name := file.Name()
            if name == "user_acc.dat" {
                  continue
            }

            id, err := strconv.Atoi(name[len(name) - 8 : len(name) - 4])
            if (err != nil || id < 0 || id >= MAX_ID) {
                  panic ("key file name error: must be ..._nnnn.pem (ID is nnnn)")
            }

            path := user_dir + "/" + file.Name()
            pub_key := LoadRsaPublicKey (path)
            if (pub_key == nil) {
                  panic ("load key file error")
            }
            Users[id].PubKey = pub_key
      }

      id_pool = dsg.InitFullLinkSet (MAX_ID)
      id_used = dsg.InitLinkSet (MAX_ID)
      for id, user := range Users {
            if (user.PubKey != nil) {
                  id_pool.UnSet (id)
                  id_used.Set(id)
            }
      }

      /* set admin user */
      Users[0] = User {
            UserName : "admin",
            AccTime : 0,
            AccLimit : -1,
            PubKey : admin_pubkey,
      }
      id_pool.UnSet(0)
      id_used.Set(0)

      admin_on = true
}

/* return JWT: len(token_str) = 0 means fail */
func GenerateJWT (id int, seq int, uname string, rsa_key_path string) (token_str string) {
      if (id < 0 || id >= MAX_ID) {
            return
      }

      rsa_key := LoadRsaPrivateKey(rsa_key_path)
      if (rsa_key == nil) {
            return
      }

      claims := JWTClaim {
            CommSeq: seq,
            UserName: uname,
            UserId: id,
      }
      token := jwt.NewWithClaims (jwt.GetSigningMethod("RS512"), claims)
      token_str, err := token.SignedString (rsa_key)
      if (err != nil) {
            token_str = ""
            return
      }

      return
}

/* id = -1 means fail */
func ValidateJWT (token_str string, rsa_pub_key *rsa.PublicKey) (id int, seq int, uname string) {
      token, err := jwt.ParseWithClaims (token_str, &JWTClaim{}, func (token *jwt.Token) (interface{}, error) {
            return rsa_pub_key, nil },
      )
      if err != nil || !token.Valid {
            id = -1
            return
      }

      claims := token.Claims.(*JWTClaim)
      if (claims.UserId < 0 || claims.UserId >= MAX_ID) {
            id = -1
            return
      }

      id = claims.UserId
      seq = claims.CommSeq
      uname = claims.UserName

      return
}

func GetInfoFromToken (token_str string) (id int, seq int, uname string) {
      token, _, err := jwt.NewParser().ParseUnverified (token_str, &JWTClaim{})
      if err != nil {
            id = -1
            return
      }
      claims := token.Claims.(*JWTClaim)
      id = claims.UserId
      seq = claims.CommSeq
      uname = claims.UserName

      return
}

func NewUserId () int {
      if !admin_on { return -1 }
      AdminLock()
      defer AdminUnlock()
      id := id_pool.GetFirstLabel()
      return id
}

func UserAdd (token_str string, acc_limit int, pub_key_str []byte, user_path string) UserAddStatus {
      if !admin_on { return UAS_QUIT_ERROR }
      AdminLock ()
      defer AdminUnlock()

      pub_key, err := jwt.ParseRSAPublicKeyFromPEM(pub_key_str)
      if (err != nil) {
            return UAS_KEY_PARSE_ERR
      }
      /* obtain id, uname, email */
      id, _, uname := ValidateJWT (token_str, pub_key)

      if id < 0 || id >= MAX_ID {
            return UAS_ID_ERR
      }
      if !id_pool.GetLabel(id) {
            return UAS_ID_ERR
      }

      /* write pub_key to file */
      fname := fmt.Sprintf ("%s/%s_%04d.pem", user_path, uname, id)
      err = os.WriteFile(fname, pub_key_str, 0644)
      if (err != nil) {
            return UAS_KEY_WRITE_ERR
      }

      /* create table entry for user info */
      Users[id] = User {
            UserName: uname,
            AccTime: 0,
            AccLimit: acc_limit,
            PubKey: pub_key,
      }

      if Users[id].PubKey == nil {
            Users[id] = User{}
            return UAS_KEY_PARSE_ERR
      }

      id_pool.UnSet (id)
      id_used.Set (id)

      return UAS_SUCCESS
}

func UserRemove (id int, user_path string) UserAddStatus {
      if !admin_on { return UAS_QUIT_ERROR }
      AdminLock ()
      defer AdminUnlock()

      if id <= 0 || id >= MAX_ID {
            return UAS_ID_ERR
      }
      if id_pool.GetLabel(id) {
            return UAS_ID_ERR
      }

      fname := fmt.Sprintf ("%s/%s_%04d.pem", user_path, Users[id].UserName, id)
      err := os.Remove(fname)
      if (err != nil) {
            return UAS_KEY_WRITE_ERR
      }

      Users[id] = User{}

      id_pool.Set(id)
      id_used.UnSet(id)

      return UAS_SUCCESS
}

/* return true if successfully access */
func UserAccess (token_str string) AccessStatus {
      if !admin_on { return AS_QUIT_ERROR }
      AdminLock()
      defer AdminUnlock()

      id, _, _ := GetInfoFromToken (token_str)
      if (id < 0 || id >= MAX_ID || id_pool.GetLabel(id)) {
            return AS_INVALID_ID
      }
      if Users[id].AccTime >= Users[id].AccLimit {
            return AS_EXCEED_LIMIT
      }

      idv, seq, uname := ValidateJWT (token_str, Users[id].PubKey)
      if (id != idv || uname != Users[id].UserName || seq != Users[id].AccTime) {
            return AS_FAIL
      }

      Users[id].AccTime ++
      return AS_SUCCESS
}

func ClearAccessTime () bool {
      if !admin_on { return true }
      AdminLock ()
      defer AdminUnlock()

      for id_used.TraverseStart();;id_used.TraverseForward() {
            id := id_used.GetTraverseLabel()
            if id == -1 {
                  break
            }
            Users[id].AccTime = 0
      }
      return false
}

func ListUsers (print_user_func func (id int, u User)) bool {
      if !admin_on { return true}
      AdminLock ()
      defer AdminUnlock()

      for id_used.TraverseStart();;id_used.TraverseForward() {
            id := id_used.GetTraverseLabel()
            if id == -1 {
                  break
            }
            print_user_func (id, Users[id])
      }
      return false
}

func SaveUserInfo (user_dir string) bool {
      if !admin_on { return true}
      AdminLock ()
      defer AdminUnlock()

      facc, err := os.Create(user_dir + "/user_acc.dat")
      if err != nil {
            panic ("cannot create user info record file")
      }

      for id_used.TraverseStart();;id_used.TraverseForward() {
            id := id_used.GetTraverseLabel()
            if id == 0 {
                  continue
            }
            if id == -1 {
                  break
            }
            u := Users[id]
            fmt.Fprintf (facc, "%v %v %v %v\n", id, u.UserName, u.AccTime, u.AccLimit)
      }

      facc.Close()

      admin_on = false
      return false
}

