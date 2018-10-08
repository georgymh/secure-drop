package main
//package main 
import (
	"github.com/nweaver/cs161-p2/userlib"

	"encoding/json"

	//"github.com/google/uuid"

	//"strings"

	//"errors"
	"fmt"
)

type User struct {
	Username string
	Password string
	//should we derreferance it?
	Priv *userlib.PrivateKey
	Signature_Id []byte
}
var datastore = make(map[string][]byte)

func main() {

	password := "eliavelar"
	username := "computerscienceEECS"

	Kpriv, _ := userlib.GenerateRSAKey()
	//Kpubl := &Kpriv.PublicKey

	//2. Generate Kgen, IV, and signature_id using Argon2 (salt=password). 
	//Key length(36) : 16 bytes (key), 16 bytes (IV), 4 bytes (signature -- ID)
	Fields_Generate := userlib.Argon2Key([]byte(username), []byte(password), 36)
	Kgen := Fields_Generate[:16]
	IV := Fields_Generate[16:32]
	signature := Fields_Generate[32:]	

	// 3. Fill in struct (signature_id should be a random string)
	user_init := User{Username: username, Password: password, Priv: Kpriv, Signature_Id:signature}

	// Marshall object then encrypt 
	msg, _ := json.Marshal(user_init)
	//fmt.Println(mar);


	//Encrypted_User := userlib.CFBEncrypter(Kgen, IV)
	Encrypted_User := cfb_encrypt(Kgen, msg, IV) 
	encrypted_PlusIV := append(IV, Encrypted_User...)
	//s := string(signature)
	//user_data_store = "signatures_" + s
	


	fmt.Println("this is IV")
	fmt.Println(IV)
	
	// fmt.Println("this is the original message")
	// fmt.Println(msg)

	// fmt.Println("this is the encypted Message")
	fmt.Println(Encrypted_User)

	// fmt.Println("after appending")
	// s := string(signature[:])
	// user_data_store := "signatures_" + s
	// mac := userlib.NewHMAC(Kgen)
	// mac.Write(encrypted_PlusIV)
	// expectedMAC := mac.Sum(nil)
	// datastore[user_data_store] = expectedMAC
	// fmt.Println(expectedMAC)
	// fmt.Println(user_data_store)
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	datastore[user_lookup_id] = encrypted_PlusIV

	fmt.Println("this is the user_lookup_id")

	fmt.Println(user_lookup_id)


	
} 

func cfb_encrypt(key []byte,  plainText []byte, iv []byte) (cipherText []byte) {
	stream := userlib.CFBEncrypter(key, iv)
	cipherText = make([]byte, len(plainText))

	//stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	stream.XORKeyStream(cipherText, plainText)
	return 
	
}






