package main
//package main 
import (
	"github.com/nweaver/cs161-p2/userlib"

	"encoding/json"
	"encoding/hex"

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
	test_init_user()

} 

func  test_init_user() {
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
	fmt.Println("---------------------This is the length of unecrypted user struct -------------------------------")
	EncodeStringMarshal_user := hex.EncodeToString(msg)
	// fmt.Println(len(EncodeStringMarshal_user))

	// fmt.Println("---------------------This is the unecrypted user struct -------------------------------")
	// fmt.Println(EncodeStringMarshal_user);

	// fmt.Println("---------------------This is the Encrypted user struct -------------------------------")
	 Encrypted_User := cfb_encrypt(Kgen, msg, IV) 
	// encodedStr := hex.EncodeToString(Encrypted_User)
	// fmt.Println(encodedStr)

	// fmt.Println("---------------------This is the decrypted user struct -------------------------------")
	// //decrypted_User := cfb_decrypt(Kgen, Encrypted_User, IV) 
    Decrypted_user := cfb_decrypt(Kgen, Encrypted_User, IV) 
    EncodeDecryotedStr := hex.EncodeToString(Decrypted_user)

	//fmt.Println(EncodeDecryotedStr)

    // Print if EncodedString and Decoded String are the sames
	fmt.Println(EncodeStringMarshal_user == EncodeDecryotedStr)



//encrypted_PlusIV := append(IV, Encrypted_User...)
	//s := string(signature)
	//user_data_store = "signatures_" + s
	


	//fmt.Println("this is IV")
	//fmt.Println(IV)
	
	// fmt.Println("this is the original message")
	// fmt.Println(msg)

	// fmt.Println("this is the encypted Message")
	


//Writting the hash of user into the data store
	// fmt.Println("after appending")
	// s := string(signature[:])
	// user_data_store := "signatures_" + s
	// mac := userlib.NewHMAC(Kgen)
	// mac.Write(encrypted_PlusIV)
	// expectedMAC := mac.Sum(nil)
	// datastore[user_data_store] = expectedMAC
	// fmt.Println(expectedMAC)
	// fmt.Println(user_data_store)


// Writting user into 
	// sha256 := userlib.NewSHA256()
	// sha256.Write([]byte(Kgen))
	// user_lookup_id := "users_" + string(sha256.Sum(nil))
	// datastore[user_lookup_id] = encrypted_PlusIV

	// fmt.Println("this is the user_lookup_id")

	// fmt.Println(user_lookup_id)

	
}

func cfb_encrypt(key []byte,  plainText []byte, iv []byte) (cipherText []byte) {
	stream := userlib.CFBEncrypter(key, iv)
	cipherText = make([]byte, len(plainText))

	//stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	stream.XORKeyStream(cipherText, plainText)
	return 
	
}

func cfb_decrypt(key []byte,  ciphertext []byte, iv []byte) (plaintext []byte){
	stream := userlib.CFBDecrypter(key, iv)
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	//fmt.Println(ciphertext)
	//plaintext = ciphertext
	return 
	
}






