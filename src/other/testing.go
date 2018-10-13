package main
//package main 
import (
	"github.com/nweaver/cs161-p2/userlib"

	"encoding/json"
	// /"encoding/hex"
	"crypto/rsa"

	//"github.com/google/uuid"

	//"strings"

	"errors"
	"fmt"
)


////////----------------from weivers files: START -------------------------////
var datastore = make(map[string][]byte)
var keystore = make(map[string]rsa.PublicKey)


func DatastoreSet(key string, value []byte) {
	foo := make([]byte, len(value))
	copy(foo, value)
	datastore[key] = foo
}

// Returns the value if it exists
func DatastoreGet(key string) (value []byte, ok bool) {
	value, ok = datastore[key]
	if ok && value != nil {
		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

// Deletes a key
func DatastoreDelete(key string) {
	delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
	datastore = make(map[string][]byte)
}

func KeystoreClear() {
	keystore = make(map[string]rsa.PublicKey)
}

func KeystoreSet(key string, value rsa.PublicKey) {
	keystore[key] = value
}

func KeystoreGet(key string) (value rsa.PublicKey, ok bool) {
	value, ok = keystore[key]
	return
}

////////----------------from weivers files: END -------------------------////

type User struct {
	Username string
	Password string
	//should we derreferance it?
	Priv *userlib.PrivateKey
	Signature_Id []byte
}


func main() {
	username := "Fuck161"
	password := "cs161"
	test_InitUser(username, password)

	///////////////////-------------------------------- TESTING IF THE USER EXISTS IN DATASTORE -------------------------//////
	userStruct, errors:= testing_GetUser(username, password)
	if userStruct == nil {
		fmt.Println("ohhhh noooo")
		fmt.Println(errors)
	}
	fmt.Println("We just got the user ")
	fmt.Println(" The username is: ")
	fmt.Println(userStruct)
} 

func  test_InitUser(username string, password string) (userdataptr *User, err error) {
	//var userdata User

	// 1. Generate RSA key-pair
	Kpriv, _ := userlib.GenerateRSAKey()
	Kpubl := &Kpriv.PublicKey

	//2. Generate Kgen, IV, and signature_id using Argon2 (salt=password).
	//Key length(36) : 16 bytes (key), 16 bytes (IV), 4 bytes (signature -- ID)
	Fields_Generate := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := Fields_Generate[:16]
	IV := Fields_Generate[16:32]
	signature := Fields_Generate[32:]

	// 3. Fill in struct (signature_id should be a random string)
	var userdata = User{Username: username, Password: password, Priv: Kpriv, Signature_Id: signature}

	// 4. Encrypt struct with CFB (key=Kgen, IV=random string)
	// Marshall User before encrypt
	user_, _ := json.Marshal(userdata)

	Encrypted_User := cfb_encrypt(Kgen, user_, IV)

	// 5. Concat IV||E(struct)
	IV_EncryptedStruct := append(IV, Encrypted_User...)
	// fmt.Println("This is the IV_EncryptedStruct from user init")
	// fmt.Println(IV_EncryptedStruct)

	// 6. Put "signatures_"||signature_id -> HMAC(K_gen, IV||E(struct) into DataStore
	user_data_store := "signatures_" + string(signature[:])
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	DatastoreSet(user_data_store, expectedMAC)

	// 7. Put "users_"||SHA256(Kgen) -> IV||E(struct) into DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	DatastoreSet(user_lookup_id, IV_EncryptedStruct)

	// IV_Encrypted, _ := DatastoreGet(user_lookup_id)
	// fmt.Println("This is get the user using GetUser")
	// fmt.Println(string(IV_Encrypted)==string(IV_EncryptedStruct))

	// 8. Store RSA public key into KeyStore
	
	KeystoreSet(username, *Kpubl)

	// 9. Return pointer to the struct
	return &userdata, err
}

func testing_GetUser(username string, password string) (userdataptr *User, err error) {
	// 1. Reconstruct Kgen using Argon2
	bytes_generated := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := bytes_generated[:16]

	// 2. Look up "users_"||SHA256(Kgen) in the DataStore and get the E(struct)||IV
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	IV_EncryptedStruct, ok := DatastoreGet(user_lookup_id)
	// fmt.Println("This is get the user using GetUser")
	// fmt.Println(IV_EncryptedStruct)

	// 3. If the id is not found in the DataStore, fail with an error
	if !ok {
		return nil, errors.New("Incorrect username or password.")
	}

	// 4. Break up IV||E(struct) and decrypt the structure using Kgen
	IV := IV_EncryptedStruct[:16]
	E_struct := IV_EncryptedStruct[16:]
	fmt.Println("this is the size of the struct")
	fmt.Println(len(E_struct))
	

	//Decrypt then unmarshall data then get ID field
	struct_marshall := cfb_decrypt(Kgen, E_struct, IV)
	var userStruct User
	json.Unmarshal(struct_marshall, &userStruct)

	// 5. Look up "signatures_"||struct->signature_id from the DataStore and
	// get the Signature_HMAC
	id := userStruct.Signature_Id
	id_to_lookup := "signatures_" + string(id)
	signature_hmac, ok := DatastoreGet(id_to_lookup)

	/////----------- Error might be above this line -------------------------////

	if !ok {
		return nil, errors.New("HMAC was not found")
	}

	// 6. Verify that HMAC(K_gen, IV||E(struct)) == Signature_HMAC and if not,
	// fail with an error
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	fmt.Println("The size of the MAC is: ")
	fmt.Println(len(expectedMAC))

    // Not sure if this is right way to compare but cannot compare using bytes.equals since cannnot import anything else
	if string(expectedMAC) != string(signature_hmac) { 
		return nil, errors.New("Found corrupted data")
	}

	// 7. Check that username == struct->username and password == struct->password,
	// and if not, fail with an error
	if userStruct.Username != username {
		return nil, errors.New("Wrong username")
	}

	// 8. Return a pointer to the user struct
	return &userStruct, err
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






