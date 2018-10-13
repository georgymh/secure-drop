package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	//should we derreferance it?
	Priv *userlib.PrivateKey

	//Modified to type[]byte
	Signature_Id []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
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

	// 6. Put "signatures_"||signature_id -> HMAC(K_gen, IV||E(struct) into DataStore
	user_data_store := "signatures_" + string(signature[:])
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	userlib.DatastoreSet(user_data_store, expectedMAC)

	// 7. Put "users_"||SHA256(Kgen) -> IV||E(struct) into DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	userlib.DatastoreSet(user_lookup_id, IV_EncryptedStruct)

	// 8. Store RSA public key into KeyStore
	userlib.KeystoreSet(username, *Kpubl)

	// 9. Return pointer to the struct
	

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// 1. Reconstruct Kgen using Argon2
	bytes_generated := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := bytes_generated[:16]

	// 2. Look up "users_"||SHA256(Kgen) in the DataStore and get the E(struct)||IV
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	IV_EncryptedStruct, ok := userlib.DatastoreGet(user_lookup_id)

	// 3. If the id is not found in the DataStore, fail with an error
	if !ok {
		return nil, errors.New("Incorrect username or password.")
	}

	// 4. Break up IV||E(struct) and decrypt the structure using Kgen
	IV := IV_EncryptedStruct[:16]
	E_struct := IV_EncryptedStruct[16:]

	//Decrypt then unmarshall data then get ID field
	struct_marshall := cfb_decrypt(Kgen, E_struct, IV)
	var userStruct User
	json.Unmarshal(struct_marshall, &userStruct)

	// 5. Look up "signatures_"||struct->signature_id from the DataStore and
	// get the Signature_HMAC
	id := userStruct.Signature_Id
	id_to_lookup := "signatures_" + string(id)
	signature_hmac, ok := userlib.DatastoreGet(id_to_lookup)

	if !ok {
		return nil, errors.New("HMAC was not found")
	}

	// 6. Verify that HMAC(K_gen, IV||E(struct)) == Signature_HMAC and if not,
	// fail with an error
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)

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

type File struct {
	Data              string
	Count             int
	Shared_With_Users []string
	Signature_Id      []byte
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Call _StoreFileHelper() with index = 0
}

func (userdata *User) _StoreFileHelper(filename string, data []byte, index int) {
	// 1. Generate KgenF, IV and signature_id using Argon2 with parameters
	//    (pass=username || 0, salt=filename)

	// 2. Fill in a File struct with the filename, data, count integer,
	//	  shared with users and signature_id

	// 3. Marshall and encrypt struct with CFB (key=Kgen, IV=random string).

	// 4. Concat IV||E(struct)

	// 5. Put "signatures_"||signature_id -> HMAC(K_genF, IV||E(struct)) into
	//    DataStore

	// 6. Put "files_"||SHA256(KgenF) -> IV||E(struct) into DataStore

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// 1. Reconstruct KgenF and IV using Argon2

	// 2. Get and decrypt the File struct from DataStore
	// (NOTE: first look for it in the namespace "shared_files_". Do the
	//	conversion if found, otherwise look at the "files_" namespace)

	// 3. Return an error if the file struct has been tampered with (check
	// signature and HMAC)

	// 4. For i = 1 to struct_0->count, return an error if file struct_i has been
	// tampered

	// 5. Add 1 to the count on the struct

	// 6. Update the File structure and signature in DataStore

	// 7. Call _StoreFileHelper on the new appended data with index = count + 1
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// 1. Reconstruct KgenF and IV using Argon2 (using index = 0)

	// 2. Get and decrypt the File struct from DataStore
	// (NOTE: first look for it in the namespace "shared_files_". Do the
	//	conversion if found, otherwise look at the "files_" namespace)

	// 3. Return nil if record not found

	// 4. Return an error if the file struct_0 has been tampered with (check
	// signature and HMAC)

	// 5. Retrieve the count from the structure

	// 6. Initialize all_data variable with struct_0->data

	// 7. For i between 1 and count (inclusive)

	// 7.a. Reconstruct KgenF, IV, and signature_id using Argon2 (using index = i)

	// 7.b. Get and decrypt the File struct from DataStore

	// 7.c. Return an error if the file struct_i has been tampered with (check
	// signature and HMAC)

	// 7.d. Append struct_i->data to all_data

	// 8. Return all_data
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Sender       string
	Reveiver     string
	File_Key     []byte
	Iv           []byte
	Signature_Id []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// 1. Reconstruct KgenF and IV using Argon2 (using index = 0)

	// 1.5. Get the file and error if File struct is not found on the DataStore
	// (NOTE: first look for it in the namespace "shared_files_". Do the
	//	conversion if found, otherwise look at the "files_" namespace)

	// 1.75. Error if data has been tampered with [NOTE: not sure if we need to
	// check this -- prompt doesn't say anything about it]

	// 2. Make a sharingRecord struct with the sender's username, receiver's
	// username, KgenF (as File_Key), and IV (make signature_id be empty)

	// 3. Look up the RSA Public Key of the recipient in the KeyStore

	// 3.5. Error if it is not found

	// 4. Store a random byte onto the DataStore with id:
	// "pending_shares_"||SHA256(Argon2(pass=KgenF, salt=recipient's username))
	// (This will be used to verify that the file wasn't already received)

	// 5. RSA Encrypt the marshalled version of the sharingRecord struct using
	// the recipient's RSA Public Key

	// 6. Sign (HMAC) the encrypted message (from step 4) using the current user's
	// RSA private key [NOTE: I changed this -- before we had the HMAC of the
	// encrypted message using the RSA Public Key of the receiver, but I think
	// this is more secure]

	// 7. Return the concatenation of the encrypted message || signature ||
	// current user's username

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	// 1. (msgid is the RSA-E_K_rec,pub(sharingRecord struct)||HMAC())
	// Decrypt the sharingRecord struct using the receiver's RSA Private Key

	// 2. Get the receiver's RSA Public Key from KeyStore

	// 3. Verify the HMAC of the encrypted sharingRecord using the receiver's RSA
	// Public Key [if not valid, error]

	// 4. Generate the one_time_verification_id and completed_IV with
	// Argon2(pass=struct->KgenF, salt=receiver's username)

	// 5. If "pending_shares_"||SHA256(one_time_verification_id) doesn't exist in
	// the DataStore, send error (this implies that the data was already shared
	// with this user)

	// 6. Delete "pending_shares_"||SHA256(one_time_verification_id) from the
	// DataStore to prevent message reuses

	// 4. Generate NewKgenF, IV and signature_id using Argon2 with parameters
	// (pass=receiver's username || 0, salt=filename)

	// 5. Set struct->signature_id to be signature_id

	// 6. Marshall and encrypt struct with CFB (key=NewKgenF, IV=IV) [E(struct)]

	// 7. Concat IV||E(struct)

	// 8. Put "signatures_"||signature_id -> HMAC(NewKgenF, IV||E(struct)) into
	// DataStore

	// 9. Put "shared_files_"||SHA256(NewKgenF) -> IV||E(struct) into DataStore

	// 10. Get the original File struct from DataStore (Get
	// "files_"||SHA256(struct->File_Key) and decrypt it with struct->File_Key)
	// [NOTE: this may be insecure because receiver could store the
	// struct->File_Key somewhere! -- let's ask Piazza]

	// 11. Append the SHA256(NewKGenF) to original File struct's property
	// Shared_With_Users (this will be used for revoking)

	// 12. Update the Original File Struct on the DataStore (marshall and encrypt
	// and store as struct->Iv||E(struct))

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// 1. Generate KgenF, IV and signature_id using Argon2 with parameters
	//    (pass=username || 0, salt=filename)

	// 2. Get the File struct from DataStore under the "shared_files_" namespace

	// 3. If found, return error because this user is not the original owner of
	// the file

	// 4. Get the File struct from DataStore under the "files_" namespace

	// 5. If not found, return error because the file doesn't exist

	// 6. Decrypt the File struct

	// 7. For each of the SHA256(NewKGenF) in struct->Shared_With_Users

	// 7.a. Delete "shared_files_"||SHA256(NewKgenF)" from the DataStore

	// 8. Make struct->Shared_With_Users be the empty array

	// 9. Update the File Struct on the DataStore (marshall and encrypt and store
	// as IV||E(struct))

	return
}

//-------- helper functions --------//

func cfb_encrypt(key []byte, plainText []byte, iv []byte) (cipherText []byte) {
	stream := userlib.CFBEncrypter(key, iv)
	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return
}

func cfb_decrypt(key []byte, ciphertext []byte, iv []byte) (plaintext []byte) {
	stream := userlib.CFBDecrypter(key, iv)
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return

}
