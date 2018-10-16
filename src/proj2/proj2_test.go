package proj2

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/nweaver/cs161-p2/userlib"
)

// import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	someUsefulThings()
	userlib.DatastoreClear()

	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

// This test does not pass ?
func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
}

// //------------------ Extra tests ----------------------------------//

// Test for creating and getting multiple users
func TestInitAndGetMultiple(t *testing.T) {
	//userlib.DatastoreClear()
	userlib.DebugPrint = false
	u, err := InitUser("alice", "fubar")
	y, errTwo := InitUser("Bob", "fubar")
	z, errThree := InitUser("Nick", "Waiver")
	if err != nil || errTwo != nil || errThree != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Got user", y)
	t.Log("Got user", z)
	// You probably want many more tests here.

	z1, e1 := GetUser("Nick", "Waiver")
	if e1 != nil {
		t.Error("Failed to reload user", e1)
		return
	}

	u1, e2 := GetUser("alice", "fubar")
	if e2 != nil {
		t.Error("Failed to reload user", e2)
		return
	}
	t.Log("Loaded user", u1)
	t.Log("Loaded user", z1)

	v1 := []byte("This is a test")
	u1.StoreFile("file1", v1)

	v2 := []byte("Checking if user test")
	z1.StoreFile("file1", v2)
}

func Test_Get_User(t *testing.T) {
	user1, e1 := InitUser("cs161-p2", "csiscool")
	user2, e2 := GetUser("cs161-p2", "csiscool")
	if e1 != nil && e2 != nil {
		if user1.Username != "cs161-p2" {
			t.Error("Username not stored correctly")
		}
		if !reflect.DeepEqual(user1.Signature_Id, user2.Signature_Id) {
			t.Error("Signature_Id don't match", user1.Signature_Id, user2.Signature_Id)
		}
		if !reflect.DeepEqual(user1.Priv, user2.Priv) {
			t.Error("Private keys corrupted", user1.Priv, user2.Priv)
		}
	}
}

//This test passes
func TestStorageValid(t *testing.T) {
	// Create another user
	user, userError := InitUser("Elizabeth", "Avelar")
	if userError != nil {
		t.Error("User (Elizabeth) could not be created.")
		return
	}

	// Create a file under the user
	fileName := "somefile.txt"
	fileContents := []byte("CS161 Homework")
	fileContentsBytes := []byte(fileContents) // for future use...
	t.Log("Storing the contents:", fileContents)
	user.StoreFile(fileName, fileContents)

	// Reconstruct the keys and manually check the DataStore to see if the file
	// was stored
	output := userlib.Argon2Key([]byte(user.Username), []byte(fileName), 32)
	KgenF := output[:16]

	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(KgenF))
	lookupID := string(sha256.Sum(nil))
	_, ok := userlib.DatastoreGet("files_" + lookupID)
	if ok {
		str := fmt.Sprintf("We found the value in the DataStore! (key: %s)", lookupID)
		t.Log(str)
	} else {
		str := fmt.Sprintf("An error ocurred while looking up (%s) in DataStore.", lookupID)
		t.Error(str)
	}

	// Now check if we can retrieve and read the file, and everythin is OK
	fileData, fileError := user.LoadFile("somefile.txt")

	// Check for errors
	if fileError != nil {
		str := fmt.Sprintf("Error while uploading the file.\n"+
			"Error message: %s\n"+"Data returned: %s\n", fileError, fileData)
		t.Error(str)
	}

	if bytes.Compare(fileContentsBytes, fileData) != 0 {
		str := fmt.Sprintf(
			"Data is not what is supposed to be!\n"+
				"Found (bytes): %s\n"+
				"Expected (bytes): %s\n",
			fileData,
			fileContentsBytes,
		)
		t.Error(str)
	}
}

// //Test append
func TestAppend(t *testing.T) {
	// Get user
	user, userError := GetUser("Elizabeth", "Avelar")
	if userError != nil {
		t.Error("Failed to get user")
	}
	t.Log("Logged in as", user.Username)

	// Get file (sanity)
	fileName := "somefile.txt"
	initialFileData, fileError := user.LoadFile(fileName)
	if fileError != nil {
		t.Error("Failed to get the file")
	}
	t.Log("Initial file contents:", initialFileData)

	// Append to file
	newData := "\nThis is totally unrelated but w/e"
	newDataInBytes := []byte(newData)
	appendingError := user.AppendFile(fileName, newDataInBytes)
	if appendingError != nil {
		t.Error("Failed to append to file")
	}

	// Append to file again
	newData2 := "\nThis too"
	newDataInBytes2 := []byte(newData2)
	appendingError2 := user.AppendFile(fileName, newDataInBytes2)
	if appendingError2 != nil {
		t.Error("Failed to append to file for the second time")
	}

	// Read file to check if we actually appended
	resultingFileData, resultingFileError := user.LoadFile(fileName)
	if resultingFileError != nil {
		t.Error("Failed to get the file after appending. Error:", resultingFileError)
	}
	var expectedFileData []byte
	expectedFileData = append(expectedFileData, initialFileData...)
	expectedFileData = append(expectedFileData, newData...)
	expectedFileData = append(expectedFileData, newData2...)
	t.Log("Current file contents:", resultingFileData)
	t.Log("Expected file contents:", expectedFileData)
	if bytes.Compare(resultingFileData, expectedFileData) != 0 {
		t.Error("Resulting file data and contents are not the same")
	}
}

//Testing corrupting data user
// func TestGetUserWithCorruptedData(t *testing.T) {
// 	_, e1 := InitUser("Berkeley", "EECS")
// 	if e1 != nil {
// 		t.Error("User1 could not be created")
// 	}
// 	_, e2 := InitUser("Nick", "waver")
// 	if e2 != nil {
// 		t.Error("User2 could not be created")
// 	}
// 	m := userlib.DatastoreGetMap()
// 	//len_ := range m;
// 	var val [4][]byte
// 	var keys [6]string
// 	var i = 0
// 	for k, _ := range m {
// 		val[i] = m[k]
// 		keys[i] = k
// 		i += 1
// 	}
// 	userlib.DatastoreSet(keys[0], val[1])
// 	userlib.DatastoreSet(keys[1], val[0])
// 	_, eer := GetUser("Berkeley", "EECS")
// 	if eer == nil {
// 		t.Error("Accessed corrupted data of user", eer)
// 	}
// 	userlib.DatastoreClear()
// }

func TestForSharingAndRecieving(t *testing.T) {
	_, e1 := InitUser("Nick", "Waiver")
	if e1 != nil {
		t.Error("Failed to initialize user1", e1)
	}
	u, e2 := GetUser("Nick", "Waiver")
	if e2 != nil {
		t.Error("Failed to reload user1", e2)
	}
	user2, e3 := InitUser("Scott", "Shenker")
	if e3 != nil {
		t.Error("Failed to initialize user2", e3)
	}
	var v []byte
	var msgid string

	//var msgid1 string
	v = []byte("This is a test")
	u.StoreFile("file1", v)
	v, e4 := u.LoadFile("file1")
	if e4 != nil {
		t.Error("Failed to download the file from nick", e4)
	}
	msgid, e5 := u.ShareFile("file1", "Scott")
	if e5 != nil {
		t.Error("Failed to share the a file", e5)
	}
	//_ = u.RevokeFile("file1")
	e6 := user2.ReceiveFile("file2", "Nick", msgid)
	if e6 != nil {
		t.Error("Failed to receive the share message", e6)
	}
	v2, e7 := user2.LoadFile("file2")
	if e7 == nil {
		t.Error("Succeded to download the file after sharing", e7)
	}
	if reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
}
