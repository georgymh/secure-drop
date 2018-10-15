package proj2

import "github.com/nweaver/cs161-p2/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	someUsefulThings()

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

	// v2, err2 := u.LoadFile("file1")
	// if err2 != nil {
	// 	t.Error("Failed to upload and download", err2)
	// }
	// if !reflect.DeepEqual(v, v2) {
	// 	t.Error("Downloaded file is not the same", v, v2)
	// }
}

// func TestShare(t *testing.T) {
// 	u, err := GetUser("alice", "fubar")
// 	if err != nil {
// 		t.Error("Failed to reload user", err)
// 	}
// 	u2, err2 := InitUser("bob", "foobar")
// 	if err2 != nil {
// 		t.Error("Failed to initialize bob", err2)
// 	}

// 	var v, v2 []byte
// 	var msgid string

// 	v, err = u.LoadFile("file1")
// 	if err != nil {
// 		t.Error("Failed to download the file from alice", err)
// 	}

// 	msgid, err = u.ShareFile("file1", "bob")
// 	if err != nil {
// 		t.Error("Failed to share the a file", err)
// 	}
// 	err = u2.ReceiveFile("file2", "alice", msgid)
// 	if err != nil {
// 		t.Error("Failed to receive the share message", err)
// 	}

// 	v2, err = u2.LoadFile("file2")
// 	if err != nil {
// 		t.Error("Failed to download the file after sharing", err)
// 	}
// 	if !reflect.DeepEqual(v, v2) {
// 		t.Error("Shared file is not the same", v, v2)
// 	}
// }


//------------------ Extra tests ----------------------------------//
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

//Debugging test case 
// func TestCorruptDataAndGetUser(t *testing.T) {
//    userlib.DatastoreClear()
//    _, e1 := InitUser("Berkeley", "EECS")
//    if e1 != nil {
//         t.Error("User1 could not be created")
//    }
//    _, e2 := InitUser("Nick", "waver")
//    if e2 != nil {
//         t.Error("User2 could not be created")
//    }
//    m := userlib.DatastoreGetMap()
//    var val [2][]byte
//    var keys [2]string
//    var i = 0
//    for k, _ := range m {
//        val[i] = m[k]
//        keys[i] = k
//        i += 1
//    }
//    userlib.DatastoreSet(keys[0], val[1])
//    userlib.DatastoreSet(keys[1], val[0])
//    _, eer := GetUser("Berkeley", "EECS")
//    if eer == nil {
//         t.Error("Accessed corrupted data of user", eer)
//    }
// 	 userlib.DatastoreClear()
// }
































