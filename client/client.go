package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	//RSAPublickey        userlib.PKEEncKey  Stored in Keystore as username+"'s RSAPublickey"
	RSAPrivatekey userlib.PKEDecKey
	//SignaturePublicKey  userlib.DSVerifyKey Stored in Keystore as username+"'s SignaturePublicKey"
	SiganturePrivateKey userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// This is the secondary structure representing the user's personal space. It's UUID is deterministically generated from username
// and filename. The FileUUID field could point to the location of a File struct or location of a Invitation struct. The
// owner field specifies the username of the actual onwer of the file. If the Owner is other than the current user's username, it
// means that the current owner is shared with this file. The DirectlySharedWith field will only be non-nil iff the file's owner
// is the current user.
type FilePointer struct {
	FileUUID           uuid.UUID
	SourceKey          []byte
	Owner              string
	DirectlySharedWith uuid.UUID //--> A serialized map[string] {recipientname: SourceKey for Invitation(16-byte stored as string)}
}

// This is a linkedlist-like struct to wrap around the actual cipher text of the file content. Field names are self-explanatory.
// Notice that all the Tail and TailSourceKey field will only be non-nil iff it's the head of the linked list. However, the Head
// field will be filled in for all of them.
type File struct {
	Ciphertext    uuid.UUID
	Head          uuid.UUID
	Tail          uuid.UUID
	Next          uuid.UUID
	TailSourceKey []byte
}

// This is a struct containing information needed for recipints to access the file. Fields are self-explanatory.
type Invitation struct {
	Owner     string
	Filename  string
	FileUUID  uuid.UUID
	SourceKey []byte
}

// This is the actual invitations passed around users. Location refers to the location of the corresponding Invitation object.
type InvitationAccess struct {
	Location  uuid.UUID
	SourceKey []byte
}

// Some useful Helpers that can be reused
// Serialize an object v and then encrypt-then-hmac, returning the 128-byte content for Datastore and error message
func obj_EncryptThenMac(v interface{}, EncKey []byte, MacKey []byte) (storage []byte, err error) {
	DataSerialized, err := json.Marshal(v)
	DataEncrypted := userlib.SymEnc(EncKey, userlib.RandomBytes(16), DataSerialized)
	DataEncryptedHashed, err := userlib.HMACEval(MacKey, DataEncrypted)
	if err != nil {
		return nil, err
	}
	storage = append(DataEncryptedHashed, DataEncrypted...)
	return storage, nil
}

// Takes in a text content and then encrypt-then-hmac, returning the 128-byte content for Datastore and error message
func text_EncryptThenMac(content []byte, EncKey []byte, MacKey []byte) (storage []byte, err error) {
	DataEncrypted := userlib.SymEnc(EncKey, userlib.RandomBytes(16), content)
	DataEncryptedHashed, err := userlib.HMACEval(MacKey, DataEncrypted)
	if err != nil {
		return nil, err
	}
	storage = append(DataEncryptedHashed, DataEncrypted...)
	return storage, nil
}

// Takes in 128-byte storage read from Datastore, verify-then-decrypt. Updating the object passed in if doesn't run into error.
func obj_VerifyThenDecrypt(storage []byte, EncKey []byte, MacKey []byte, obj interface{}) (err error) {
	DataEncryptedHashed, DataEncrypted := storage[:64], storage[64:]
	ExpectedHash, err := userlib.HMACEval(MacKey, DataEncrypted)
	if !userlib.HMACEqual(DataEncryptedHashed, ExpectedHash) {
		err := errors.New("The data has been tampered.")
		return err
	}
	DataSerialized := userlib.SymDec(EncKey, DataEncrypted)
	err = json.Unmarshal(DataSerialized, obj)
	if err != nil {
		return err
	}
	return nil
}

// Takes in 128-byte storage read from Datastore, verify-then-decrypt. Returning plaintext in if doesn't run into error.
func text_VerifyThenDecrypt(storage []byte, EncKey []byte, MacKey []byte) (plaintext []byte, err error) {
	DataEncryptedHashed, DataEncrypted := storage[:64], storage[64:]
	ExpectedHash, err := userlib.HMACEval(MacKey, DataEncrypted)
	if !userlib.HMACEqual(DataEncryptedHashed, ExpectedHash) {
		err := errors.New("The data has been tampered.")
		return nil, err
	}
	plaintext = userlib.SymDec(EncKey, DataEncrypted)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Encrypt then sign an object. Notice that the signature is the first 256 bytes of the returned bytes.
func EncryptThenSign(v interface{}, sender_Sign_PrivateKey userlib.DSSignKey, recipient_RSA_PublicKey userlib.PKEEncKey) (storage []byte, err error) {
	DataSerialized, err := json.Marshal(v)
	DataEncrypted, err := userlib.PKEEnc(recipient_RSA_PublicKey, DataSerialized)
	if err != nil {
		return nil, err
	}
	signature, err := userlib.DSSign(sender_Sign_PrivateKey, DataEncrypted)
	if err != nil {
		return nil, err
	}
	storage = append(signature, DataEncrypted...)
	return storage, nil
}

// Verify the Signature and decrypt an onject
func VerifySignThenDecrypt(storage []byte, sender_Sign_PublicKey userlib.DSVerifyKey, recipient_RSA_PrivateKey userlib.PKEDecKey, obj interface{}) (err error) {
	signature, DataEncrypted := storage[:256], storage[256:]
	err = userlib.DSVerify(sender_Sign_PublicKey, DataEncrypted, signature)
	if err != nil {
		return err
	}
	DataSerialized, err := userlib.PKEDec(recipient_RSA_PrivateKey, DataEncrypted)
	err = json.Unmarshal(DataSerialized, obj)
	if err != nil {
		return err
	}
	return nil
}

// Get the File info based on secondary structure for users who are shared with a File
func getFileInfo(Location uuid.UUID, InvitationSourceKey []byte) (FileUUID uuid.UUID, FileSourceKey []byte, FileOwner string, err error) {
	EncryptKey, _ := userlib.HashKDF(InvitationSourceKey, []byte("Invitation encryption"))
	InvEncKey, InvMacKey := EncryptKey[:16], EncryptKey[16:32]
	storage, ok := userlib.DatastoreGet(Location)
	if !ok {
		err = errors.New("Invitation not found.")
		return uuid.Nil, nil, "", err
	}
	var newInvitation Invitation
	err = obj_VerifyThenDecrypt(storage, InvEncKey, InvMacKey, &newInvitation)
	if err != nil {
		return uuid.Nil, nil, "", err
	}
	return newInvitation.FileUUID, newInvitation.SourceKey, newInvitation.Owner, nil
}

// load all the content bytes starting from headFileUUID
func LoadContents(headFileUUID uuid.UUID, headFileSourceKey []byte) (content []byte, err error) {
	var headFile File
	headEncryptKey, err := userlib.HashKDF(headFileSourceKey, []byte("File encryption"))
	if err != nil {
		return nil, err
	}
	headfileEncKey, headfileMacKey, ciphEncKey, ciphMacKey := headEncryptKey[:16], headEncryptKey[16:32], headEncryptKey[32:48], headEncryptKey[48:]
	data, ok := userlib.DatastoreGet(headFileUUID)
	if ok {
		err = obj_VerifyThenDecrypt(data, headfileEncKey, headfileMacKey, &headFile)
		if err != nil {
			return nil, err
		}
	} else {
		err = errors.New("File was tempered.")
		return nil, err
	}

	storage, ok := userlib.DatastoreGet(headFile.Ciphertext)
	if !ok {
		err = errors.New("File was tempered.")
		return nil, err
	}
	content, err = text_VerifyThenDecrypt(storage, ciphEncKey, ciphMacKey)
	if err != nil {
		return nil, err
	}

	if headFile.Tail == headFileUUID {
		return content, nil
	} else {
		rest, err := LoadContents(headFile.Next, headfileEncKey)
		if err != nil {
			return nil, err
		}
		return append(content, rest...), nil
	}
}

// Check user struct
func checkUser(username string, password string) (err error) {
	var userdata User
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("Username" + username))[:16])
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		err = errors.New("User data tempered")
		return err
	}
	salt := username
	EncryptKey := userlib.Argon2Key([]byte(password), []byte(salt), 32)
	EncKey := EncryptKey[:16]
	MacKey := EncryptKey[16:]
	err = obj_VerifyThenDecrypt(data, EncKey, MacKey, &userdata)
	if err != nil {
		return err
	}
	if (userdata.Username == username) && userdata.Password == password {
		return nil
	} else {
		err = errors.New("User data tempered")
		return err
	}
}

// check ciphertext integrity
func checkCipher(Ciphertext uuid.UUID, ciphEncKey []byte, ciphMacKey []byte) (err error) {
	storage, ok := userlib.DatastoreGet(Ciphertext)
	if !ok {
		err = errors.New("File was tempered.")
		return err
	}
	DataEncryptedHashed, DataEncrypted := storage[:64], storage[64:]
	ExpectedHash, err := userlib.HMACEval(ciphMacKey, DataEncrypted)
	if !userlib.HMACEqual(DataEncryptedHashed, ExpectedHash) {
		err := errors.New("The data has been tampered.")
		return err
	}
	return nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		err = errors.New("The username is empty.")
		return nil, err
	}
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("Username" + username))[:16])
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		err = errors.New("The username already exists.")
		return nil, err
	}
	var userdata User
	userdata.Username = username
	userdata.Password = password
	RSAPublickey, RSAPrivatekey, err := userlib.PKEKeyGen()
	userdata.RSAPrivatekey = RSAPrivatekey
	err = userlib.KeystoreSet(username+"'s RSAPublickey", RSAPublickey)
	SiganturePrivateKey, SignaturePublicKey, err := userlib.DSKeyGen()
	userdata.SiganturePrivateKey = SiganturePrivateKey
	err = userlib.KeystoreSet(username+"'s SignaturePublicKey", SignaturePublicKey)
	if err != nil {
		return nil, err
	}

	salt := username
	EncryptKey := userlib.Argon2Key([]byte(password), []byte(salt), 32)
	EncKey := EncryptKey[:16]
	MacKey := EncryptKey[16:]
	// userlib.DebugMsg("Original Enc Key: %v", EncKey)
	// userlib.DebugMsg("Original Mac Key: %v", MacKey)
	storage, err := obj_EncryptThenMac(userdata, EncKey, MacKey)
	userlib.DatastoreSet(userUUID, storage)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte("Username" + username))[:16])
	data, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		err = errors.New("The username does not exist")
		return nil, err
	}
	salt := username
	EncryptKey := userlib.Argon2Key([]byte(password), []byte(salt), 32)
	EncKey := EncryptKey[:16]
	MacKey := EncryptKey[16:]
	err = obj_VerifyThenDecrypt(data, EncKey, MacKey, &userdata)
	if err != nil {
		return nil, err
	}
	if (userdata.Username == username) && userdata.Password == password {
		userdataptr = &userdata
		return userdataptr, nil
	} else {
		err = errors.New("The username and password are not correct.")
		return nil, err
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//The address of secondary structure is generated deterministically from filename and username
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	//The keys to the secondary structure is generated deterministically from password and a new salt of filename + usename
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	//Get secondary structure and create if doesn't exist.
	data, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		pointer.FileUUID = uuid.New()
		pointer.SourceKey = userlib.RandomBytes(16)
		pointer.Owner = userdata.Username
		pointer.DirectlySharedWith = uuid.New()
	} else {
		err = obj_VerifyThenDecrypt(data, pointerEncKey, pointerMacKey, &pointer)
		if err != nil {
			return err
		}
	}

	//Get File object and create if doesn't exist
	var newFile File
	var newFileUUID uuid.UUID
	var newFileSourceKey []byte
	if pointer.Owner == userdata.Username {
		newFileUUID = pointer.FileUUID
		newFileSourceKey = pointer.SourceKey
	} else {
		newFileUUID, newFileSourceKey, _, err = getFileInfo(pointer.FileUUID, pointer.SourceKey)
		if err != nil {
			return err
		}
	}
	EncryptKey, _ = userlib.HashKDF(newFileSourceKey, []byte("File encryption"))
	fileEncKey, fileMacKey, ciphEncKey, ciphMacKey := EncryptKey[:16], EncryptKey[16:32], EncryptKey[32:48], EncryptKey[48:]
	data, ok = userlib.DatastoreGet(newFileUUID)
	if ok {
		err = obj_VerifyThenDecrypt(data, fileEncKey, fileMacKey, &newFile)
		if err != nil {
			return err
		}
	} else {
		newFile.Head = newFileUUID
		newFile.Next = uuid.New()
	}

	//Encrypt then store the new content, update corresponding fields of the File object
	newCipherText, err := text_EncryptThenMac(content, ciphEncKey, ciphMacKey)
	newCiphertextUUID := uuid.New()
	userlib.DatastoreSet(newCiphertextUUID, newCipherText)
	newFile.Ciphertext = newCiphertextUUID
	newFile.Tail = newFileUUID
	newFile.TailSourceKey = newFileSourceKey

	//Encrypt and write File object back to Datastore
	fileStorage, err := obj_EncryptThenMac(newFile, fileEncKey, fileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newFileUUID, fileStorage)

	//Encrypt and write secondary structure back to Datastore
	pointerStorage, err := obj_EncryptThenMac(pointer, pointerEncKey, pointerMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pointerAddress, pointerStorage)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//check personal space if the file exists
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	data, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		err = errors.New("The file called " + filename + "doesn't exist in" + userdata.Username + "'s file space.")
		return err
	} else {
		err = obj_VerifyThenDecrypt(data, pointerEncKey, pointerMacKey, &pointer)
		if err != nil {
			return err
		}
	}

	//get the current head File
	var headFile File
	var headFileUUID uuid.UUID
	var headFileSourceKey []byte
	if pointer.Owner == userdata.Username {
		headFileUUID = pointer.FileUUID
		headFileSourceKey = pointer.SourceKey
	} else {
		headFileUUID, headFileSourceKey, _, err = getFileInfo(pointer.FileUUID, pointer.SourceKey)
		if err != nil {
			return err
		}
	}
	headEncryptKey, _ := userlib.HashKDF(headFileSourceKey, []byte("File encryption"))
	headfileEncKey, headfileMacKey, _, _ := headEncryptKey[:16], headEncryptKey[16:32], headEncryptKey[32:48], headEncryptKey[48:]
	data, ok = userlib.DatastoreGet(headFileUUID)
	if ok {
		err = obj_VerifyThenDecrypt(data, headfileEncKey, headfileMacKey, &headFile)
		if err != nil {
			return err
		}
	} else {
		err = errors.New("Can't locate File head in Dataset.")
		return err
	}
	// err = checkCipher(headFile.Ciphertext, headciphEncKey, headciphMacKey)
	// if err != nil {
	// 	return err
	// }
	currentTailUUID, curretTailSourceKey := headFile.Tail, headFile.TailSourceKey

	//get the current tail File
	var tailFile File
	tailEncryptKey, _ := userlib.HashKDF(curretTailSourceKey, []byte("File encryption"))
	tailfileEncKey, tailfileMacKey, _, _ := tailEncryptKey[:16], tailEncryptKey[16:32], tailEncryptKey[32:48], tailEncryptKey[48:]
	data, ok = userlib.DatastoreGet(currentTailUUID)
	if ok {
		err = obj_VerifyThenDecrypt(data, tailfileEncKey, tailfileMacKey, &tailFile)
		if err != nil {
			return err
		}
	} else {
		err = errors.New("Can't locate File tail in Dataset.")
		return err
	}
	// err = checkCipher(tailFile.Ciphertext, tailciphEncKey, tailciphMacKey)
	// if err != nil {
	// 	return err
	// }
	newTailUUID := tailFile.Next
	newTailSourceKey := tailfileEncKey

	//update current tail and write back to memory
	tailFile.Tail = uuid.Nil
	tailFile.TailSourceKey = nil
	fileStorage, err := obj_EncryptThenMac(tailFile, tailfileEncKey, tailfileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(currentTailUUID, fileStorage)

	//create new File struct and update correspoing fields
	var newTailFile File
	newtailEncryptKey, _ := userlib.HashKDF(newTailSourceKey, []byte("File encryption"))
	newtailfileEncKey, newtailfileMacKey, newtailciphEncKey, newtailciphMacKey := newtailEncryptKey[:16], newtailEncryptKey[16:32], newtailEncryptKey[32:48], newtailEncryptKey[48:]
	newTailFile.Head = tailFile.Head
	newTailFile.Tail = newTailUUID
	newTailFile.TailSourceKey = newTailSourceKey
	newTailFile.Next = uuid.New()

	//get ciphertext and write to memory
	newCipherText, err := text_EncryptThenMac(content, newtailciphEncKey, newtailciphMacKey)
	if err != nil {
		return err
	}
	newCiphertextUUID := uuid.New()
	newTailFile.Ciphertext = newCiphertextUUID
	userlib.DatastoreSet(newCiphertextUUID, newCipherText)

	fileStorage, err = obj_EncryptThenMac(newTailFile, newtailfileEncKey, newtailfileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newTailUUID, fileStorage)

	//update fields for the corrent head
	headFile.Tail = newTailUUID
	headFile.TailSourceKey = newTailSourceKey
	fileStorage, err = obj_EncryptThenMac(headFile, headfileEncKey, headfileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(headFileUUID, fileStorage)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}

	// check personal space if the file exists
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	data, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		err = errors.New("The file called " + filename + "doesn't exist in" + userdata.Username + "'s file space.")
		return nil, err
	} else {
		err = obj_VerifyThenDecrypt(data, pointerEncKey, pointerMacKey, &pointer)
		if err != nil {
			return nil, err
		}
	}

	// get the current head File
	var headFileUUID uuid.UUID
	var headFileSourceKey []byte
	if pointer.Owner == userdata.Username {
		headFileUUID = pointer.FileUUID
		headFileSourceKey = pointer.SourceKey
	} else {
		headFileUUID, headFileSourceKey, _, err = getFileInfo(pointer.FileUUID, pointer.SourceKey)
		if err != nil {
			return nil, err
		}
	}

	// pass to helper method
	content, err = LoadContents(headFileUUID, headFileSourceKey)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}

	//The address of secondary structure is generated deterministically from filename and username
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	//The keys to the secondary structure is generated deterministically from password and a new salt of filename + usename
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	//Get secondary structure and error if doesn't exist.
	data, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		err = errors.New("The file called " + filename + "doesn't exist in" + userdata.Username + "'s file space.")
		return uuid.Nil, err
	} else {
		err = obj_VerifyThenDecrypt(data, pointerEncKey, pointerMacKey, &pointer)
		if err != nil {
			return uuid.Nil, err
		}
	}

	//check if the recipient exists
	recipientUUID, err := uuid.FromBytes(userlib.Hash([]byte("Username" + recipientUsername))[:16])
	_, ok = userlib.DatastoreGet(recipientUUID)
	if !ok {
		err = errors.New("The recipient doesn't exist.")
		return uuid.Nil, err
	}

	//Handle the case for non_owner sharing
	if pointer.Owner != userdata.Username {
		var newInvitationAccess InvitationAccess
		newInvitationAccess.Location, newInvitationAccess.SourceKey = pointer.FileUUID, pointer.SourceKey
		newInvitationAccessAddress := uuid.New()

		recipient_RSA_PublicKey, ok := userlib.KeystoreGet(recipientUsername + "'s RSAPublickey")
		if !ok {
			err = errors.New("Can't access recipient's RSA Public Key.")
			return uuid.Nil, err
		}
		sender_Sign_Privatekey := userdata.SiganturePrivateKey

		storage, err := EncryptThenSign(newInvitationAccess, sender_Sign_Privatekey, recipient_RSA_PublicKey)
		userlib.DatastoreSet(newInvitationAccessAddress, storage)

		if err != nil {
			return uuid.Nil, err
		}
		return newInvitationAccessAddress, nil
	}

	//Create new invitation object and write to Datastore
	var newInvitation Invitation
	newInvitation.Owner = userdata.Username
	newInvitation.Filename = filename
	newInvitation.FileUUID = pointer.FileUUID
	newInvitation.SourceKey = pointer.SourceKey
	message := userdata.Username + "To" + recipientUsername + "On" + filename
	newInvitationAddress, err := uuid.FromBytes(userlib.Hash([]byte(message))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	InvitationSourceKey := userlib.RandomBytes(16)
	EncryptKey, _ = userlib.HashKDF(InvitationSourceKey, []byte("Invitation encryption")) //Generate keys for the newInvitation object
	InvEncKey, InvMacKey := EncryptKey[:16], EncryptKey[16:32]
	storage, err := obj_EncryptThenMac(newInvitation, InvEncKey, InvMacKey)
	userlib.DatastoreSet(newInvitationAddress, storage)

	//update the DirectlySharedWith field of the shared file
	var SharedMap map[string][]byte
	EncryptKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username+filename+"SharedMap"), 32) //Genrate keys for the ShareMap
	SharedMapEncKey := EncryptKey[:16]
	SharedMapMacKey := EncryptKey[16:]
	data, ok = userlib.DatastoreGet(pointer.DirectlySharedWith)
	if !ok {
		SharedMap = make(map[string][]byte)
	} else {
		err = obj_VerifyThenDecrypt(data, SharedMapEncKey, SharedMapMacKey, &SharedMap)
		if err != nil {
			return uuid.Nil, err
		}
	}
	SharedMap[recipientUsername] = InvitationSourceKey
	storage, err = obj_EncryptThenMac(SharedMap, SharedMapEncKey, SharedMapMacKey)
	userlib.DatastoreSet(pointer.DirectlySharedWith, storage)
	// userlib.DebugMsg("Print invitation map:", SharedMap)

	//Create new InvitationAccess object and return
	var newInvitationAccess InvitationAccess
	newInvitationAccess.Location = newInvitationAddress
	newInvitationAccess.SourceKey = InvitationSourceKey
	newInvitationAccessAddress := uuid.New()

	recipient_RSA_PublicKey, ok := userlib.KeystoreGet(recipientUsername + "'s RSAPublickey")
	if !ok {
		err = errors.New("Can't access recipient's RSA Public Key.")
		return uuid.Nil, err
	}
	sender_Sign_Privatekey := userdata.SiganturePrivateKey

	storage, err = EncryptThenSign(newInvitationAccess, sender_Sign_Privatekey, recipient_RSA_PublicKey)
	userlib.DatastoreSet(newInvitationAccessAddress, storage)

	if err != nil {
		return uuid.Nil, err
	}
	return newInvitationAccessAddress, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//Check the recipient's personal space
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	_, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		pointer.DirectlySharedWith = uuid.Nil
	} else {
		err = errors.New("The file " + filename + " already exists in " + userdata.Username + "'s personal space")
		return err
	}

	//Get the InvitatonAccess struct
	storage, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New("There's no such invitation.")
		return err
	}
	sender_Sign_PublicKey, ok := userlib.KeystoreGet(senderUsername + "'s SignaturePublicKey")
	if !ok {
		err = errors.New("Can't access sender's Signature Public Key.")
		return err
	}
	recipient_RSA_Privatekey := userdata.RSAPrivatekey

	var invitationAccess InvitationAccess
	err = VerifySignThenDecrypt(storage, sender_Sign_PublicKey, recipient_RSA_Privatekey, &invitationAccess)
	if err != nil {
		return err
	}

	//Get the Invitation struct information
	_, _, FileOwner, err := getFileInfo(invitationAccess.Location, invitationAccess.SourceKey)
	if err != nil {
		return err
	}

	//Add file to personal space and update sorrecponding fields
	pointer.FileUUID = invitationAccess.Location
	pointer.SourceKey = invitationAccess.SourceKey
	pointer.Owner = FileOwner
	pointerStorage, err := obj_EncryptThenMac(pointer, pointerEncKey, pointerMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pointerAddress, pointerStorage)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	//check User integrity
	err = checkUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	//check personal space and verify is owner
	pointerAddress, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	EncryptKey := userlib.Argon2Key([]byte(userdata.Password), []byte(filename+userdata.Username), 32)
	pointerEncKey := EncryptKey[:16]
	pointerMacKey := EncryptKey[16:]
	data, ok := userlib.DatastoreGet(pointerAddress)
	var pointer FilePointer
	if !ok {
		err = errors.New("The file " + filename + "doesn't exist in " + userdata.Username + "'s personal space")
		return err
	} else {
		err = obj_VerifyThenDecrypt(data, pointerEncKey, pointerMacKey, &pointer)
		if err != nil {
			return err
		}
	}
	if pointer.Owner != userdata.Username {
		err = errors.New(userdata.Username + "isn't the owner of the file" + filename)
	}

	//check if the recipient exists
	recipientUUID, err := uuid.FromBytes(userlib.Hash([]byte("Username" + recipientUsername))[:16])
	_, ok = userlib.DatastoreGet(recipientUUID)
	if !ok {
		err = errors.New("The recipient" + recipientUsername + "doesn't exist.")
		return err
	}
	//check sharedmap for recipient
	EncryptKey = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username+filename+"SharedMap"), 32) //Genrate keys for the ShareMap
	SharedMapEncKey := EncryptKey[:16]
	SharedMapMacKey := EncryptKey[16:]
	data, ok = userlib.DatastoreGet(pointer.DirectlySharedWith)
	var SharedMap map[string][]byte
	if !ok {
		err = errors.New("The Sharing map was tempered.")
		return err
	} else {
		err = obj_VerifyThenDecrypt(data, SharedMapEncKey, SharedMapMacKey, &SharedMap)
		if err != nil {
			return err
		}
	}

	_, ok = SharedMap[recipientUsername]
	if !ok {
		err = errors.New("The file" + filename + "isn't directly shared with" + recipientUsername)
		return err
	}

	//delete Invitation object for revoked user
	message := userdata.Username + "To" + recipientUsername + "On" + filename
	InvitationAddress, err := uuid.FromBytes(userlib.Hash([]byte(message))[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(InvitationAddress)

	//Update SharedMap and store
	delete(SharedMap, recipientUsername)
	storage, err := obj_EncryptThenMac(SharedMap, SharedMapEncKey, SharedMapMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pointer.DirectlySharedWith, storage)
	//Load file
	content, err := userdata.LoadFile(filename)

	//Generate new address and key for the file
	pointer.FileUUID = uuid.New()
	pointer.SourceKey = userlib.RandomBytes(16)

	//Create the new File object
	var newFile File
	var newFileUUID uuid.UUID
	var newFileSourceKey []byte
	newFileUUID = pointer.FileUUID
	newFileSourceKey = pointer.SourceKey

	EncryptKey, _ = userlib.HashKDF(newFileSourceKey, []byte("File encryption"))
	fileEncKey, fileMacKey, ciphEncKey, ciphMacKey := EncryptKey[:16], EncryptKey[16:32], EncryptKey[32:48], EncryptKey[48:]
	data, ok = userlib.DatastoreGet(newFileUUID)

	newFile.Head = newFileUUID
	newFile.Next = uuid.New()

	//Encrypt then store the new content, update corresponding fields of the File object
	newCipherText, err := text_EncryptThenMac(content, ciphEncKey, ciphMacKey)
	newCiphertextUUID := uuid.New()
	userlib.DatastoreSet(newCiphertextUUID, newCipherText)
	newFile.Ciphertext = newCiphertextUUID
	newFile.Tail = newFileUUID
	newFile.TailSourceKey = newFileSourceKey

	//Encrypt and write File object back to Datastore
	fileStorage, err := obj_EncryptThenMac(newFile, fileEncKey, fileMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newFileUUID, fileStorage)

	//Encrypt and write secondary structure back to Datastore
	pointerStorage, err := obj_EncryptThenMac(pointer, pointerEncKey, pointerMacKey)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pointerAddress, pointerStorage)
	//Update information for other users
	for recipient, InvitationSourceKey := range SharedMap {
		message := userdata.Username + "To" + recipient + "On" + filename
		Location, err := uuid.FromBytes(userlib.Hash([]byte(message))[:16])
		if err != nil {
			return err
		}
		EncryptKey, _ := userlib.HashKDF(InvitationSourceKey, []byte("Invitation encryption"))
		InvEncKey, InvMacKey := EncryptKey[:16], EncryptKey[16:32]
		storage, ok := userlib.DatastoreGet(Location)
		if !ok {
			err = errors.New("Invitation not found.")
			return err
		}
		var newInvitation Invitation
		err = obj_VerifyThenDecrypt(storage, InvEncKey, InvMacKey, &newInvitation)
		if err != nil {
			return err
		}
		newInvitation.FileUUID = newFileUUID
		newInvitation.SourceKey = newFileSourceKey
		storage, err = obj_EncryptThenMac(newInvitation, InvEncKey, InvMacKey)
		userlib.DatastoreSet(Location, storage)
	}
	return nil
}
