package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"fmt"

	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

func measureBandwidth(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

func content_match(b string, a string) (ok bool) {
	return a == b
}

func uuid_match(b userlib.UUID, a userlib.UUID) (ok bool) {
	return a == b
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Self-written tests", func() {
		Specify("Empty username & existing username", func() {
			userlib.DebugMsg("Initializing user with an empty name.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with an existing name.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("no initialized user & invalid credentials", func() {
			userlib.DebugMsg("Getting initialized user.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get Alice with wrong password.")
			alice, err = client.GetUser("alice", "1234")
			Expect(err).ToNot(BeNil())

		})

		Specify("no initialized user & invalid credentials", func() {
			userlib.DebugMsg("Getting initialized user.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Get Alice with wrong password.")
			alice, err = client.GetUser("alice", "1234")
			Expect(err).ToNot(BeNil())

		})

		Specify("File not created or overwritten", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob storing file with the same name %s with content: %s", aliceFile, contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob shares file with the same name")
			invite1, err := bob.CreateInvitation(aliceFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepts the file.")
			err = alice.AcceptInvitation("bob", invite1, aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Multiple Sessions appending to file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("AlicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		})

		Specify("Multiple Sessions storing file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'alice'.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceDesktop storing file %s with content: %s", aliceFile, contentTwo)
			err = aliceDesktop.StoreFile("aliceDesktop", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("AlicePhone storing file %s with content: %s", aliceFile, contentThree)
			err = alicePhone.StoreFile("alicePhone", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alice.LoadFile("aliceDesktop")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile("alicePhone")
			Expect(data).To(Equal([]byte(contentThree)))

		})

		Specify("Loading nonexistent file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loading non-existent file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

		})

		Specify("Appending to nonexistent file or append not successful", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to non-existent file.")
			err = alice.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to existent file.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

		})

		Specify("Invalid Invitation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sending to non-existent user.")
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice sending non-existent file.")
			_, err = alice.CreateInvitation(bobFile, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("Invalid accept invitation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sending an invitation to Bob.")
			invitationUUID, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob errors when trying to accept.")
			err = bob.AcceptInvitation("alice", invitationUUID, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revokes the invitation to Bob.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob errors when trying to accept.")
			err = bob.AcceptInvitation("alice", invitationUUID, aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Invalid revocation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", charlesFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sending an invitation to Bob.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes a file that Alice does not own.")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revokes a file that Alice does not share with the recipient.")
			err = alice.RevokeAccess(charlesFile, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("Checking that invitations are successful", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sending an invitation to Bob.")
			invitationUUID, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invitation.")
			err = bob.AcceptInvitation("alice", invitationUUID, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loads the file.")
			bobloaded, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(bobloaded).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob appends to the file.")
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loads the file.")
			aliceloaded, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(aliceloaded).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Alice appends to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loads the file.")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Alice revokes the invitation to Bob.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob fails to load the file.")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		// Specify("Checking that revocations are successful", func() {
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Initializing user Bob.")
		// 	bob, err = client.InitUser("bob", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Initializing user Charlie.")
		// 	charlie, err := client.InitUser("charlie", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Initializing user Den.")
		// 	den, err := client.InitUser("den", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Initializing user Eve.")
		// 	eve, err := client.InitUser("eve", defaultPassword)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		// 	err = alice.StoreFile(aliceFile, []byte(contentOne))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Alice sending an invitation to Bob.")
		// 	invitationUUID, err := alice.CreateInvitation(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Bob fails to share the file with Den.")
		// 	_, err = bob.CreateInvitation(bobFile, "den")
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Bob accepts invitation.")
		// 	err = bob.AcceptInvitation("alice", invitationUUID, aliceFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Bob shares the file with Den.")
		// 	invitationUUID3, err := bob.CreateInvitation(aliceFile, "den")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Den accepts invitation.")
		// 	err = den.AcceptInvitation("bob", invitationUUID3, bobFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Alice sending an invitation to Charlie.")
		// 	invitationUUID2, err := alice.CreateInvitation(aliceFile, "charlie")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Charlie accepts invitation.")
		// 	err = charlie.AcceptInvitation("alice", invitationUUID2, aliceFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Charlie shares the file with Eve.")
		// 	invitationUUID4, err := charlie.CreateInvitation(aliceFile, "eve")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Eve accepts invitation.")
		// 	err = eve.AcceptInvitation("charlie", invitationUUID4, aliceFile)
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Alice revokes the invitation to Bob.")
		// 	err = alice.RevokeAccess(aliceFile, "bob")
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Bob fails to load the file.")
		// 	_, err = bob.LoadFile(aliceFile)
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Den fails to load the file.")
		// 	_, err = den.LoadFile(aliceFile)
		// 	Expect(err).ToNot(BeNil())

		// 	userlib.DebugMsg("Charlie still loads the file.")
		// 	data, err := charlie.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data).To(Equal([]byte(contentOne)))

		// 	userlib.DebugMsg("Eve still loads the file.")
		// 	data2, err := charlie.LoadFile(aliceFile)
		// 	Expect(err).To(BeNil())
		// 	Expect(data2).To(Equal([]byte(contentOne)))

		// })

		Specify("Checking that append is efficient", func() {

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			contentLarge := userlib.RandomBytes(1048576)
			aliceFile1 := "aliceFile1.txt"
			aliceFile2 := "aliceFile2.txt"

			userlib.DebugMsg("Alice storing small file %s with content: %s", aliceFile1, contentOne)
			err = alice.StoreFile(aliceFile1, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing large file %s with Large content", aliceFile2)
			err = alice.StoreFile(aliceFile2, contentLarge)
			Expect(err).To(BeNil())

			t1 := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to small file %s with content: %s", aliceFile1, contentTwo)
				err = alice.AppendToFile(aliceFile1, []byte(contentTwo))
				Expect(err).To(BeNil())

			})

			t2 := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to Large file %s with content: %s", aliceFile2, contentTwo)
				err = alice.AppendToFile(aliceFile2, []byte(contentTwo))
				Expect(err).To(BeNil())
			})

			if t1 != t2 {
				err = fmt.Errorf("not efficient enough")
			}
			Expect(err).To(BeNil())

		})

		Specify("Username sensitive", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

		})

		Specify("Password Validity", func() {
			userlib.DebugMsg("Password of length zero.")
			alice, err = client.InitUser("Alice", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Duplicate password.")
			alice, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

		})

		Specify("Constant number of public keys", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			n1 := len(userlib.KeystoreGetMap())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			n2 := len(userlib.KeystoreGetMap())
			Expect(n1).ToNot(Equal(n2))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			n3 := len(userlib.KeystoreGetMap())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = alice.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			n4 := len(userlib.KeystoreGetMap())
			Expect(n3).To(Equal(n4))

			contentLarge := userlib.RandomBytes(1048576)
			aliceFile2 := "aliceFile2.txt"
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile2, contentLarge)
			err = alice.StoreFile(aliceFile2, []byte(contentLarge))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile2, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile2)
			err = bob.AcceptInvitation("alice", invite, aliceFile2)
			Expect(err).To(BeNil())

			n5 := len(userlib.KeystoreGetMap())
			Expect(n5).To(Equal(n4))

		})

		Specify("Integrity of user struct", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var set map[uuid.UUID][]byte
			set = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				set[i] = v
			}
		})

		Specify("Integrity of user struct", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var set map[uuid.UUID][]byte
			set = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				set[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, set[i])

			}

			userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Integrity of storing", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var set map[uuid.UUID][]byte
			set = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				set[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, set[i])

			}

			userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Integrity of appending", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice append to file %s with content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			var set map[uuid.UUID][]byte
			set = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				set[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, set[i])

			}

			userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Integrity of Creating Sharing", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice append to file %s with content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			var set map[uuid.UUID][]byte
			set = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				set[i] = v
			}

			userlib.DebugMsg("Alice shares the file %s with user: %s", aliceFile, "bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			var changes map[uuid.UUID][]byte
			changes = make(map[uuid.UUID][]byte)
			for i, v := range userlib.DatastoreGetMap() {
				if set[i] == nil {
					changes[i] = v
				}
			}

			fmt.Println(len(changes))

			for i, v := range changes {
				userlib.DatastoreSet(i, userlib.RandomBytes(len(v)))

			}

			userlib.DebugMsg("Checking that if Bob can find the attack when accepting invitation.")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if Alice can find the attack when revoking Bob's Access.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

		})
	})

	Specify("Additional Test: integrity and confidentiality of sharing invitations.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		var ori_ori_res map[uuid.UUID][]byte
		ori_ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		var fileReleventuuid []uuid.UUID
		var fileReleventcontent []string
		for i, v := range ori_res {
			_, flag := ori_ori_res[i]
			if flag {
				continue
			} else {
				fileReleventuuid = append(fileReleventuuid, i)
				fileReleventcontent = append(fileReleventcontent, string(v))
			}
		}

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}
		//fmt.Println("*************************************************")
		//fmt.Println(len(res) - len(ori_res))
		//fmt.Println("*************************************************")
		userlib.DebugMsg("Checking confidentiality")
		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				ok := content_match("bob", string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(contentOne, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(aliceFile, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				for _, v2 := range fileReleventuuid {
					ok = content_match(v2.String(), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				for _, v2 := range fileReleventcontent {
					ok = content_match(v2, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				Expect(err).To(BeNil())
			}
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				fmt.Println(len(res))
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("Additional Test: integrity and confidentiality of file content.", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				err = nil
				ok := content_match(contentOne, string(v))
				if ok {
					//fmt.Println(string(v))
					err = fmt.Errorf("no confidentiality")
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					//fmt.Println(string(v))
					err = fmt.Errorf("no confidentiality")
				}
				ok = content_match(aliceFile, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				Expect(err).To(BeNil())
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])

				userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
				_, err = alice.LoadFile(aliceFile)
				Expect(err).ToNot(BeNil())

				userlib.DatastoreSet(i, v)
			}
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
		_, err = alice.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
		err = alice.AppendToFile(aliceFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
		err = alice.StoreFile(aliceFile, []byte(contentThree))
		Expect(err).ToNot(BeNil())

		for i, v := range ori_res {
			res[i] = userlib.RandomBytes(len(v))
			userlib.DatastoreSet(i, res[i])
		}

		userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
		_, err = alice.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
		err = alice.AppendToFile(aliceFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
		err = alice.StoreFile(aliceFile, []byte(contentThree))
		Expect(err).ToNot(BeNil())
	})

	Specify("Additional Test: integrity and confidentiality of sharing invitations.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		var ori_ori_res map[uuid.UUID][]byte
		ori_ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		var fileReleventuuid []uuid.UUID
		var fileReleventcontent []string
		for i, v := range ori_res {
			_, flag := ori_ori_res[i]
			if flag {
				continue
			} else {
				fileReleventuuid = append(fileReleventuuid, i)
				fileReleventcontent = append(fileReleventcontent, string(v))
			}
		}

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}
		//fmt.Println("*************************************************")
		//fmt.Println(len(res) - len(ori_res))
		//fmt.Println("*************************************************")
		userlib.DebugMsg("Checking confidentiality")
		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				ok := content_match("bob", string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(contentOne, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(aliceFile, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				for _, v2 := range fileReleventuuid {
					ok = content_match(v2.String(), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				for _, v2 := range fileReleventcontent {
					ok = content_match(v2, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				Expect(err).To(BeNil())
			}
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				fmt.Println(len(res))
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("Additional Test: integrity and confidentiality of file content.", func() {
		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		err = alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				err = nil
				ok := content_match(contentOne, string(v))
				if ok {
					//fmt.Println(string(v))
					err = fmt.Errorf("no confidentiality")
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					//fmt.Println(string(v))
					err = fmt.Errorf("no confidentiality")
				}
				ok = content_match(aliceFile, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				Expect(err).To(BeNil())
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])

				userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
				_, err = alice.LoadFile(aliceFile)
				Expect(err).ToNot(BeNil())

				userlib.DatastoreSet(i, v)
			}
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
		_, err = alice.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
		err = alice.AppendToFile(aliceFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
		err = alice.StoreFile(aliceFile, []byte(contentThree))
		Expect(err).ToNot(BeNil())

		for i, v := range ori_res {
			res[i] = userlib.RandomBytes(len(v))
			userlib.DatastoreSet(i, res[i])
		}

		userlib.DebugMsg("Checking that if Alice can find the changes by loading.")
		_, err = alice.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by appending.")
		err = alice.AppendToFile(aliceFile, []byte(contentTwo))
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Checking that if Alice can find the changes by storing.")
		err = alice.StoreFile(aliceFile, []byte(contentThree))
		Expect(err).ToNot(BeNil())
	})

	Specify("Additional Test: integrity and confidentiality of sharing invitations.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		var ori_ori_res map[uuid.UUID][]byte
		ori_ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		var fileReleventuuid []uuid.UUID
		var fileReleventcontent []string
		for i, v := range ori_res {
			_, flag := ori_ori_res[i]
			if flag {
				continue
			} else {
				fileReleventuuid = append(fileReleventuuid, i)
				fileReleventcontent = append(fileReleventcontent, string(v))
			}
		}

		userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}
		//fmt.Println("*************************************************")
		//fmt.Println(len(res) - len(ori_res))
		//fmt.Println("*************************************************")
		userlib.DebugMsg("Checking confidentiality")
		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				ok := content_match("bob", string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(contentOne, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(contentOne))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(aliceFile, string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				ok = content_match(string(userlib.Hash([]byte(aliceFile))), string(v))
				if ok {
					err = fmt.Errorf("no confidentiality")
					break
				}
				for _, v2 := range fileReleventuuid {
					ok = content_match(v2.String(), string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				for _, v2 := range fileReleventcontent {
					ok = content_match(v2, string(v))
					if ok {
						err = fmt.Errorf("no confidentiality")
						break
					}
				}
				Expect(err).To(BeNil())
			}
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				fmt.Println(len(res))
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		err = bob.AcceptInvitation("alice", invite, bobFile)
		Expect(err).ToNot(BeNil())
	})

	Specify("Additional Test: duplicate invitation revocations.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Alice creating invite for Bob.")
		_, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

	})

	Specify("Additional Test: integrity of revoking invitations.", func() {

		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		var ori_ori_res map[uuid.UUID][]byte
		ori_ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_ori_res[i] = v
		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		userlib.DebugMsg("alice creating invite for Bob.")
		_, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			res[i] = v
		}

		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				fmt.Println(len(res))
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("alice creating invite for Bob.")
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile)
		err = bob.AcceptInvitation("alice", invite, aliceFile)
		Expect(err).ToNot(BeNil())

		var new_res map[uuid.UUID][]byte
		new_res = make(map[uuid.UUID][]byte)
		for i, v := range new_res {
			_, flag := res[i]
			if flag {
				continue
			} else {
				fmt.Println(len(res))
				res[i] = userlib.RandomBytes(len(v))
				userlib.DatastoreSet(i, res[i])
			}
		}

		userlib.DebugMsg("Check whether Alice can find the error while revoking access.")
		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).ToNot(BeNil())

	})

	Specify("Additional Test: confidentiality of file content and location after revoking invitations.", func() {
		userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		var ori_ori_res map[uuid.UUID][]byte
		ori_ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_ori_res[i] = v

		}

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		var fileReleventuuid []uuid.UUID
		var fileReleventcontent []string
		for i, v := range ori_res {
			_, flag := ori_ori_res[i]
			if flag {
				continue
			} else {
				fileReleventuuid = append(fileReleventuuid, i)
				fileReleventcontent = append(fileReleventcontent, string(v))
			}
		}

		userlib.DebugMsg("alice creating invite for Bob.")
		invite, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", aliceFile)
		err = bob.AcceptInvitation("alice", invite, aliceFile)
		Expect(err).To(BeNil())

		//fmt.Println("*************************************************")
		//fmt.Println(len(res) - len(ori_res))
		//fmt.Println("*************************************************")
		var newFileReleventuuid []uuid.UUID
		var newFileReleventcontent []string
		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		userlib.DebugMsg("Checking confidentiality")
		for i, v := range res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {

				ok := uuid_match(i, invite)
				if ok {
					err = fmt.Errorf("invitation uuid not destroyed")
					break
				}

				newFileReleventuuid = append(newFileReleventuuid, i)
				newFileReleventcontent = append(newFileReleventcontent, string(v))

			}
		}

		userlib.DebugMsg("Alice revokes access.")
		err = alice.RevokeAccess(aliceFile, "bob")
		Expect(err).To(BeNil())

		var new_res map[uuid.UUID][]byte
		new_res = make(map[uuid.UUID][]byte)
		userlib.DebugMsg("Checking confidentiality")

		for i, v := range new_res {
			_, flag := ori_res[i]
			if flag {
				continue
			} else {
				for _, v2 := range newFileReleventuuid {
					ok := content_match(v2.String(), string(v))
					if ok {
						err = fmt.Errorf("File information not confidential after revocation.")
						break
					}
				}

			}
		}

	})

	Specify("Additional Test: integrity and confidentiality of sharing tree.", func() {

		userlib.DebugMsg("Initializing users Alice")
		alice, err = client.InitUser("alice", defaultPassword)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Initializing users Bob")
		bob, err = client.InitUser("bob", defaultPassword)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Initializing users charles")
		charles, err = client.InitUser("charles", defaultPassword)
		Expect(err).To(BeNil())

		userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
		alice.StoreFile(aliceFile, []byte(contentOne))

		userlib.DebugMsg("Charles storing file %s with content: %s", charlesFile, contentOne)
		charles.StoreFile(charlesFile, []byte(contentOne))

		var ori_res map[uuid.UUID][]byte
		ori_res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			ori_res[i] = v
		}

		userlib.DebugMsg("Initializing file_sharing tree.")
		userlib.DebugMsg("Alice creating invite for Bob for file %s, and accepting invite under name %s.",
			aliceFile, bobFile)

		invite1, err := alice.CreateInvitation(aliceFile, "bob")
		Expect(err).To(BeNil())

		invite2, err := charles.CreateInvitation(charlesFile, "alice")
		Expect(err).To(BeNil())

		var res map[uuid.UUID][]byte
		res = make(map[uuid.UUID][]byte)
		for i, v := range userlib.DatastoreGetMap() {
			_, flag := ori_res[i]
			if !flag {
				res[i] = v
			}
		}

		userlib.DebugMsg("bob cant verify that the secure file share invitation pointed to by the given invitationPtr was created by senderUsername.")
		userlib.DebugMsg("Wrong invitaion(not for you).")
		err = bob.AcceptInvitation("charles", invite2, bobFile)
		Expect(err).ToNot(BeNil())

		userlib.DebugMsg("Wrong signature(for you but wrong senderusername).")
		err = bob.AcceptInvitation("charles", invite1, bobFile)
		Expect(err).ToNot(BeNil())

	})

})
