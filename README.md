# Encrypted-File-Sharing-System

This projects implements a client application for a secure file sharing system in **Golang**. It is similar to Dropbox, but secured with cryptography so that the server cannot view or tamper with your data. The client will be able to do the following: 


1. Authenticate with a username and password;
2. Save files to the server;
3. Load saved files from the server;
4. Overwrite saved files on the server;
5. Append to saved files on the server;
6. Share saved files with other users; and
7. Revoke access to previously shared files.

## System Design 

### Data structures 

We defined five structs: user, file, filePointer, invitation, and invitationAccess.

![User](https://github.com/Xiaowen2024/Encrypted-File-Sharing-System/blob/main/graphs/user.png)
![Invitation](https://github.com/Xiaowen2024/Encrypted-File-Sharing-System/blob/main/graphs/invitation.png)
![InvitationAccess](https://github.com/Xiaowen2024/Encrypted-File-Sharing-System/blob/main/graphs/invitationAccess.png)
![FilePointer](https://github.com/Xiaowen2024/Encrypted-File-Sharing-System/blob/main/graphs/filepointer.png)

### User Authentication
For each user, we will create a user struct that contains:
1. Username
2. Password
3. RSA private key (stored in Keystore as username+"'s RSAPublickey")
4. Signature private key (stored in Keystore as username+"'s SignaturePublicKey")
When we initialize a user, we first check if the username is valid. Then we generate the users’
RSA key pairs with the PKEKeyGen() function and generate the users’ Signature key pairs with
the DSKeyGen() function. Then we assign keys generated to the variable RSA private key and
Signature private key. To encrypt and mac the user struct, we generate two keys using the
Password-Based Key Derivation Function. The salt used in the function is the username itself.
Last, we will put the encrypted user struct in the datastore. The uuid of the entry in datastore is
generated from the username. To authenticate a user, we first check if the username and the
corresponding uuid exists in the datastore. Then we put the username and the salt (the username
itself) into the Password-Based Key Derivation Function. We will then use the derived
encryption and mac keys to verify and decrypt the user struct. Once encrypted, we will check the
username and password. Once confirmed to be the same, we will return the pointer to the
decrypted user data.
To ensure that a user can have multiple client instances, we make sure that the user struct is static
so that different instances will be synchronous and will not interfere with each other.

### File Storage and Retrieval
To store and retrieve files, we will create two structs filePointer struct and file struct. The file
pointer struct stores fileUUID, source key for the file, owner of the file, and a UUID that points
to a map that contains recipient name and source key pair for each invitation sent. The file struct
contains a uuid that stores the ciphertext, a uuid that stores the head of the file, a uuid that stores
the tail of the file, a uuid that stores the next part of this file if anything is appended to the file,
and lastly the source key to decrypt the tail of file. To store a file, we first need to check the
integrity of the user, which is implemented by a helper function. Then we will generate a
secondary structure whose address is generated deterministically from filename and username.
The keys to the secondary structure are generated deterministically from password and a new salt
of filename and username. Check whether the file pointer already exists, if not, create a new one.
Then create a file object. If there exists a file object whose owner is the same as the given user,
update the uuid and source key of the new file. Next, we will get two file description keys derived from the Hash-Based Key Derivation Function. We can use the keys to decrypt existing files with the same name, if there’s any. Then we will either update uuid, ciphertext, tail, tail source attributes of the file (create new attributes if they didn’t already exist). Lastly, we will
encrypt the file struct and the secondary structure and store them in the datastore. When a user
wants to retrieve the file from the server, we first check the integrity of the user and whether the
file exists. Then we will get the address of the file pointer and put the decrypted file struct in the
file pointer. Then we will get the current head file and get the head file content and return it. To
efficiently append to the file, we create a structure similar to a linked list, where we first store the
head of the file and store the position of head and tail. Then when we append to the file, we
create the appended content as a new file and store it at the tail of the original file. We also
update the tail of the file and the source key of the tail so that when we want to decrypt the file, it
will be very efficient.

### File Sharing and Revocation
How will a user share files with another user? How does this shared user access the shared file
after accepting the invitation? How will a user revoke a different user’s access to a file? How
will you ensure a revoked user cannot take any malicious actions on a file?
To share a file with another user, we first need to create an invitation and an invitation access
struct. After checking the user's integrity and the validity of owner and recipient, we create an
object object which stores the owner of the file, filename, file uuid, and source key of the file.
Then we generate a random invitation source key and use Hash-Based Key Derivation Function
to derive keys to encrypt the file and put them in the datastore. For the shared file, we will access
the uuid that stores with whom the file is directly shared with and then update the attribute.
Lastly, we will create an invitation access pointer (includes location of invitation and source key
for decryption) and use the recipient’s public key to encrypt the invitation access struct. We’re
using a RSA encryption scheme here.
To accept an invitation, we first check the integrity of the user and whether the shared file
already exists in the recipient’s namespace. Then we will get the invitation access struct and
decrypt the key with the user’s private RSA key. After decryption, the user will know the uuid of
the file and encrypt the file using the keys from the Password-Based Key Derivation Function.
At last, the user will add the encrypted file to their own namespace.
To revoke access, we first check the integrity of the user and verify personal space, the owner of
the file, and the recipient. We will then check the shared map of the file (with whom the file is
shared with) in the file attribute. After verifying the person to revoke access from exists in the
first shared map, we delete the invitation object sent to the user, update the shared map, encrypt
the shared map, and store it in the datastore. Then we will generate a new address and shared key
for the file, create a new file object, and update the new file with content from the original file.
Lastly, we will create a new secondary structure (file pointer object) that stores the new file
address and uuid. We will send this new secondary structure to all the users who still have
access.
