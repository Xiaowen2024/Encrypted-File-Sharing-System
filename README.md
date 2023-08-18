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

