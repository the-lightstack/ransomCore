# RansomCore

An open source golang Ransomware for learning about the behaviore of ransomware.
Currently it only really works on Linux though.
This piece of software is meant for educational purposes only.
I am not responsible for anything done with this code.

# How to install it?
Get the Repository
`git clone https://github.com/the-lightstack/ransomCore`
Make sure you have go and gcc installed and execute the following
`cd ransomCore && ./run.sh`

You will find the client and server ELF binaries in their corresponding folders.

# How does it work?
When first executed, the client fetches an AES key over an SSL encrypted tunnel
from the server and uses it to encrypt all files that have the right file extension.
The files are read into memory in 100MB chunks and each one has their own unique
nonce value for encryption. Nonce + encrypted data are written into a file with 
the filename being `original_filename.rce` (rce standing for RansomCoreEncrypted)

# Does the malware spread?
No. This feature has to be implemented by you, feel free to fork or submit PR's.

# Is there any automatic payment method builtin?
No there is not, but if you know the AES key that encrypted your files (which is
in the **keys** table of the **encryptionKeys.db** database on the server) you can 
call `./client decrypt <base64-encoded AES key>`

