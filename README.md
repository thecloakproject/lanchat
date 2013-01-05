# LanChat


## Example Usage

### Server

If you're acting as the server, run the following:

    go run lanchat.go -serve

then follow the provided instructions.


### Client

If someone else's set up the server and you're just connecting, run

    go run lanchat.go -server 192.168.xx.yy:9999

then follow the provided instructions.


### Testing

#### Local Testing

If the server is already running on `localhost` (and therefore using port 10000
for its own TCP or telnet clients), choose a different local port to listen on:

    go run lanchat.go -local-port 10001 -server localhost:9999


#### Multiple, Concurrent Local Clients

Similar to the above, except you may want to accept many TCP/telnet clients:

    go run lanchat.go -local-port 10001 -local-conns 5 -server localhost:9999


## TODO

* Remove weird restrictions on `SharedSecret` length

* Clients should call `os.Exit(1)` when they disconnect from the server

  * Better yet, try reconnecting, and say you're doing so

* Decide whether to merge LanChat, MailChat, and/or CloakCast into CloakChat

* Create crypto helper repo

  * Add AES{EncryptDecrypt}Bytes, PadBytes

    * Consider adding Gob{Encode,Decode} functions

  * Use these functions in LanChat and Vaporizer

  * Consider calling it `github.com/thecloakproject/helpers/crypt`

* Create server helper repo

  * Include `TCPServer`

* Server should tell users how many others are connected when they connect

  * Do the same after user has been idle for a while

* Create "server pass-through mode"

  * Server just relays encrypted messages back and forth, never sees the key

  * Decide whether server should send unencrypted message saying len(conns)

* Add padding

  * Make all messages 50kb in length?

* Add flocking

  * Send message every second or two?


## Completed TODO

* When a new user connects to your server, say so

* 
