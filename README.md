# LanChat

LanChat is an encrypted chat application for the paranoid

## Why not just use Google Talk + Pidgin + OTR (Off-The-Record messaging)?

Several reasons.

1. Sending your private traffic across the internet and through
   Google's servers is completely unnecessary, especially when the
   person/people you're chatting with are nearby


2. When you use such a 3rd party service, the company behind it knows
   some combination of who you are, who you're communicating with, and
   other information it makes no sense to disclose (e.g., when
   communication occurs, how much traffic is sent, and other things
   that could be used against you as part of advanced traffic
   analysis).

   This especially matters to us at The Cloak Project, as one of our
   primary goals is to provide _ridiculously_ paranoid tools with
   innovative security properties.

   When it comes to 3rd parties, we aim to disclose nothing.


3. LanChat is simpler. Thanks to how Go works, LanChat can be compiled
   and stored as a single statically-linked binary -- just one file --
   that assumes the existence of no special dependencies on the
   computer running it (just OS and architecture).


4. Due to its brevity, LanChat's code is much easier to read and
   therefore audit than Pidgin's or that of other programs.


## Current Features

* AES-encrypted chat

## Example Usage

### Server

If you're acting as the server, run the following:

    lanchat -serve

then follow the provided instructions. (If `lanchat` isn't installed
but you've downloaded the source code, run `go run lanchat.go ...`
instead of `lanchat ...`.)


### Client

If someone else's set up the server and you're just connecting, run

    lanchat -server 192.168.xx.yy:9999

then follow the provided instructions.


### Testing

#### Local Testing

If the server is already running on `localhost` (and therefore using
port 10000 for its own TCP or telnet clients), choose a different
local port to listen on:

    go run lanchat.go -local-port 10001 -server localhost:9999


#### Multiple, Concurrent Local Clients

Similar to the above, except you may want to accept many TCP/telnet
clients:

    go run lanchat.go -local-port 10001 -local-conns 5 -server localhost:9999


## TODO

* Remove weird restrictions on `SharedSecret` length

* Clients should call `os.Exit(1)` when they disconnect from the server

  * Better yet, they should try reconnecting, and say they're so

* Decide whether to merge LanChat, MailChat, and/or CloakCast into CloakChat

* Create server helper repo

  * Include `TCPServer`

* Rewrite `TCPServer` to return earlier

  * Launch the major for loop in a goroutine, then return

    * There is no significant, panic-worthy concern once that loop is reached

* Server should tell users how many others are connected when they connect

  * Do the same after user has been idle for a while

* Add special instructions somewhere for those without Go installed

  * How about on the GitHub wiki for The Cloak Project?

* Make `MAX_MESSAGE_SIZE` a flag/command line option

* Always correctly report disconnections


## Maybe-TODO

* Create "server pass-through mode"

  * Server just relays encrypted messages back and forth, never sees the key

  * Decide whether server should send unencrypted message saying len(conns)

* Add padding

  * Make all messages 50kb in length?

* Add flocking

  * Send message every second or two?

* ...Remove embarrassing global variables...


## Completed TODO Items (cross 'em off!)

* When a new user connects to your server, say so

* De-relativize `./types` package

* Create crypto helper repo

  * Add AES{EncryptDecrypt}Bytes, PadBytes

    * Consider adding Gob{Encode,Decode} functions

  * (Use these functions in LanChat and Vaporizer)

  * Consider calling it `github.com/thecloakproject/utils{,/crypt}`

* Replace `log.Printf(...); os.Exit(1)` with `log.Fatalf(...)`

* Create `NewConnList()` "constructor" function
