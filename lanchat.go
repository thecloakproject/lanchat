// Steve Phillips / elimisteve
// 2012.11.26

package main

import (
	"./types"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"github.com/elimisteve/fun"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	MAX_MESSAGE_SIZE = 8192
)

var (
	SharedSecret = "go run lanchat.go -serve -conns "
)

// Define flags
var (
	// TODO: Make this a common-ish port
	RemoteListen = flag.String("listen", "0.0.0.0:9999",
		"ip:port to listen on for remote connections")
	LocalListenPort = flag.String("local-port", "10000",
		"Port to listen on for local connections")
	Protocol    = flag.String("proto", "tcp", "Protocol options: tcp, ws")
	ActAsServer = flag.Bool("serve", false, "Act as server?")
	Server      = flag.String("server", "",
		"ip:port of remote server to connect to (used when '-serve' not used)")
	MaxRemoteConns = flag.Int("conns", 1,
		"Maximum simultaneous remote connections allowed")
	MaxLocalConns = flag.Int("local-conns", 1,
		"Maximum simultaneous remote connections allowed")

	DEBUG = false
)

var connList = types.ConnList{
	AddLocal:       make(chan net.Conn),
	DeleteLocal:    make(chan net.Conn),
	AddRemote:      make(chan net.Conn),
	DeleteRemote:   make(chan net.Conn),
	WriteToRemotes: make(chan *types.Cipherstore),
}

func init() {
	types.DEBUG = false
	flag.BoolVar(&DEBUG, "debug", DEBUG,
		"Enable debug mode for verbose terminal messages")
	flag.Parse()
}

func main() {
	// Prompt user for shared secret if not already given
	// TODO: Use this to get password instead: http://code.google.com/p/go/source/browse/ssh/terminal/terminal.go?repo=crypto#430
	if SharedSecret == "" {
		fmt.Printf("AES shared secret (must be of length 16, 24, or 32): ")
		// TODO: Remove length restriction (pad with zeroes or something)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Printf("Couldn't get secret from you: %v\n", err)
			os.Exit(1)
		}
		// Exclude trailing newline
		SharedSecret = line[:len(line)-1]
	}

	// Listen for changes to the routing table
	go connList.Listen()

	// If this client is acting as the server, spawn server
	if *ActAsServer {
		remoteServer := TCPServer
		if strings.ToLower(*Protocol) == "ws" {
			remoteServer = RemoteWSServer
		}
		// `server` must be of type `func(string, string, int)`
		go remoteServer(*RemoteListen, *MaxRemoteConns, RemoteConnHandler)
	} else if *Server == "" {
		// If this isn't the server and no server specified...
		fmt.Printf("Must specify server ip:port ('-server xx.yy.zz.ww:9999)'\n")
		os.Exit(1)
	} else {
		go TCPBridge(*Server)
	}

	// Open port for local telnet client
	go TCPServer("localhost:"+*LocalListenPort, *MaxLocalConns,
		LocalConnHandler)

	// Give user command
	fmt.Printf("\nNow run\n\n    telnet localhost %s\n\n", *LocalListenPort)

	// Block forever
	if DEBUG {
		log.Printf("Servers started. Blocking...\n")
	}
	select {}
}

func RemoteWSServer(listenIPandPort string, maxConns int, handler func(net.Conn)) {
	fmt.Printf("Not implemented! Choose '-proto tcp' for now\n")
	os.Exit(0)
}

// TCPServer creates a TCP server to listen for remote connections and
// pass them to the given handler
func TCPServer(listenIPandPort string, maxConns int, handler func(net.Conn)) {
	// Create TCP connection listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", listenIPandPort)
	fun.MaybeFatalAt("net.ResolveTCPAddr", err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	fun.MaybeFatalAt("net.ListenTCP", err)

	activeConns := make(chan int, maxConns)

	// Accept new TCP connections forever
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("RemoteTCPServer: Error accepting TCP traffic: %v", err)
			continue
		}
		// Every time someone connects, spawn goroutine that handles the
		// connection once the number of connections <= maxConns
		go func() {
			activeConns <- 1
			if DEBUG {
				log.Printf("Added 1 to semaphore. Calling handler\n")
			}

			handler(conn)
			if DEBUG {
				log.Printf("handler for %s returned\n", conn.RemoteAddr())
			}

			<-activeConns
			if DEBUG {
				log.Printf("activeConns drained by 1\n")
			}
		}()
	}
}

// RemoteConnHandler continuously reads an encrypted message from a remote user
// (sent from his/her LanChat client), decrypts it, then prints it to the
// terminal. Called by RemoteTCPServer, which is used when *ActAsServer == true,
// and TCPBridge, which is used when *ActAsServer == false.
func RemoteConnHandler(conn net.Conn) {
	// New user connected; add their connection to routing table
	connList.AddRemote <- conn

	// Close conn and remove it from the routing table when we're done
	// here
	defer func() {
		connList.DeleteRemote <- conn
		conn.Close()
	}()

	// Create new cipher.Block
	decBlock, err := aes.NewCipher([]byte(SharedSecret))
	if err != nil {
		fmt.Printf("Error creating AES cipher for decryption: %v\n", err)
		os.Exit(1)
	}
	ciphertext := make([]byte, MAX_MESSAGE_SIZE)
	cipherstore := &types.Cipherstore{}
	for {
		n, err := conn.Read(ciphertext)
		if err != nil {
			log.Printf("Error reading message from remote conn %s: %v\n",
				conn.RemoteAddr(), err)
			if err == io.EOF {
				break
				// TODO: os.Exit(1) when disconnecting from _the_ server
			}
			continue
		}
		// Send message to other remote users
		go func() {
			cipherstore.Conn = conn
			cipherstore.Data = ciphertext[:n]
			connList.WriteToRemotes <- cipherstore
		}()

		// Decrypt
		plaintext, err := aesDecryptBytes(decBlock, ciphertext[:n])
		if err != nil {
			log.Printf("Error decrypting '%v' ('%s'): %v\n",
				ciphertext[:n], ciphertext[:n], err)
			continue
		}
		// Print to screen of the form `[timestamp] remoteIP: Message`
		now := time.Now().Format(time.Kitchen)
		fmt.Printf("[%s] %s: %s\n", now, conn.RemoteAddr(), plaintext)
	}
}

// Continuously read local user input (from telnet) and write it to all remote
// connections
func LocalConnHandler(conn net.Conn) {
	// New user connected; add their connection to routing table
	connList.AddLocal <- conn

	// Close conn and remove it from the routing table when we're done
	// here
	defer func() {
		connList.DeleteLocal <- conn
		conn.Close()
	}()

	// Create new cipher.Block
	if DEBUG {
		log.Printf("Using shared secret '%s'\n", SharedSecret)
	}
	encBlock, err := aes.NewCipher([]byte(SharedSecret))
	if err != nil {
		fmt.Printf("Error creating AES cipher for encryption: %v\n", err)
		os.Exit(1)
	}
	plaintext := make([]byte, MAX_MESSAGE_SIZE)
	cipherstore := &types.Cipherstore{}
	for {
		if DEBUG {
			log.Printf("Listening for new message...\n")
		}
		n, err := conn.Read(plaintext)
		if err != nil {
			log.Printf("Error reading message from local conn %s: %v\n",
				conn.RemoteAddr(), err)
			if err == io.EOF {
				break
			}
			continue
		}
		// Print user input to screen
		now := time.Now().Format(time.Kitchen)
		fmt.Printf("[%s] %s: %s\n", now, conn.RemoteAddr(), plaintext[:n])

		plaintext = padBytes(plaintext[:n], encBlock.BlockSize())
		ciphertext, err := aesEncryptBytes(encBlock, plaintext)
		if err != nil {
			log.Printf("Error encrypting '%s': %v\n", plaintext, err)
			continue
		}
		go func() {
			cipherstore.Conn = conn
			cipherstore.Data = ciphertext
			connList.WriteToRemotes <- cipherstore
		}()
	}
}

// TCPBridge connects to the given server, then calls RemoteConnHandler. Used
// when *ActAsServer == false.
func TCPBridge(serverIPandPort string) {
	// Connect to server
	conn, err := net.Dial("tcp", serverIPandPort)
	if err != nil {
		log.Printf("Couldn't connect to %s: %v\n", serverIPandPort, err)
		os.Exit(1)
	}
	RemoteConnHandler(conn)
}

//
// Add to github.com/thecloakproject/helpers/crypt then import accordingly
//

func aesEncryptBytes(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	length := len(data)

	cipherBytes := make([]byte, length)
	numBlocks := length / blockSize
	// Add one more if there were bytes left over
	if length%blockSize != 0 {
		numBlocks++
	}

	// Encrypt
	for i := 0; i < length; i += blockSize {
		block.Encrypt(cipherBytes[i:i+blockSize], data[i:i+blockSize])
	}

	return cipherBytes, nil
}

func padBytes(data []byte, blockSize int) []byte {
	// Add padding (originally for correctness, now for simplicity)
	for len(data)%blockSize != 0 {
		data = append(data, 0x0)
	}
	return data
}

func aesDecryptBytes(block cipher.Block, cipherBytes []byte) (plain []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("Panic from aesDecryptBytes: %v", e)
			plain = nil
			err = fmt.Errorf("%v", e)
		}
	}()

	blockSize := block.BlockSize()
	plain = make([]byte, len(cipherBytes))
	for i := 0; i < len(cipherBytes); i += blockSize {
		block.Decrypt(plain[i:i+blockSize], cipherBytes[i:i+blockSize])
	}
	return plain, nil
}
