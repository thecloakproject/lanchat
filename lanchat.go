// Steve Phillips / elimisteve
// 2012.11.26

package main

import (
	"bufio"
	"crypto/aes"
	"flag"
	"fmt"
	"github.com/thecloakproject/lanchat/types"
	"github.com/thecloakproject/utils/crypt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	MAX_MESSAGE_SIZE = 1e6 // 1MB
)

var (
	SharedSecret = ""
)

// Define flags
var (
	// TODO: Make this a common-ish port
	RemoteListen = flag.String("listen", "0.0.0.0:9999",
		"IP:Port to listen on for remote connections (use with -serve)")
	LocalListenPort = flag.String("local-port", "10000",
		"Port to listen on for local connections")
	Protocol = flag.String("proto", "tcp",
		"Protocol options: tcp")
	ActAsServer = flag.Bool("serve", false,
		"Act as server?")
	Server = flag.String("server", "",
		"IP:Port of remote server to connect to (used when -serve isn't)")
	MaxRemoteConns = flag.Int("conns", 1,
		"Maximum simultaneous remote connections allowed")
	MaxLocalConns = flag.Int("local-conns", 1,
		"Maximum simultaneous local connections allowed")

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

	// If this client is acting as the server, spawn a server, otherwise spawn
	// a bridge between the remote server and local TCP connections
	if *ActAsServer {
		remoteIPandPort := strings.Split(*RemoteListen, ":")
		// Everything after last :
		remotePort := remoteIPandPort[len(remoteIPandPort)-1]
		fmt.Printf("\nTell your friend to connect to your IP on port %s\n",
			remotePort)
		go TCPServer(*RemoteListen, *MaxRemoteConns, RemoteConnHandler)
	} else if *Server == "" {
		// If this isn't the server and no server specified...
		fmt.Printf("Must specify server ip:port ('-server xx.yy.zz.ww:9999)'\n")
		os.Exit(1)
	} else {
		go TCPBridge(*Server)
	}

	// Open port for local telnet client
	go func() {
		err := fmt.Errorf("Non-nil error")
		// Try listening on new port until it works, or fails 10 times
		for attempts := 0; err != nil && attempts < 10; attempts++ {
			// Give user command
			if attempts != 0 {
				fmt.Printf("Just kidding!")
			}
			fmt.Printf("\nNow run\n\n    telnet localhost %s\n\n",
				*LocalListenPort)
			fmt.Printf("Type into the telnet window and view the ")
			fmt.Printf("full conversation in this one.\n\n")
			err = TCPServer("localhost:"+*LocalListenPort, *MaxLocalConns,
				LocalConnHandler)
			IncrementString(LocalListenPort)
		}
		panic(fmt.Sprintf("Error converting %s to int: %v\n",
			LocalListenPort, err))
	}()

	// Block forever
	if DEBUG {
		log.Printf("Servers started. Blocking...\n")
	}
	select {}
}

// TCPServer creates a TCP server to listen for remote connections and
// pass them to the given handler
func TCPServer(listenIPandPort string, maxConns int, handler func(net.Conn)) error {
	// Create TCP connection listener
	tcpAddr, err := net.ResolveTCPAddr("tcp4", listenIPandPort)
	if err != nil {
		return fmt.Errorf("Error calling net.ResolveTCPAddr: " + err.Error())
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("Error calling net.ListenTCP: " + err.Error())
	}

	if DEBUG {
		log.Printf("%s maxConns == %d\n", listenIPandPort, maxConns)
	}

	// Semaphore
	activeConns := make(chan int, maxConns)

	for {
		// Every time someone connects and the number of active connections
		// <= maxConns, handle the connection

		activeConns <- 1
		if DEBUG {
			log.Printf("Added 1 to semaphore. Accepting connections...\n")
		}

		// Accept new connections
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCPServer: Error accepting TCP traffic: %v", err)
			<-activeConns
			continue
		}

		log.Printf("* New connection: %s\n\n", conn.RemoteAddr())

		// Handle
		go func() {
			handler(conn)
			if DEBUG {
				log.Printf("handler for %s returned\n", conn.RemoteAddr())
			}
			<-activeConns
		}()
	}
	return nil
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
			if err == io.EOF {
				break
				// TODO: os.Exit(1) when disconnecting from _the_ server
			}
			log.Printf("Error reading message from remote conn %s: %v\n",
				conn.RemoteAddr(), err)
			continue
		}
		if DEBUG { log.Printf("ciphertext[:n] == %v\n", ciphertext[:n]) }
		// Send message to other remote users
		go func() {
			cipherstore.Conn = conn
			cipherstore.Data = ciphertext[:n]
			connList.WriteToRemotes <- cipherstore
		}()

		// Decrypt
		plaintext, err := crypt.AESDecryptBytes(decBlock, ciphertext[:n])
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
	cipherstore := &types.Cipherstore{}
	var text []byte

	r := bufio.NewReader(conn)
	for {
		if DEBUG { log.Printf("Listening for new message...\n") }

		plaintext := []byte{}
		isPrefix := true

		for isPrefix {
			text, isPrefix, err = r.ReadLine()
			if DEBUG { fmt.Printf("isPrefix == %v\n", isPrefix) }
			if err != nil {
				log.Printf("Error reading message from local conn %s: %v\n",
					conn.RemoteAddr(), err)
				if err == io.EOF {
					fmt.Printf("Exiting RemoteConnHandler for %s\n",
						conn.RemoteAddr())
					return
				}
				break
			}
			if DEBUG { fmt.Printf("text == %s\n", text) }
			plaintext = append(plaintext, text...)
		}
		// Print user input to screen
		now := time.Now().Format(time.Kitchen)
		fmt.Printf("[%s] %s: %s\n", now, conn.RemoteAddr(), plaintext)

		// Encrypt plaintext coming from local user over telnet
		ciphertext, err := crypt.AESEncryptBytes(encBlock, plaintext)
		if err != nil {
			log.Printf("Error encrypting '%s': %v\n", plaintext, err)
			continue
		}
		// Asynchronously write encrypted message to all remote
		// connections
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

func IncrementString(numStr *string) error {
	if numStr == nil {
		return fmt.Errorf("Can't turn `nil` into an int")
	}
	num, err := strconv.Atoi(*numStr)
	if err != nil {
		return fmt.Errorf("Error converting %s to int: %v", *numStr, err)
	}
	num++
	*numStr = strconv.Itoa(num)
	return nil
}
