// Steve Phillips / elimisteve
// 2012.11.26

package types

import (
	"fmt"
	"log"
	"net"
)

var (
	DEBUG = false
)

// Cipherstores store encrypted data to be sent to all remote
// connections except the net.Conn stored in the `Conn` field.
type Cipherstore struct {
	// Conn is the sending connection, so we know who _not_ to send
	// Data to
	Conn net.Conn
	Data []byte
}

type ConnList struct {
	locals      []net.Conn
	AddLocal    chan net.Conn
	DeleteLocal chan net.Conn

	remotes      []net.Conn
	AddRemote    chan net.Conn
	DeleteRemote chan net.Conn

	WriteToRemotes chan *Cipherstore
	writeErrors    chan string
}

func NewConnList() *ConnList {
	cl := ConnList{
		AddLocal:       make(chan net.Conn),
		DeleteLocal:    make(chan net.Conn),
		AddRemote:      make(chan net.Conn),
		DeleteRemote:   make(chan net.Conn),
		WriteToRemotes: make(chan *Cipherstore),
		writeErrors:    make(chan string),
	}
	return &cl
}

func (list *ConnList) Listen() {
	go func() {
		for errStr := range list.writeErrors {
			log.Printf("%s\n", errStr)
		}
	}()

	for {
		if DEBUG {
			log.Printf("Listen() waiting for new event...\n")
		}
		select {
		// Handle local connection changes
		case conn := <-list.AddLocal:
			if DEBUG {
				log.Printf("Adding %s to local routing table\n",
					conn.RemoteAddr())
			}
			list.locals = append(list.locals, conn)
		case conn := <-list.DeleteLocal:
			if DEBUG {
				log.Printf("Deleting %s from local routing table\n",
					conn.RemoteAddr())
			}
			DeleteConn(list.locals, conn)

		// Handle remote connection changes
		case conn := <-list.AddRemote:
			if DEBUG {
				log.Printf("Adding %s to remote routing table\n",
					conn.RemoteAddr())
			}
			list.remotes = append(list.remotes, conn)
		case conn := <-list.DeleteRemote:
			if DEBUG {
				log.Printf("Deleting %s from remote routing table\n",
					conn.RemoteAddr())
			}
			DeleteConn(list.remotes, conn)

		// Handle writing to remote connections
		case cipherstore := <-list.WriteToRemotes:
			if DEBUG {
				log.Printf("Writing '%v' ('%s') to remotes\n",
					cipherstore.Data, cipherstore.Data)
			}
			for _, rc := range list.remotes {
				// Write to every connection... except itself!
				if rc != cipherstore.Conn {
					go func(c net.Conn) {
						if DEBUG {
							log.Printf("Writing '%v' to %s\n",
								cipherstore.Data, c.RemoteAddr())
						}
						_, err := c.Write(cipherstore.Data)
						if err != nil {
							errStr := "Error writing ciphertext to %s: %v\n"
							errStr = fmt.Sprintf(errStr, c.RemoteAddr(), err)
							// Report error, then assume this
							// connection won't magically heal itself
							// and remove it from the connection list
							list.writeErrors <- errStr
							DeleteConn(list.remotes, c)
							fmt.Printf("%s removed from connList\n",
								c.RemoteAddr())
						}
					}(rc)
				}
			}
		}
	}
}

// Delete the given net.Conn from the given []net.Conn
func DeleteConn(connList []net.Conn, c net.Conn) {
	for ndx, _ := range connList {
		if connList[ndx] == c {
			connList = append(connList[:ndx], connList[ndx+1:]...)
			if DEBUG {
				log.Printf("Removed %v from connList\n", c.RemoteAddr())
			}
			break
		}
	}
}
