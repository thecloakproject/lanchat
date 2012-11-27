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

type ConnList struct {
	locals   []net.Conn
	AddLocal chan net.Conn
	DeleteLocal chan net.Conn

	remotes   []net.Conn
	AddRemote chan net.Conn
	DeleteRemote chan net.Conn

	WriteToRemotes chan []byte
	writeErrors chan string
}

func (list *ConnList) Listen() {
	go func() {
		for errStr := range list.writeErrors {
			log.Printf("%s\n", errStr)
		}
	}()

	for {
		if DEBUG { log.Printf("Listen() waiting for new event...\n") }
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
		case ciphertext := <-list.WriteToRemotes:
			if DEBUG {
				log.Printf("Writing '%v' ('%s') to remotes\n",
					ciphertext, ciphertext)
			}
			for _, rc := range list.remotes {
				go func(c net.Conn) {
					if DEBUG {
						log.Printf("Writing '%v' to %s\n", ciphertext,
							c.RemoteAddr())
					}
					_, err := c.Write(ciphertext)
					if err != nil {
						errStr := "Error writing ciphertext to %s: %v\n"
						errStr = fmt.Sprintf(errStr, c.RemoteAddr(), err)
						list.writeErrors <- errStr
						DeleteConn(list.remotes, c)
						fmt.Printf("%s removed from connList\n", c.RemoteAddr())
					}
				}(rc)
			}
		}
	}
}

// Delete the given net.Conn from the given []net.Conn
func DeleteConn(connList []net.Conn, conn net.Conn) {
	for ndx, _ := range connList {
		if connList[ndx] == conn {
			connList = append(connList[:ndx], connList[ndx+1:]...)
			break
		}
	}
}