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

When testing with multiple local clients, you may want to run

    go run lanchat.go -local-port 10001 -server localhost:9999
