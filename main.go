/**
* Estudiando como funciona ssh de cara a hacer aplicaicones a traces de SHH, si se puede en tiempo real
 */
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type (
	AppHandler func()
	Aplication struct {
		Port    uint
		Handler AppHandler
	}
	SSHServer struct {
		Config     *ssh.ServerConfig
		privateKey []byte
		Channels   any
	}
)

const (
	ADRESS = "0.0.0.0:2222"
)

func (app *Aplication) Handle(appHandler AppHandler) {
	app.Handler = appHandler
}

/**
* TLS: Transport Layer Security => Version de ssl para encriptacion de la comunicacion
*   hace un tunel a traves de la capa de transporte TCP
*   Para tener varios canales se crean varias conexiones TCP
*   SSH ofrece mejores alternativas de autenticacion a HTTP
*   SSH permite que el servidor envie informacion sin solicitu del cliente (sockets en HTTP)
*   TCP > SSH en vez de TCP > TLS > HTTP > WS
* Multiplexacion de canales
*   HTTP: paths de la Security
*   SSH : por protocolo, canal de ssh
 */
func main() {
	passwd := flag.String("passwd", "", "Contraseña de la clave privada")
	flag.Parse()

	homedir := getHomedir()
	// Configuracion del servidor y handler de la autenticacion
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-VALVAR",
		NoClientAuth:  true,
		// Pre auth se lanza aunque NoClientAuth sea true
		PreAuthConnCallback: func(pre ssh.ServerPreAuthConn) {
			user := pre.User()
			version := string(pre.ClientVersion())
			remoteAddr := pre.RemoteAddr().String()
			log.Printf("PreAuth: %s %s %s", user, version, remoteAddr)
		},
		PasswordCallback: func(meta ssh.ConnMetadata, passwd []byte) (*ssh.Permissions, error) {
			// logica de comprobar la contraseña, a no ser que se devuelva un error esta ok
			// el valor son los permisos, queda como TODO
			return nil, nil
		},
	}

	privateBytes, err := os.ReadFile(homedir + "/.ssh/id_rsa")
	if err != nil {
		log.Printf("Error clave privada %s", err)
		log.Fatal("Fallo leyendo la clave privada")
	}

	var privateKey ssh.Signer
	privateKey, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		// log.Fatalf("Error parseando la clave privada (%s)", err)
		privateKey, err = ssh.ParsePrivateKeyWithPassphrase(privateBytes, []byte(*passwd))
		if err != nil {
			log.Fatalf("Error parseando la clave privada (%s)", err)
		}
	}

	config.AddHostKey(privateKey)

	listener, err := net.Listen("tcp", ADRESS)
	if err != nil {
		log.Fatal("Error escuchando conexiones en: " + ADRESS)
	}

	log.Print("Servidor iniciado en ", ADRESS)

	// TODO:
	// - [x] aceptar conexiones simultaneas
	// - [ ] un cierre de conexion cierra todo el servidor
	for {
		tcpConn, err := listener.Accept()
		defer tcpConn.Close()

		if err != nil {
			log.Printf("Error aceptando la conexion (%s)", err)

			continue
		}

		sshConn, channels, requests, err := ssh.NewServerConn(tcpConn, config)
		defer sshConn.Close()

		if err != nil {
			log.Printf("Error estableciendo conexion (%s)", err)
			continue
		}

		log.Printf("Conexion establecida desde %s v(%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		// waitgroup para los requests
		var wg sync.WaitGroup
		wg.Add(1) // para los descartados

		go func() {
			ssh.DiscardRequests(requests)
			wg.Done()
		}()

		go handleChannels(channels, &wg)
	}
}

/**
* La idea es que los canales, peticiones asincronas de cada sesion se gestionen en rutinas
 */
func handleChannels(chans <-chan ssh.NewChannel, wg *sync.WaitGroup) {
	for nchan := range chans {

		log.Printf("Canal tipo: (%s)", nchan.ChannelType())

		go handleChannelProgram(nchan, wg)
	}
}

func handleChannelProgram(nchan ssh.NewChannel, wg *sync.WaitGroup) {
	if t := nchan.ChannelType(); t != "session" {
		ssh.NewChannel.Reject(nchan, ssh.UnknownChannelType, "No implementado")
		return
	}

	// Solo para tipo session
	channel, requests, err := nchan.Accept()
	if err != nil {
		log.Printf("No se acepta el canal (%s)", err)
	}

	wg.Add(1)
	// subrutina que muestra en el server que requests estan llegando
	// acepta un canal de requests
	go func(requestsIn <-chan *ssh.Request) {
		for req := range requestsIn {
			log.Printf("Req: %s %s %t", req.Type, string(req.Payload), req.WantReply)
			if req.WantReply {
				req.Reply(true, []byte("Resp OK"))
			}
		}
	}(requests)

	termChan := term.NewTerminal(channel, " > ")

	wg.Add(1)
	go func() {
		defer func() {
			channel.Close()
			wg.Done()
		}()

		for {
			line, err := termChan.ReadLine()
			if err != nil {
				log.Fatalf("Error en la terminal", err)
			}
			log.Print(line)
			termChan.Write([]byte("recibido\n"))
		}
	}()
}

func handleChannel(nchan ssh.NewChannel) {
	// De momento solo se implementa session
	// Antes era solo nchan.Reject
	if t := nchan.ChannelType(); t != "session" {
		ssh.NewChannel.Reject(nchan, ssh.UnknownChannelType, "No implementado")
		return
	}

	// Solo para tipo session
	connection, requests, err := nchan.Accept()
	if err != nil {
		log.Printf("No se acepta el canal (%s)", err)
	}

	// Cambiar por el programa en si
	bash := exec.Command("bash")

	// No me gusta que se cree la funcion de cerrar aqui
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("No se ha podido salir de bash (%s)", err)
		}
		log.Printf("Session cerrada")
	}

	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Error lanzando la pty (%s)", err)
		close()
		return
	}

	// No estoy seguro de esta parte
	// en teoria copia bashf -> connection y al
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()

	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

func getHomedir() string {
	dir, err := os.UserHomeDir()
	currUser, _ := user.Current()
	if err != nil {
		log.Fatalf("Error obtenidendo el direcotrio home de %s: %s", currUser.Name, err)
	}
	return dir
}
