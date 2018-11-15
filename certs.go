package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"os"

	"github.com/coreos/go-systemd/activation"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func main() {
	lns, err := activation.Listeners()
	if err != nil {
		panic(err)
	}

	var keys []ssh.PublicKey
	for _, path := range os.Args[1:] {
		f, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		ks, err := parseKeys(f)
		if err != nil {
			panic(err)
		}
		keys = append(keys, ks...)
	}

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		panic(err)
	}
	agent := newAgent(sshagent.NewClient(conn))
	for _, c := range filterCerts(keys) {
		agent.addCert(c)
	}

	for _, ln := range lns {
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Print(err)
					continue
				}
				go sshagent.ServeAgent(agent, conn)
			}
		}(ln)
	}
	<-make(chan struct{})
}

func newAgent(agent sshagent.Agent) *Agent {
	return &Agent{
		Agent: agent,
		certs: make(map[string][]*ssh.Certificate),
	}
}

type Agent struct {
	sshagent.Agent
	certs map[string][]*ssh.Certificate
}

func (a *Agent) addCert(cert *ssh.Certificate) {
	fp := ssh.FingerprintSHA256(cert.Key)
	a.certs[fp] = append(a.certs[fp], cert)
}

func (a *Agent) List() ([]*sshagent.Key, error) {
	keys, err := a.Agent.List()
	if err != nil {
		return nil, err
	}
	keys = append([]*sshagent.Key{}, keys...)
	for _, k := range keys {
		fp := ssh.FingerprintSHA256(k)
		for _, c := range a.certs[fp] {
			keys = append(keys, &sshagent.Key{
				Format: c.Type(),
				Blob:   c.Marshal(),
			})
		}
	}
	return keys, nil
}

func filterCerts(keys []ssh.PublicKey) []*ssh.Certificate {
	var certs []*ssh.Certificate
	for _, k := range keys {
		if c, ok := k.(*ssh.Certificate); ok {
			certs = append(certs, c)
		}
	}
	return certs
}

func parseKeys(r io.Reader) (keys []ssh.PublicKey, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func nextWord(line []byte) (string, []byte) {
	i := bytes.IndexAny(line, "\t ")
	if i == -1 {
		return string(line), nil
	}
	return string(line[:i]), bytes.TrimSpace(line[i:])
}

func parseLine(line []byte) (ssh.PublicKey, error) {
	// ignore the keytype as it's in the key blob anyway.
	_, line = nextWord(line)
	if len(line) == 0 {
		return nil, errors.New("missing key type pattern")
	}
	keyBlob, _ := nextWord(line)
	keyBytes, err := base64.StdEncoding.DecodeString(keyBlob)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(keyBytes)
}
