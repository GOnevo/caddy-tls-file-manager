package caddytlsfilemanager

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(FileCertGetter{})
}

// FileCertGetter can get a certificate via file.
type FileCertGetter struct {
	// The path to file with domain-certificate dictionary. Required.
	Path string `json:"path,omitempty"`

	ctx context.Context
}

// CaddyModule returns the Caddy module information.
func (fcg FileCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.file",
		New: func() caddy.Module { return new(FileCertGetter) },
	}
}

func (fcg *FileCertGetter) Provision(ctx caddy.Context) error {
	fcg.ctx = ctx
	if fcg.Path == "" {
		return fmt.Errorf("path is required")
	}
	return nil
}

func (fcg FileCertGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certMap, err := getMapFromFile(fcg.Path)
	if err != nil {
		return nil, err
	}

	var certFile string
	for domain, certPath := range certMap {
		if hello.ServerName == domain {
			certFile = certPath
			break
		}
	}

	bodyBytes, err := getCertificateFromFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate bundle body: %v", err)
	}

	cert, err := tlsCertFromCertAndKeyPEMBundle(bodyBytes)
	if err != nil {
		return &cert, err
	}

	return &cert, nil
}

func getCertificateFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func getMapFromFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := make(map[string]string)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) != 2 {
			return nil, errors.New("incorrect format of file")
		}

		data[parts[0]] = parts[1]
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

func tlsCertFromCertAndKeyPEMBundle(bundle []byte) (tls.Certificate, error) {
	certBuilder, keyBuilder := new(bytes.Buffer), new(bytes.Buffer)
	var foundKey bool // use only the first key in the file

	for {
		// Decode next block, so we can see what type it is
		var derBlock *pem.Block
		derBlock, bundle = pem.Decode(bundle)
		if derBlock == nil {
			break
		}

		if derBlock.Type == "CERTIFICATE" {
			// Re-encode certificate as PEM, appending to certificate chain
			if err := pem.Encode(certBuilder, derBlock); err != nil {
				return tls.Certificate{}, err
			}
		} else if derBlock.Type == "EC PARAMETERS" {
			// EC keys generated from openssl can be composed of two blocks:
			// parameters and key (parameter block should come first)
			if !foundKey {
				// Encode parameters
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}

				// Key must immediately follow
				derBlock, bundle = pem.Decode(bundle)
				if derBlock == nil || derBlock.Type != "EC PRIVATE KEY" {
					return tls.Certificate{}, fmt.Errorf("expected elliptic private key to immediately follow EC parameters")
				}
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else if derBlock.Type == "PRIVATE KEY" || strings.HasSuffix(derBlock.Type, " PRIVATE KEY") {
			// RSA key
			if !foundKey {
				if err := pem.Encode(keyBuilder, derBlock); err != nil {
					return tls.Certificate{}, err
				}
				foundKey = true
			}
		} else {
			return tls.Certificate{}, fmt.Errorf("unrecognized PEM block type: %s", derBlock.Type)
		}
	}

	certPEMBytes, keyPEMBytes := certBuilder.Bytes(), keyBuilder.Bytes()
	if len(certPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("failed to parse PEM data")
	}
	if len(keyPEMBytes) == 0 {
		return tls.Certificate{}, fmt.Errorf("no private key block found")
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("making X509 key pair: %v", err)
	}

	return cert, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into ts.
//
//	... file <path>
func (fcg *FileCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		fcg.Path = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			return d.Err("block not allowed here")
		}
	}
	return nil
}

// Interface guards
var (
	_ certmagic.Manager     = (*FileCertGetter)(nil)
	_ caddy.Provisioner     = (*FileCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*FileCertGetter)(nil)
)
