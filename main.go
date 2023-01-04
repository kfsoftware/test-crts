package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

func parseX509Certificate(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

// compute Subject Key Identifier using RFC 7093, Section 2, Method 4
func computeSKI(privKey *ecdsa.PrivateKey) []byte {
	// Marshall the public key
	raw := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	// Hash it
	hash := sha256.Sum256(raw)
	return hash[:]
}
func CreateDefaultCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
		return nil, nil, err
	}
	log.Printf("serialNumber: %v", serialNumber)
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	expiry := 3650 * 24 * time.Hour
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		//Subject: pkix.Name{
		//	Organization:       []string{"Kyma"},
		//	Country:            []string{"DE"},
		//	Locality:           []string{"Berlin"},
		//	OrganizationalUnit: []string{"Kyma"},
		//	StreetAddress:      []string{"Karl-Liebknecht-Str. 3"},
		//	CommonName:         "Kyma",
		//},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(expiry).UTC(),
		//IsCA:                  true,
		//SubjectKeyId:          computeSKI(caPrivKey),
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		//KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	subject := pkix.Name{
		Organization: []string{"Kyma"},
		//Country:            []string{"US"},
		//Locality:           []string{"Berlin"},
		//OrganizationalUnit: []string{"Kyma"},
		//StreetAddress:      []string{"Karl-Liebknecht-Str. 3"},
		CommonName: "kyma",
	}
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageDigitalSignature |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageServerAuth,
	}
	template.Subject = subject
	template.SubjectKeyId = computeSKI(caPrivKey)
	caBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return crt, caPrivKey, nil
}
func EncodeX509Certificate(crt *x509.Certificate) []byte {
	pemPk := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Raw,
	})
	return pemPk

}
func main() {
	caCert, _, err := CreateDefaultCA()
	if err != nil {
		log.Fatal(err)
	}
	_ = caCert
	certToCheck := EncodeX509Certificate(caCert)
	//	certToCheck := []byte(`-----BEGIN CERTIFICATE-----
	//MIICQTCCAeagAwIBAgIRAIlyPiTZkAYHopLI/MMzu5gwCgYIKoZIzj0EAwIwajEL
	//MAkGA1UEBhMCRVMxETAPBgNVBAcTCEFsaWNhbnRlMREwDwYDVQQJEwhBbGljYW50
	//ZTEZMBcGA1UEChMQS3VuZyBGdSBTb2Z0d2FyZTENMAsGA1UECxMEVGVjaDELMAkG
	//A1UEAxMCY2EwHhcNMjMwMTAzMTA1NTIyWhcNMzMwMTA0MTA1NTIyWjBqMQswCQYD
	//VQQGEwJFUzERMA8GA1UEBxMIQWxpY2FudGUxETAPBgNVBAkTCEFsaWNhbnRlMRkw
	//FwYDVQQKExBLdW5nIEZ1IFNvZnR3YXJlMQ0wCwYDVQQLEwRUZWNoMQswCQYDVQQD
	//EwJjYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB9O3T8iBC2OpFHe6BWJNEh4
	//mxSR8AmyqKZKyjCLy9HnjDeYVoVQLK7Qouvc0iyTs+WTscv+iTkjzEkm9pfWdEqj
	//bTBrMA4GA1UdDwEB/wQEAwIBpjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
	//AwEwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQgV0rtlf59BQ7pjZHD+RF0zIIj
	//mmgjUWR+6Q+npPY9mIcwCgYIKoZIzj0EAwIDSQAwRgIhAJqVsD9z4GSB26uKQNqW
	//swGxS0xvdrwzJ8Wm/CKNPnBLAiEAkRuMG+YojjB/UKkArQEQNcxy8CzAUPoCbmG7
	//cN2el6c=
	//-----END CERTIFICATE-----`)
	log.Printf("certToCheck: %s", certToCheck)
	certPool := x509.NewCertPool()
	parentCert, err := parseX509Certificate([]byte(certToCheck))
	if err != nil {
		log.Fatal(err)
	}
	_ = certPool.AppendCertsFromPEM([]byte(certToCheck))
	x509Cert, err := parseX509Certificate([]byte(certToCheck))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("parentCert: %v", parentCert)
	s := new(big.Int)
	s = s.Set(GetCurveHalfOrdersAt(elliptic.P256()))
	s = s.Add(s, big.NewInt(1))

	lowS, err := IsLowS(parentCert.PublicKey.(*ecdsa.PublicKey), s)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("lowS: %v", lowS)
	expectedSig, err := SignatureToLowS(parentCert.PublicKey.(*ecdsa.PublicKey), x509Cert.Signature)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("expectedSig: %v currentSig: %v", expectedSig, x509Cert.Signature)

	equalSig := bytes.Equal(x509Cert.Signature, expectedSig)
	log.Printf("equalSig: %v", equalSig)

	options := x509.VerifyOptions{}
	options.Roots = certPool
	_, err = x509Cert.Verify(options)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Hello, world.")
}
