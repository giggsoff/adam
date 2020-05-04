// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/lf-edge/eve/api/go/auth"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/config"

	"github.com/gorilla/mux"
	"github.com/lf-edge/adam/pkg/driver"
)

// Server an adam server
type Server struct {
	Port          string
	HTTPPort      string
	Address       string
	CertPath      string
	KeyPath       string
	DeviceManager driver.DeviceManager
	CertRefresh   int
}

// Start start the server
func (s *Server) Start() {
	// ensure the server cert and key exist
	_, err := os.Stat(s.CertPath)
	if err != nil {
		log.Fatalf("server cert %s does not exist", s.CertPath)
	}
	_, err = os.Stat(s.KeyPath)
	if err != nil {
		log.Fatalf("server key %s does not exist", s.KeyPath)
	}

	if s.DeviceManager == nil {
		log.Fatalf("empty device manager")
	}

	// save the device manager settings
	s.DeviceManager.SetCacheTimeout(s.CertRefresh)

	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFound)

	// to pass logs and info around
	logChannel := make(chan proto.Message)
	infoChannel := make(chan proto.Message)

	// edgedevice endpoint - fully compliant with EVE open API
	api := &apiHandler{
		manager:     s.DeviceManager,
		logChannel:  logChannel,
		infoChannel: infoChannel,
	}

	router.HandleFunc("/", api.probe).Methods("GET")

	ed := router.PathPrefix("/api/v1/edgedevice").Subrouter()
	ed.Use(ensureMTLS)
	ed.Use(logRequest)
	ed.HandleFunc("/register", api.register).Methods("POST")
	ed.HandleFunc("/ping", api.ping).Methods("GET")
	ed.HandleFunc("/config", api.config).Methods("GET")
	ed.HandleFunc("/config", api.configPost).Methods("POST")
	ed.HandleFunc("/info", api.info).Methods("POST")
	ed.HandleFunc("/metrics", api.metrics).Methods("POST")
	ed.HandleFunc("/logs", api.logs).Methods("POST")

	edv2 := router.PathPrefix("/api/v2/edgedevice").Subrouter()
	edv2.Use(ensureMTLS)
	edv2.Use(logRequest)
	edv2.HandleFunc("/register", api.register).Methods("POST")
	edv2.HandleFunc("/ping", api.ping).Methods("GET")
	edv2.HandleFunc("/config", api.config).Methods("GET")
	edv2.HandleFunc("/config", api.configPostV2).Methods("POST")
	edv2.HandleFunc("/info", api.info).Methods("POST")
	edv2.HandleFunc("/metrics", api.metrics).Methods("POST")
	edv2.HandleFunc("/logs", api.logs).Methods("POST")

	// admin endpoint - custom, used to manage adam
	admin := &adminHandler{
		manager:     s.DeviceManager,
		logChannel:  logChannel,
		infoChannel: infoChannel,
	}

	ad := router.PathPrefix("/admin").Subrouter()
	ad.HandleFunc("/onboard", admin.onboardList).Methods("GET")
	ad.HandleFunc("/onboard/{cn}", admin.onboardGet).Methods("GET")
	ad.HandleFunc("/onboard", admin.onboardAdd).Methods("POST")
	ad.HandleFunc("/onboard", admin.onboardClear).Methods("DELETE")
	ad.HandleFunc("/onboard/{cn}", admin.onboardRemove).Methods("DELETE")
	ad.HandleFunc("/device", admin.deviceList).Methods("GET")
	ad.HandleFunc("/device/{uuid}", admin.deviceGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/config", admin.deviceConfigSet).Methods("PUT")
	ad.HandleFunc("/device/{uuid}/logs", admin.deviceLogsGet).Methods("GET")
	ad.HandleFunc("/device/{uuid}/info", admin.deviceInfoGet).Methods("GET")
	ad.HandleFunc("/device", admin.deviceAdd).Methods("POST")
	ad.HandleFunc("/device", admin.deviceClear).Methods("DELETE")
	ad.HandleFunc("/device/{uuid}", admin.deviceRemove).Methods("DELETE")

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  nil,
	}

	serverTLS := &http.Server{
		Handler:   router,
		Addr:      fmt.Sprintf("%s:%s", s.Address, s.Port),
		TLSConfig: tlsConfig,
	}

	routerHTTP := mux.NewRouter()
	routerHTTP.NotFoundHandler = http.HandlerFunc(notFound)
	edvHttp := routerHTTP.PathPrefix("/api/v2/edgedevice").Subrouter()
	edvHttp.HandleFunc("/certs", api.certs).Methods("POST")

	serverHTTP := &http.Server{
		Handler: routerHTTP,
		Addr:    fmt.Sprintf("%s:%s", s.Address, s.HTTPPort),
	}
	log.Println("Starting adam:")
	log.Printf("\tIP:Port: %s:%s\n", s.Address, s.Port)
	log.Printf("\tIP:Port HTTP: %s:%s\n", s.Address, s.HTTPPort)
	log.Printf("\tstorage: %s\n", s.DeviceManager.Name())
	log.Printf("\tdatabase: %s\n", s.DeviceManager.Database())
	log.Printf("\tserver cert: %s\n", s.CertPath)
	log.Printf("\tserver key: %s\n", s.KeyPath)
	go func() {
		log.Fatal(serverHTTP.ListenAndServe())
	}()
	log.Fatal(serverTLS.ListenAndServeTLS(s.CertPath, s.KeyPath))
}

// middleware handlers to check device cert and onboarding cert

// check that a known device cert has been presented
func ensureMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ensure we have TLS with at least one PeerCertificate
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusUnauthorized)
			return
		}
		if r.TLS.PeerCertificates == nil || len(r.TLS.PeerCertificates) < 1 {
			http.Error(w, "client TLS authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// log the request and client
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := getClientCert(r)
		log.Printf("%s requested %s", cert.Subject.String(), r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// retrieve the client cert
func getClientCert(r *http.Request) *x509.Certificate {
	return r.TLS.PeerCertificates[0]
}

// retrieve the AuthContainer from request
func getAuthContainer(r *http.Request) (*auth.AuthContainer, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Body read failed: %v", err)
		return nil, err
	}
	authContainer := &auth.AuthContainer{}
	err = proto.Unmarshal(body, authContainer)
	if err != nil {
		log.Printf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return authContainer, nil
}

// ComputeSha - Compute sha256 on data
func ComputeSha(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	return hash
}

// sign hash'ed data with certificate private key
func signAuthData(sigdata []byte, cert tls.Certificate) ([]byte, error) {
	hash := ComputeSha(sigdata)

	var sigres []byte
	switch key := cert.PrivateKey.(type) {
	default:
		err := fmt.Errorf("signAuthData: privatekey default, type %T", key)
		return nil, err
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			log.Printf("signAuthData: ecdsa sign error %v\n", err)
			return nil, err
			//log.Fatal("ecdsa.Sign: ", err)
		}
		log.Printf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres = r.Bytes()
		sigres = append(sigres, s.Bytes()...)
		log.Printf("signAuthData: ecdas sigres (len %d): %x\n",
			len(sigres), sigres)
	}
	return sigres, nil
}

// retrieve the config request
func getClientConfigRequest(r *http.Request) (*config.ConfigRequest, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Body read failed: %v", err)
		return nil, err
	}
	configRequest := &config.ConfigRequest{}
	err = proto.Unmarshal(body, configRequest)
	if err != nil {
		log.Printf("Unmarshalling failed: %v", err)
		return nil, err
	}
	return configRequest, nil
}

func notFound(w http.ResponseWriter, r *http.Request) {
	log.Printf("404 returned for %s", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
