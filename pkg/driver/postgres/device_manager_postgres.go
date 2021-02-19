// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/lf-edge/adam/pkg/driver/common"

	ax "github.com/lf-edge/adam/pkg/x509"
	uuid "github.com/satori/go.uuid"
)

//OnboardCert db model
type OnboardCert struct {
	Id      int64
	Cn      string
	Cert    []byte
	Serials []string
}

//Device db model
type Device struct {
	Id      int64
	UUID    string
	Cert    []byte
	Onboard []byte
	Serial  string
	Config  string `pg:"type:jsonb"`
}

//DeviceLog db model
type DeviceLog struct {
	Id     int64
	Device *Device `pg:"rel:has-one" sql:"on_delete:CASCADE"`
	Data   string  `pg:"type:jsonb"`
}

//DeviceInfo db model
type DeviceInfo struct {
	Id     int64
	Device *Device `pg:"rel:has-one" sql:"on_delete:CASCADE"`
	Data   string  `pg:"type:jsonb"`
}

//DeviceMetric db model
type DeviceMetric struct {
	Id     int64
	Device *Device `pg:"rel:has-one" sql:"on_delete:CASCADE"`
	Data   string  `pg:"type:jsonb"`
}

//DeviceRequests db model
type DeviceRequests struct {
	Id     int64
	Device *Device `pg:"rel:has-one" sql:"on_delete:CASCADE"`
	Data   string  `pg:"type:jsonb"`
}

//App db model
type App struct {
	Id     int64
	UUID   string
	Device *Device `pg:"rel:has-one" sql:"on_delete:CASCADE"`
}

//AppLog db model
type AppLog struct {
	Id   int64
	App  *App   `pg:"rel:has-one" sql:"on_delete:CASCADE"`
	Data string `pg:"type:jsonb"`
}

const (
	MB                      = common.MB
	maxLogSizePostgres      = 100 * MB
	maxInfoSizePostgres     = 100 * MB
	maxMetricSizePostgres   = 100 * MB
	maxRequestsSizePostgres = 100 * MB
	maxAppLogsSizePostgres  = 100 * MB
)

//StreamType to write objects into DB
type StreamType string

const (
	StreamTypeLog     StreamType = "log"
	StreamTypeInfo    StreamType = "info"
	StreamTypeMetric  StreamType = "metric"
	StreamTypeRequest StreamType = "request"
	StreamTypeAppLog  StreamType = "app"
)

// ManagedStream stream of data interface
type ManagedStream struct {
	variant StreamType
	id      int64
	client  *pg.DB
}

func (m *ManagedStream) Get(_ int) ([]byte, error) {
	return nil, errors.New("unsupported")
}

func (m *ManagedStream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	switch m.variant {
	case StreamTypeAppLog:
		var app App
		if err := m.client.Model(&app).Where("id = ?", m.id).Select(); err != nil {
			al := &AppLog{
				App:  &app,
				Data: string(b),
			}
			if _, err := m.client.Model(al).Insert(); err != nil {
				return 0, err
			}
			if _, err := m.client.Exec(fmt.Sprintf("NOTIFY %s, '%d'", m.variant, al.Id)); err != nil {
				return 0, err
			}
		}
	case StreamTypeLog:
		var device Device
		if err := m.client.Model(&device).Where("id = ?", m.id).Select(); err != nil {
			dl := &DeviceLog{
				Device: &device,
				Data:   string(b),
			}
			if _, err := m.client.Model(dl).Insert(); err != nil {
				return 0, err
			}
			if _, err := m.client.Exec(fmt.Sprintf("NOTIFY %s, '%d'", m.variant, dl.Id)); err != nil {
				return 0, err
			}
		}
	case StreamTypeMetric:
		var device Device
		if err := m.client.Model(&device).Where("id = ?", m.id).Select(); err != nil {
			dm := &DeviceMetric{
				Device: &device,
				Data:   string(b),
			}
			if _, err := m.client.Model().Insert(dm); err != nil {
				return 0, err
			}
			if _, err := m.client.Exec(fmt.Sprintf("NOTIFY %s, '%d'", m.variant, dm.Id)); err != nil {
				return 0, err
			}
		}
	case StreamTypeInfo:
		var device Device
		if err := m.client.Model(&device).Where("id = ?", m.id).Select(); err != nil {
			di := &DeviceInfo{
				Device: &device,
				Data:   string(b),
			}
			if _, err := m.client.Model(di).Insert(); err != nil {
				return 0, err
			}
			if _, err := m.client.Exec(fmt.Sprintf("NOTIFY %s, '%d'", m.variant, di.Id)); err != nil {
				return 0, err
			}
		}
	case StreamTypeRequest:
		var device Device
		if err := m.client.Model(&device).Where("id = ?", m.id).Select(); err != nil {
			dr := &DeviceRequests{
				Device: &device,
				Data:   string(b),
			}
			if _, err := m.client.Model().Insert(dr); err != nil {
				return 0, err
			}
			if _, err := m.client.Exec(fmt.Sprintf("NOTIFY %s, '%d'", m.variant, dr.Id)); err != nil {
				return 0, err
			}
		}
	default:
		return 0, fmt.Errorf("not implemented: %s", m.variant)
	}
	return len(b), nil
}

func (m *ManagedStream) Reader() (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

// DeviceManager implementation of DeviceManager interface with a Postgres DB as the backing store
type DeviceManager struct {
	client       *pg.DB
	database     string
	cacheTimeout int
	lastUpdate   time.Time
	// these are for caching only
	onboardCerts map[string]map[string]bool
	deviceCerts  map[string]uuid.UUID
	devices      map[uuid.UUID]common.DeviceStorage
}

// Name return name
func (d *DeviceManager) Name() string {
	return "postgres"
}

// Database return database hostname and port
func (d *DeviceManager) Database() string {
	return d.database
}

// MaxLogSize return the default maximum log size in bytes for this device manager
func (d *DeviceManager) MaxLogSize() int {
	return maxLogSizePostgres
}

// MaxInfoSize return the default maximum info size in bytes for this device manager
func (d *DeviceManager) MaxInfoSize() int {
	return maxInfoSizePostgres
}

// MaxMetricSize return the maximum metrics size in bytes for this device manager
func (d *DeviceManager) MaxMetricSize() int {
	return maxMetricSizePostgres
}

// MaxRequestsSize return the maximum requests log size in bytes for this device manager
func (d *DeviceManager) MaxRequestsSize() int {
	return maxRequestsSizePostgres
}

// MaxAppLogsSize return the maximum app logs size in bytes for this device manager
func (d *DeviceManager) MaxAppLogsSize() int {
	return maxAppLogsSizePostgres
}

// Init check if a URL is valid and initialize
func (d *DeviceManager) Init(s string, _ common.MaxSizes) (bool, error) {
	URL, err := url.Parse(s)
	if err != nil || URL.Scheme != "postgres" {
		return false, err
	}
	if URL.Path != "" {
		d.database = strings.Trim(URL.Path, "/")
	} else {
		d.database = "postgres"
	}
	username := "postgres"
	if URL.User.Username() != "" {
		username = URL.User.Username()
	}
	password := ""
	passwordSet := false
	if password, passwordSet = URL.User.Password(); !passwordSet {
		password = "postgres"
	}
	d.client = pg.Connect(&pg.Options{
		User:     username,
		Password: password,
		Database: d.database,
		Addr:     URL.Host,
	})
	if d.client == nil {
		return false, fmt.Errorf("cannot open connection")
	}
	if err := createSchema(d.client); err != nil {
		return false, err
	}
	return true, nil
}

// createSchema creates database schema for User and Story models.
func createSchema(db *pg.DB) error {
	models := []interface{}{
		(*OnboardCert)(nil),
		(*Device)(nil),
		(*DeviceInfo)(nil),
		(*DeviceLog)(nil),
		(*DeviceMetric)(nil),
		(*DeviceRequests)(nil),
		(*App)(nil),
		(*AppLog)(nil),
	}

	for _, model := range models {
		err := db.Model(model).CreateTable(&orm.CreateTableOptions{
			Temp: true,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SetCacheTimeout set the timeout for refreshing the cache, unused in memory
func (d *DeviceManager) SetCacheTimeout(timeout int) {
	d.cacheTimeout = timeout
}

// OnboardCheck see if a particular certificate and serial combination is valid
func (d *DeviceManager) OnboardCheck(cert *x509.Certificate, serial string) error {
	// do not accept a nil certificate
	if cert == nil {
		return fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}

	if err := d.checkValidOnboardSerial(cert, serial); err != nil {
		return err
	}
	if d.getOnboardSerialDevice(cert, serial) != nil {
		return &common.UsedSerialError{Err: fmt.Sprintf("serial already used for onboarding certificate: %s", serial)}
	}
	return nil
}

// OnboardGet get the onboard cert and its serials based on Common Name
func (d *DeviceManager) OnboardGet(cn string) (*x509.Certificate, []string, error) {
	if cn == "" {
		return nil, nil, fmt.Errorf("empty cn")
	}

	cert, serials, err := d.readCertOnboard(cn)
	if err != nil {
		return nil, nil, err
	}
	return cert, serials, nil
}

// OnboardList list all of the known Common Names for onboard
func (d *DeviceManager) OnboardList() ([]string, error) {
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	cns := make([]string, 0)
	for certStr := range d.onboardCerts {
		certRaw := []byte(certStr)
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %v", err)
		}
		cns = append(cns, cert.Subject.CommonName)
	}
	return cns, nil
}

// OnboardRemove remove an onboard certificate based on Common Name
func (d *DeviceManager) OnboardRemove(cn string) (result error) {
	_, result = d.client.Model(&OnboardCert{}).Where("cn = ?", cn).Delete()
	return
}

// OnboardClear remove all onboarding certs
func (d *DeviceManager) OnboardClear() error {
	if err := d.client.Model(&OnboardCert{}).DropTable(&orm.DropTableOptions{Cascade: false, IfExists: true}); err != nil {
		return fmt.Errorf("unable to remove the onboarding certificates/serials: %v", err)
	}
	if err := d.client.Model(&OnboardCert{}).CreateTable(&orm.CreateTableOptions{Temp: true}); err != nil {
		return fmt.Errorf("unable to recreate onboarding certificates/serials: %v", err)
	}

	d.onboardCerts = map[string]map[string]bool{}
	return nil
}

// DeviceCheckCert see if a particular certificate is a valid registered device certificate
func (d *DeviceManager) DeviceCheckCert(cert *x509.Certificate) (*uuid.UUID, error) {
	if cert == nil {
		return nil, fmt.Errorf("invalid nil certificate")
	}
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	certStr := string(cert.Raw)
	if u, ok := d.deviceCerts[certStr]; ok {
		return &u, nil
	}
	return nil, nil
}

// DeviceRemove remove a device
func (d *DeviceManager) DeviceRemove(u *uuid.UUID) error {
	_, err := d.client.Model(&Device{}).Where("uuid = ?", u.String()).Delete()
	if err != nil {
		return fmt.Errorf("unable to remove the device: %v", err)
	}
	// refresh the cache
	err = d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh device cache: %v", err)
	}
	return nil
}

// DeviceClear remove all devices
func (d *DeviceManager) DeviceClear() error {
	if err := d.client.Model(&Device{}).DropTable(&orm.DropTableOptions{Cascade: false, IfExists: true}); err != nil {
		return fmt.Errorf("unable to remove the devices: %v", err)
	}
	if err := d.client.Model(&Device{}).CreateTable(&orm.CreateTableOptions{Temp: true}); err != nil {
		return fmt.Errorf("unable to recreate devices: %v", err)
	}

	d.deviceCerts = map[string]uuid.UUID{}
	d.devices = map[uuid.UUID]common.DeviceStorage{}
	return nil
}

// DeviceGet get an individual device by UUID
func (d *DeviceManager) DeviceGet(u *uuid.UUID) (*x509.Certificate, *x509.Certificate, string, error) {
	if u == nil {
		return nil, nil, "", fmt.Errorf("empty UUID")
	}

	device := &Device{}
	if err := d.client.Model(device).Where("uuid = ?", u.String()).Select(); err != nil {
		return nil, nil, "", fmt.Errorf("error in request: %s", err)
	}

	devCert, err := ax.ParseCert(device.Cert)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error decoding device certificate for %s: %v (%s)", u.String(), err, device.Cert)
	}

	cert, err := ax.ParseCert(device.Onboard)
	if err != nil {
		return nil, nil, "", fmt.Errorf("error decoding onboard certificate for %s: %v (%s)", u.String(), err, device.Onboard)
	}
	// somehow device serials are best effort
	return devCert, cert, device.Serial, nil
}

// DeviceList list all of the known UUIDs for devices
func (d *DeviceManager) DeviceList() ([]*uuid.UUID, error) {
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	ids := make([]uuid.UUID, 0, len(d.devices))
	for u := range d.devices {
		ids = append(ids, u)
	}
	pids := make([]*uuid.UUID, 0, len(ids))
	for i := range ids {
		pids = append(pids, &ids[i])
	}
	return pids, nil
}

// DeviceRegister register a new device cert
func (d *DeviceManager) DeviceRegister(unew uuid.UUID, cert, onboard *x509.Certificate, serial string, conf []byte) error {
	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	// check if it already exists - this also checks for nil cert
	u, err := d.DeviceCheckCert(cert)
	if err != nil {
		return err
	}
	// if we found a uuid, then it already exists
	if u != nil {
		return fmt.Errorf("device already registered")
	}
	dev := &Device{
		Onboard: ax.PemEncodeCert(onboard.Raw),
		Serial:  serial,
		Cert:    ax.PemEncodeCert(cert.Raw),
		Config:  string(conf),
		UUID:    unew.String(),
	}
	if _, err := d.client.Model(dev).Insert(); err != nil {
		return fmt.Errorf("failed to save config for %s: %v", u.String(), err)
	}

	// save new one to cache - just the serial and onboard; the rest is on disk
	d.deviceCerts[string(cert.Raw)] = unew
	d.devices[unew] = d.initDevice(dev.Id, onboard, serial)
	ds := d.devices[unew]

	// create the necessary Postgres streams for this device
	for _, ms := range []common.BigData{ds.Logs, ds.Info, ds.Metrics, ds.Requests} {
		if _, err := ms.Write([]byte("")); err != nil {
			return fmt.Errorf("error creating stream: %v", err)
		}
	}

	return nil
}

// initDevice initialize a device
func (d *DeviceManager) initDevice(id int64, onboard *x509.Certificate, serial string) common.DeviceStorage {
	return common.DeviceStorage{
		Onboard: onboard,
		Serial:  serial,
		Logs: &ManagedStream{
			variant: StreamTypeLog,
			id:      id,
			client:  d.client,
		},
		Info: &ManagedStream{
			variant: StreamTypeInfo,
			id:      id,
			client:  d.client,
		},
		Metrics: &ManagedStream{
			variant: StreamTypeMetric,
			id:      id,
			client:  d.client,
		},
		Requests: &ManagedStream{
			variant: StreamTypeRequest,
			id:      id,
			client:  d.client,
		},
		AppLogs: map[uuid.UUID]common.BigData{},
	}
}

// OnboardRegister register an onboard cert and update its serials
func (d *DeviceManager) OnboardRegister(cert *x509.Certificate, serial []string) error {
	if cert == nil {
		return fmt.Errorf("empty nil certificate")
	}
	certStr := string(cert.Raw)
	cn := common.GetOnboardCertName(cert.Subject.CommonName)

	if err := d.writeCertOnboard(cert.Raw, cn, serial); err != nil {
		return err
	}

	// update the cache
	if d.onboardCerts == nil {
		d.onboardCerts = map[string]map[string]bool{}
	}
	serialList := map[string]bool{}
	for _, s := range serial {
		serialList[s] = true
	}
	d.onboardCerts[certStr] = serialList

	return nil
}

// WriteRequest record a request
func (d *DeviceManager) WriteRequest(u uuid.UUID, b []byte) error {
	if dev, ok := d.devices[u]; ok {
		return dev.AddRequest(b)
	}
	return fmt.Errorf("device not found: %s", u)
}

// WriteInfo write an info message
func (d *DeviceManager) WriteInfo(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddInfo(b)
}

// WriteLogs write a message of logs
func (d *DeviceManager) WriteLogs(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddLogs(b)
}

// appExists return if an app has been created
func (d *DeviceManager) appExists(u, instanceID uuid.UUID) bool {
	if _, ok := d.devices[u]; !ok {
		return false
	}
	if _, ok := d.devices[u].AppLogs[instanceID]; !ok {
		return false
	}
	return true
}

// WriteAppInstanceLogs write a message of AppInstanceLogBundle
func (d *DeviceManager) WriteAppInstanceLogs(instanceID uuid.UUID, deviceID uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	dev, ok := d.devices[deviceID]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", deviceID)
	}
	if !d.appExists(deviceID, instanceID) {
		device := &Device{}
		if err := d.client.Model(device).Where("uuid = ?", deviceID.String()).Select(); err != nil {
			return fmt.Errorf("cannot find device: %s", err)
		}
		app := &App{Device: device, UUID: instanceID.String()}
		if _, err := d.client.Model(&App{}).Insert(); err != nil {
			return fmt.Errorf("cannot create app: %s", err)
		}
		d.devices[deviceID].AppLogs[instanceID] = &ManagedStream{
			variant: StreamTypeAppLog,
			id:      app.Id,
			client:  d.client,
		}
	}
	return dev.AddAppLog(instanceID, b)
}

// WriteMetrics write a metrics message
func (d *DeviceManager) WriteMetrics(u uuid.UUID, b []byte) error {
	// make sure it is not nil
	if len(b) < 1 {
		return nil
	}
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("device not found: %s", u)
	}
	return dev.AddMetrics(b)
}

// GetConfig retrieve the config for a particular device
func (d *DeviceManager) GetConfig(u uuid.UUID) ([]byte, error) {
	// hold our config
	device := &Device{}
	if err := d.client.Model(device).Where("uuid = ?", u.String()).Select(); err != nil {
		return nil, fmt.Errorf("error in request: %s", err)
	}
	return []byte(device.Config), nil
}

// SetConfig set the config for a particular device
func (d *DeviceManager) SetConfig(u uuid.UUID, b []byte) error {
	// pre-flight checks to bail early
	if len(b) < 1 {
		return fmt.Errorf("empty configuration")
	}

	// refresh certs from Postgres, if needed - includes checking if necessary based on timer
	err := d.refreshCache()
	if err != nil {
		return fmt.Errorf("unable to refresh certs from Postgres: %v", err)
	}
	// look up the device by uuid
	_, ok := d.devices[u]
	if !ok {
		return fmt.Errorf("unregistered device UUID %s", u.String())
	}

	device := &Device{}
	if err := d.client.Model(device).Where("uuid = ?", u.String()).Select(); err != nil {
		return fmt.Errorf("error in request: %s", err)
	}
	device.Config = string(b)
	if _, err := d.client.Model(device).Where("uuid = ?", u.String()).Update(); err != nil {
		return fmt.Errorf("error in request: %s", err)
	}
	return nil
}

// GetLogsReader get the logs for a given uuid
func (d *DeviceManager) GetLogsReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Logs.Reader()
}

// GetInfoReader get the info for a given uuid
func (d *DeviceManager) GetInfoReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Info.Reader()
}

// GetRequestsReader get the requests for a given uuid
func (d *DeviceManager) GetRequestsReader(u uuid.UUID) (io.Reader, error) {
	// check that the device actually exists
	dev, ok := d.devices[u]
	if !ok {
		return nil, fmt.Errorf("unregistered device UUID: %s", u)
	}
	return dev.Requests.Reader()
}

// refreshCache refresh cache from disk
func (d *DeviceManager) refreshCache() error { // is it time to update the cache again?
	now := time.Now()
	if now.Sub(d.lastUpdate).Seconds() < float64(d.cacheTimeout) {
		return nil
	}

	// create new vars to hold while we load
	onboardCerts := make(map[string]map[string]bool)
	deviceCerts := make(map[string]uuid.UUID)
	devices := make(map[uuid.UUID]common.DeviceStorage)

	var listOnboard []OnboardCert
	if err := d.client.Model(&listOnboard).Select(); err != nil {
		return fmt.Errorf("failed to retrieve onboarding certificated %v", err)
	}

	for _, c := range listOnboard {
		certPem, _ := pem.Decode(c.Cert)
		if certPem == nil {
			return fmt.Errorf("unable to convert data from %s", c.Cert)
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to onboard certificate: %v", c.Cert, err)
		}
		certStr := string(cert.Raw)

		onboardCerts[certStr] = make(map[string]bool)

		for _, serial := range c.Serials {
			onboardCerts[certStr][serial] = true
		}
	}
	// replace the existing onboard certificates
	d.onboardCerts = onboardCerts

	var listDevice []Device
	if err := d.client.Model(&listDevice).Select(); err != nil {
		return fmt.Errorf("failed to retrieve device certificates %v", err)
	}

	for _, c := range listDevice {
		// load the device certificate
		certPem, _ := pem.Decode(c.Cert)
		if certPem == nil {
			return fmt.Errorf("unable to convert data from %s", c.Cert)
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to device certificate: %v", c.Cert, err)
		}
		certStr := string(cert.Raw)
		u, err := uuid.FromString(c.UUID)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		deviceCerts[certStr] = u
		devices[u] = d.initDevice(c.Id, cert, c.Serial) // start with no serial, as it will be added further down

		certPem, _ = pem.Decode(c.Onboard)
		cert, err = x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return fmt.Errorf("unable to convert data from %s to device onboard certificate: %v", c.Onboard, err)
		}
		// because of the "cannot assign to struct field" golang issue
		devItem := devices[u]
		devItem.Onboard = cert
		devItem.Config = []byte(c.Config)
		devices[u] = devItem
	}
	// replace the existing device certificates
	d.deviceCerts = deviceCerts

	var listApp []App
	err := d.client.Model(&listApp).Select()
	if err != nil {
		return fmt.Errorf("failed to retrieve device app logs streams %v", err)
	}
	for _, el := range listApp {
		u, err := uuid.FromString(el.UUID)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		du, err := uuid.FromString(el.Device.UUID)
		if err != nil {
			return fmt.Errorf("unable to convert data from uuid %v", err)
		}
		devices[du].AppLogs[u] = &ManagedStream{
			variant: StreamTypeAppLog,
			id:      el.Id,
			client:  d.client,
		}
	}
	// replace the existing device cache
	d.devices = devices

	// mark the time we updated
	d.lastUpdate = now
	return nil
}

// checkValidOnboardSerial see if a particular certificate+serial combinaton is valid
// does **not** check if it has been used
func (d *DeviceManager) checkValidOnboardSerial(cert *x509.Certificate, serial string) error {
	certStr := string(cert.Raw)
	if c, ok := d.onboardCerts[certStr]; ok {
		// accept the specific serial or the wildcard
		if _, ok := c[serial]; ok {
			return nil
		}
		if _, ok := c["*"]; ok {
			return nil
		}
		return &common.InvalidSerialError{Err: fmt.Sprintf("unknown serial: %s", serial)}
	}
	return &common.InvalidCertError{Err: "unknown onboarding certificate"}
}

// getOnboardSerialDevice see if a particular certificate+serial combinaton has been used and get its device uuid
func (d *DeviceManager) getOnboardSerialDevice(cert *x509.Certificate, serial string) *uuid.UUID {
	certStr := string(cert.Raw)
	for uid, dev := range d.devices {
		dCertStr := string(dev.Onboard.Raw)
		if dCertStr == certStr && serial == dev.Serial {
			return &uid
		}
	}
	return nil
}

func (d *DeviceManager) readCertOnboard(cn string) (*x509.Certificate, []string, error) {
	onboardCert := &OnboardCert{}
	if err := d.client.Model(onboardCert).Where("cn = ?", cn).Select(); err != nil {
		return nil, nil, fmt.Errorf("error reading certificate for %s: %v", cn, err)
	}

	if cert, err := ax.ParseCert(onboardCert.Cert); err != nil {
		return nil, nil, fmt.Errorf("error decoding onboard certificate for %s: %v (%s)", cn, err, onboardCert.Cert)
	} else {
		return cert, onboardCert.Serials, nil
	}
}

// WriteCert write cert bytes to a path, after pem encoding them
func (d *DeviceManager) writeCertOnboard(cert []byte, cn string, serials []string) error {
	// make sure we have the paths we need, and that they are not already taken, unless we were told to force
	onboardCert := &OnboardCert{}
	if exists, err := d.client.Model(onboardCert).Where("cn = ?", cn).Exists(); err != nil {
		return fmt.Errorf("error in request: %s", err)
	} else if exists {
		return fmt.Errorf("certificate for %s already exists", cn)
	}
	certPem := ax.PemEncodeCert(cert)
	if certPem == nil {
		return fmt.Errorf("cannot decode cert: %s", cert)
	}
	onboardCertNew := &OnboardCert{
		Cn:      cn,
		Cert:    certPem,
		Serials: serials,
	}
	if _, err := d.client.Model(onboardCertNew).Insert(); err != nil {
		return fmt.Errorf("failed to write certificate for %s: %v", cn, err)
	}

	return nil
}
