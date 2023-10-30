// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"errors"
	"log"
	"strconv"
	"strings"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
	"github.com/strongswan/govici/vici"
)

type localOptsParams struct {
	Auth    string   `vici:"auth"`
	Certs   []string `vici:"certs"`
	ID      string   `vici:"id"`
	EapID   string   `vici:"eap_id"`
	AaaID   string   `vici:"aaa_id"`
	XauthID string   `vici:"xauth_id"`
	PubKeys []string `vici:"pubkeys"`
}

type remoteOptsParams struct {
	Auth       string   `vici:"auth"`
	ID         string   `vici:"id"`
	EapID      string   `vici:"eap_id"`
	Groups     []string `vici:"groups"`
	CertPolicy []string `vici:"cert_policy"`
	Certs      []string `vici:"certs"`
	CaCerts    []string `vici:"cacerts"`
	PubKeys    []string `vici:"pubkeys"`
}

type childSAParams struct {
	RemoteTrafficSelectors []string `vici:"remote_ts"`
	LocalTrafficSelectors  []string `vici:"local_ts"`
	Updown                 string   `vici:"updown"`
	ESPProposals           []string `vici:"esp_proposals"`
	AgProposals            []string `vici:"ag_proposals"`
	RekeyTime              string   `vici:"rekey_time"`
	LifeTime               string   `vici:"life_time"`
	RandTime               string   `vici:"rand_time"`
	Inactivity             uint32   `vici:"inactivity"`
	MarkIn                 uint32   `vici:"mark_in"`
	MarkInSa               string   `vici:"mark_in_sa"`
	MarkOut                uint32   `vici:"mark_out"`
	SetMarkIn              uint32   `vici:"set_mark_in"`
	SetMarkOut             uint32   `vici:"set_mark_out"`
	HwOffload              string   `vici:"hw_offload"`
}

type connectionParams struct {
	Name string // This field will NOT be marshaled!

	LocalAddrs  []string                 `vici:"local_addrs"`
	RemoteAddrs []string                 `vici:"remote_addrs"`
	Local       localOptsParams          `vici:"local"`
	Remote      remoteOptsParams         `vici:"remote"`
	Children    map[string]childSAParams `vici:"children"`
	Version     int                      `vici:"version"`
	Proposals   []string                 `vici:"proposals"`
	Vips        []string                 `vici:"vips"`
	LocalPort   uint32                   `vici:"local_port"`
	RemotePort  uint32                   `vici:"remote_port"`
	Dscp        uint64                   `vici:"dscp"`
	Encap       string                   `vici:"encap"`
	Mobike      string                   `vici:"mobike"`
	DpdDelay    uint32                   `vici:"dpd_delay"`
	DpdTimeout  uint32                   `vici:"dpd_timeout"`
	ReauthTime  uint32                   `vici:"reauth_time"`
	RekeyTime   string                   `vici:"rekey_time"`
	Pools       []string                 `vici:"pools"`
}

type unloadConnectionParams struct {
	// Cname string // This field will NOT be marshaled!
	Name string `vici:"name"`
}

type initConnectionParams struct {
	Child      string `vici:"child"`
	Ike        string `vici:"ike"`
	Timeout    int    `vici:"timeout"`
	InitLimits string `vici:"init-limits"`
	LogLevel   string `vici:"loglevel"`
}

type terminateConnectionParams struct {
	Child    string `vici:"child"`
	Ike      string `vici:"ike"`
	ChildID  uint64 `vici:"child-id"`
	IkeID    uint64 `vici:"ike-id"`
	Force    string `vici:"force"`
	Timeout  int    `vici:"timeout"`
	LogLevel string `vici:"loglevel"`
}

type rekeyConnectionParams struct {
	Child   string `vici:"child"`
	Ike     string `vici:"ike"`
	ChildID uint64 `vici:"child-id"`
	IkeID   uint64 `vici:"ike-id"`
	Reauth  bool   `vici:"reauth"`
}

type listSasParams struct {
	Ike     string `vici:"ike"`
	IkeID   uint64 `vici:"ike-id"`
	Child   string `vici:"child"`
	ChildID uint64 `vici:"child-id"`
	Noblock string `vici:"noblock"`
}

type listConnsParams struct {
	Ike string `vici:"ike"`
}

type listCertsParams struct {
	Type    string `vici:"type"`
	Flag    string `vici:"flag"`
	Subject string `vici:"subject"`
}

type listChildSaParams struct {
	Protocol     string `vici:"protocol"`
	Encap        string `vici:"encap"`
	SpiIn        string `vici:"spi-in"`
	SpiOut       string `vici:"spi-out"`
	CpiIn        string `vici:"cpi-in"`
	CpiOut       string `vici:"cpi-out"`
	MarkIn       string `vici:"mark-in"`
	MarkMaskIn   string `vici:"mark-mask-in"`
	MarkOut      string `vici:"mark-out"`
	MarkMaskOut  string `vici:"mark-mask-out"`
	IfIDIn       string `vici:"if-id-in"`
	IfIDOut      string `vici:"if-id-out"`
	EncrAlg      string `vici:"encr-alg"`
	EncKeysize   string `vici:"encr-keysize"`
	IntegAlg     string `vici:"integ-alg"`
	IntegKeysize string `vici:"integ-keysize"`
	DhGroup      string `vici:"dh-group"`
	Esn          string `vici:"esn"`
}

type listIkeSaParams struct {
	UniqueID      string                       `vici:"uniqueid"`
	Version       string                       `vici:"version"`
	State         string                       `vici:"state"`
	LocalHost     string                       `vici:"local-host"`
	LocalPort     string                       `vici:"local-port"`
	LocalID       string                       `vici:"local-id"`
	RemoteHost    string                       `vici:"remote-host"`
	RemotePort    string                       `vici:"remote-port"`
	RemoteID      string                       `vici:"remote-id"`
	RemoteXauthID string                       `vici:"remote-xauth-id"`
	RemoteEapID   string                       `vici:"remote-eap-id"`
	Initiator     string                       `vici:"initiator"`
	InitiatorSpi  string                       `vici:"initiator-spi"`
	ResponderSpi  string                       `vici:"responder-spi"`
	NatLocal      string                       `vici:"nat-local"`
	NatRemote     string                       `vici:"nat-remote"`
	NatFake       string                       `vici:"nat-fake"`
	NatAny        string                       `vici:"nat-any"`
	IfIDIn        string                       `vici:"if-id-in"`
	IfIDOut       string                       `vici:"if-id-out"`
	EncrAlg       string                       `vici:"encr-alg"`
	EncrKeysize   string                       `vici:"encr-keysize"`
	IntegAlg      string                       `vici:"integ-alg"`
	IntegKeysize  string                       `vici:"integ-keysize"`
	PrfAlg        string                       `vici:"prf-alg"`
	DhGroup       string                       `vici:"dh-group"`
	Ppk           string                       `vici:"ppk"`
	Established   string                       `vici:"established"`
	RekeyTime     string                       `vici:"rekey-time"`
	ReauthTime    string                       `vici:"reauth-time"`
	LocalVips     []string                     `vici:"local-vips"`
	RemoteVips    []string                     `vici:"remote-vips"`
	TasksQueued   []string                     `vici:"tasks-queued"`
	TasksActive   []string                     `vici:"tasks-active"`
	TasksPassive  []string                     `vici:"tasks-passive"`
	ChildSas      map[string]listChildSaParams `vici:"child-sas"`
}

type listAuthParams struct {
	Name       string   // This field will NOT be marshaled!
	Class      string   `vici:"class"`
	EapType    string   `vici:"eap-type"`
	EapVendor  string   `vici:"eap-vendor"`
	Xauth      string   `vici:"xauth"`
	Revocation string   `vici:"revocation"`
	ID         string   `vici:"id"`
	CaID       string   `vici:"ca_id"`
	AaaID      string   `vici:"aaa_id"`
	EapID      string   `vici:"eap_id"`
	XauthID    string   `vici:"xauth_id"`
	Groups     []string `vici:"groups"`
	CertPolicy []string `vici:"cert_policy"`
	Certs      []string `vici:"certs"`
	CaCerts    []string `vici:"cacerts"`
}

type listChildParams struct {
	Name         string   // This field will NOT be marshaled!
	Mode         string   `vici:"mode"`
	Label        string   `vici:"label"`
	RekeyTime    uint32   `vici:"rekey_time"`
	RekeyBytes   uint32   `vici:"rekey_bytes"`
	RekeyPackets uint32   `vici:"rekey_packets"`
	DpdAction    string   `vici:"dpd_action"`
	CloseAction  string   `vici:"close_action"`
	RemoteTS     []string `vici:"remote-ts"` // Used by list-conns so we can overload this struct
	LocalTS      []string `vici:"local-ts"`  // Used by list-conns so we can overload this struct
	Interface    string   `vici:"interface"`
	Priority     string   `vici:"priority"`
}

type listIkeParams struct {
	LocalAddrs  []string                   `vici:"local_addrs"`
	RemoteAddrs []string                   `vici:"remote_addrs"`
	Version     string                     `vici:"version"`
	ReauthTime  uint32                     `vici:"reauth_time"`
	RekeyTime   uint32                     `vici:"rekey_time"`
	Unique      string                     `vici:"unique"`
	DpdDelay    uint32                     `vici:"dpd_delay"`
	DpdTimeout  uint32                     `vici:"dpd_timeout"`
	Ppk         string                     `vici:"ppk"`
	PpkRequired string                     `vici:"ppk_required"`
	Local       map[string]listAuthParams  `vici:"local"`
	Remote      map[string]listAuthParams  `vici:"remote"`
	Children    map[string]listChildParams `vici:"children"`
}

type listCertParams struct {
	Type       string `vici:"type"`
	Flag       string `vici:"flag"`
	HasPrivKey string `vici:"has_privkey"`
	Data       string `vici:"data"`
	Subject    string `vici:"subject"`
	NotBefore  string `vici:"not-before"`
	NotAfter   string `vici:"not-after"`
}

func buildProposal(prop *pb.Proposals) (string, error) {
	var crypto strings.Builder
	var integ strings.Builder
	var prf strings.Builder
	var dh strings.Builder
	var result strings.Builder
	var tstr string

	if prop == nil {
		return "", errors.New("proposal can't be nil")
	}

	for k := 0; k < len(prop.CryptoAlg); k++ {
		crypto.WriteString(strings.TrimPrefix(strings.ToLower(prop.CryptoAlg[k].String()), "crypto_algorithm_"))
		if (k + 1) < len(prop.CryptoAlg) {
			tstr = "-"
			crypto.WriteString(tstr)
		}
	}
	for k := 0; k < len(prop.IntegAlg); k++ {
		integ.WriteString(strings.TrimPrefix(strings.ToLower(prop.IntegAlg[k].String()), "integ_algorithm_"))
		if (k + 1) < len(prop.IntegAlg) {
			tstr = "-"
			integ.WriteString(tstr)
		}
	}
	for k := 0; k < len(prop.Prf); k++ {
		prf.WriteString(strings.TrimPrefix(strings.ToLower(prop.Prf[k].String()), "pr_function_"))
		if (k + 1) < len(prop.Prf) {
			tstr = "-"
			prf.WriteString(tstr)
		}
	}
	for k := 0; k < len(prop.Dhgroups); k++ {
		dh.WriteString(strings.ToLower(prop.Dhgroups[k].String()))
		if (k + 1) < len(prop.Dhgroups) {
			tstr = "-"
			dh.WriteString(tstr)
		}
	}

	if crypto.String() != "" {
		result.WriteString(crypto.String())
		if integ.String() != "" || prf.String() != "" || dh.String() != "" {
			tstr = "-"
			result.WriteString(tstr)
		}
	}
	if integ.String() != "" {
		result.WriteString(integ.String())
		if prf.String() != "" || dh.String() != "" {
			tstr = "-"
			result.WriteString(tstr)
		}
	}
	if prf.String() != "" {
		result.WriteString(prf.String())
		if dh.String() != "" {
			tstr = "-"
			result.WriteString(tstr)
		}
	}
	if dh.String() != "" {
		result.WriteString(dh.String())
	}

	return result.String(), nil
}

func ipsecVersion() (*pb.IPsecVersionResponse, error) {
	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return nil, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	m, err := s.CommandRequest("version", nil)
	if err != nil {
		log.Printf("Failed getting version")
		return nil, err
	}

	daemon := m.Get("daemon").(string)
	version := m.Get("version").(string)
	sysname := m.Get("sysname").(string)
	release := m.Get("release").(string)
	machine := m.Get("machine").(string)

	// Assemble return value
	verresp := &pb.IPsecVersionResponse{
		Daemon:  daemon,
		Version: version,
		Sysname: sysname,
		Release: release,
		Machine: machine,
	}

	return verresp, err
}

//nolint:funlen
func ipsecStats() (*pb.IPsecStatsResponse, error) {
	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return nil, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	m, err := s.CommandRequest("stats", nil)
	if err != nil {
		log.Printf("Failed getting stats")
		return nil, err
	}

	var result strings.Builder

	value := m.Get("uptime")
	field, ok := value.(*vici.Message)
	if !ok {
		log.Printf("Embedded map key was not marshaled as a sub-message")
	} else {
		running := field.Get("running").(string)
		since := field.Get("since").(string)
		result.WriteString("Running time: " + running + "\n")
		result.WriteString("Absolute startup time: " + since + "\n")
	}

	value = m.Get("workers")
	field, ok = value.(*vici.Message)
	if !ok {
		log.Printf("Cannot find workers in map")
	} else {
		total := field.Get("total").(string)
		idle := field.Get("idle").(string)
		result.WriteString("Total # of worker threads: " + total + "\n")
		result.WriteString("Worker threads currently idle: " + idle + "\n")

		value = field.Get("active")
		subfield, subok := value.(*vici.Message)
		if !subok {
			log.Printf("Cannot find active in map")
		} else {
			critical := subfield.Get("critical").(string)
			high := subfield.Get("high").(string)
			medium := subfield.Get("medium").(string)
			low := subfield.Get("low").(string)
			result.WriteString("Threads processing critical priority jobs: " + critical + "\n")
			result.WriteString("Threads processing high priority jobs: " + high + "\n")
			result.WriteString("Threads processing medium priority jobs: " + medium + "\n")
			result.WriteString("Threads processing low priority jobs: " + low + "\n")
		}
	}

	value = m.Get("queues")
	field, ok = value.(*vici.Message)
	if !ok {
		log.Printf("Cannot find queues in map")
	} else {
		critical := field.Get("critical").(string)
		high := field.Get("high").(string)
		medium := field.Get("medium").(string)
		low := field.Get("low").(string)
		result.WriteString("Jobs queued with critical priority: " + critical + "\n")
		result.WriteString("Jobs queued with high priority: " + high + "\n")
		result.WriteString("Jobs queued with medium priority: " + medium + "\n")
		result.WriteString("Jobs queued with low priority: " + low + "\n")
	}

	scheduled := m.Get("scheduled").(string)
	result.WriteString("# of jobs scheduled for timed execution: " + scheduled + "\n")

	value = m.Get("ikesas")
	field, ok = value.(*vici.Message)
	if !ok {
		log.Printf("Cannot find ikesas")
	} else {
		total := field.Get("total").(string)
		halfOpen := field.Get("half-open").(string)
		result.WriteString("Total number of IKE_SAs active: " + total + "\n")
		result.WriteString("Number of IKE_SAs in half-open state: " + halfOpen + "\n")
	}

	result.WriteString("Plugins: ")
	plugins := m.Get("plugins").([]string)
	for c := 0; c < len(plugins); c++ {
		result.WriteString(plugins[c] + " ")
	}
	result.WriteString("\n")

	value = m.Get("mem")
	field, ok = value.(*vici.Message)
	if !ok {
		log.Printf("Cannot find mem")
	} else {
		total := field.Get("total").(string)
		allocs := field.Get("allocs").(string)
		result.WriteString("Total heap memory usage in bytes: " + total + "\n")
		result.WriteString("Total heap allocation in blocks: " + allocs + "\n")

		// NOTE: Skipping heap-name (Windows only) for now since OPI
		//       does not run on Windows.
	}

	value = m.Get("mallinfo")
	field, ok = value.(*vici.Message)
	if !ok {
		log.Printf("Cannot find mallinfo")
	} else {
		sbrk := field.Get("sbrk").(string)
		mmap := field.Get("mmap").(string)
		used := field.Get("used").(string)
		free := field.Get("free").(string)
		result.WriteString("Non-mmap'd space available: " + sbrk + "\n")
		result.WriteString("Mmap'd space available: " + mmap + "\n")
		result.WriteString("Total number of bytes used: " + used + "\n")
		result.WriteString("Available but unsued bytes: " + free + "\n")
	}

	statsresp := &pb.IPsecStatsResponse{
		Status: result.String(),
	}

	return statsresp, nil
}

//nolint:funlen,gocognit,gocyclo
func loadConn(connreq *pb.IPsecLoadConnRequest) error {
	// Declare the connection variable, as we have to conditionally load it
	var conn = &connectionParams{
		LocalPort:  500,
		RemotePort: 500,
		RekeyTime:  "4h",
	}
	c := connreq.GetConnection()

	if c.GetName() != "" {
		conn.Name = c.GetName()
	}
	if c.GetVersion() != "" {
		ver, _ := strconv.Atoi(c.GetVersion())
		conn.Version = ver
	} else {
		conn.Version = 2
	}
	if c.GetLocalPort() != 0 {
		conn.LocalPort = c.GetLocalPort()
	}
	if c.GetRemotePort() != 0 {
		conn.RemotePort = c.GetRemotePort()
	}
	log.Printf("Local Port [%d] Remote Port [%d]", conn.LocalPort, conn.RemotePort)

	if c.GetDscp() != 0 {
		conn.Dscp = c.GetDscp()
	}
	if c.GetEncap() != "" {
		conn.Encap = c.GetEncap()
	}
	if c.GetMobike() != "" {
		conn.Mobike = c.GetMobike()
	}
	if c.GetDpdDelay() != 0 {
		conn.DpdDelay = c.GetDpdDelay()
	}
	if c.GetDpdTimeout() != 0 {
		conn.DpdTimeout = c.GetDpdTimeout()
	}
	if c.GetReauthTime() != 0 {
		conn.ReauthTime = c.GetReauthTime()
	}
	if c.GetRekeyTime() != 0 {
		var s = strconv.FormatUint(uint64(c.GetRekeyTime()), 10)
		conn.RekeyTime = s + "s"
	}
	if c.GetLocalAuth() != nil {
		conn.Local = localOptsParams{
			Auth: strings.TrimPrefix(strings.ToLower(c.GetLocalAuth().GetAuth().String()), "auth_type_"),
			ID:   c.GetLocalAuth().GetId(),
		}

		log.Printf("DUMPING conn.Local: %v", conn.Local)
	}
	if c.GetRemoteAuth() != nil {
		conn.Remote = remoteOptsParams{
			Auth: strings.TrimPrefix(strings.ToLower(c.GetRemoteAuth().GetAuth().String()), "auth_type_"),
			ID:   c.GetRemoteAuth().GetId(),
		}

		log.Printf("DUMPING conn.Remove: %v", conn.Remote)
	}

	if c.Vips != nil {
		for i := 0; i < len(c.Vips.Vip); i++ {
			conn.Vips = append(conn.Vips, c.Vips.Vip[i])
		}
	}

	for i := 0; i < len(c.LocalAddrs); i++ {
		conn.LocalAddrs = append(conn.LocalAddrs, c.LocalAddrs[i].GetAddr())
	}
	for i := 0; i < len(c.RemoteAddrs); i++ {
		conn.RemoteAddrs = append(conn.RemoteAddrs, c.RemoteAddrs[i].GetAddr())
	}
	if c.Pools != nil {
		for i := 0; i < len(c.Pools.Pool); i++ {
			conn.Pools = append(conn.Pools, c.Pools.Pool[i])
		}
	}

	if c.Proposals != nil {
		ikeProposal, _ := buildProposal(c.Proposals)
		conn.Proposals = []string{ikeProposal}
		log.Printf("IKE proposal: %v", conn.Proposals)
	}

	for i := 0; i < len(c.Children); i++ {
		var localTS []string
		var remoteTS []string

		if c.Children[i].LocalTs != nil {
			for k := 0; k < len(c.Children[i].LocalTs.Ts); k++ {
				localTS = append(localTS, c.Children[i].LocalTs.Ts[k].GetCidr())
			}
		}
		if c.Children[i].RemoteTs != nil {
			for k := 0; k < len(c.Children[i].RemoteTs.Ts); k++ {
				remoteTS = append(remoteTS, c.Children[i].RemoteTs.Ts[k].GetCidr())
			}
		}
		log.Printf("Dumping local_ts [%v] remote_ts [%v]", localTS, remoteTS)

		csa := childSAParams{
			LocalTrafficSelectors:  localTS,
			RemoteTrafficSelectors: remoteTS,
			RekeyTime:              "1h",
			LifeTime:               "66m",
			Inactivity:             c.Children[i].GetInactivity(),
			MarkIn:                 c.Children[i].GetMarkIn(),
			MarkInSa:               "no",
			MarkOut:                c.Children[i].GetMarkOut(),
			SetMarkIn:              c.Children[i].GetSetMarkIn(),
			SetMarkOut:             c.Children[i].GetSetMarkOut(),
			HwOffload:              "no",
		}
		if c.Children[i].EspProposals != nil {
			proposal, _ := buildProposal(c.Children[i].EspProposals)
			csa.ESPProposals = []string{proposal}
		}
		if c.Children[i].AgProposals != nil {
			agProposal, _ := buildProposal(c.Children[i].AgProposals)
			csa.AgProposals = []string{agProposal}
		}

		if c.Children[i].RekeyTime != 0 {
			var s = strconv.FormatUint(uint64(c.Children[i].GetRekeyTime()), 10)
			csa.RekeyTime = s + "s"
		}
		if c.Children[i].LifeTime != 0 {
			var s = strconv.FormatUint(uint64(c.Children[i].GetLifeTime()), 10)
			csa.LifeTime = s + "s"
		}
		if c.Children[i].RandTime != 0 {
			var s = strconv.FormatUint(uint64(c.Children[i].GetRandTime()), 10)
			csa.RandTime = s + "s"
		}
		if c.Children[i].GetMarkInSa() != "" {
			csa.MarkInSa = c.Children[i].GetMarkInSa()
		}
		if c.Children[i].GetHwOffload() != "" {
			csa.HwOffload = c.Children[i].GetHwOffload()
		}

		conn.Children = make(map[string]childSAParams)
		conn.Children[c.Children[i].GetName()] = csa

		log.Printf("Dumping child object: %v", conn.Children[c.Children[i].GetName()])
		log.Printf("Dumping Proposals: %v", csa.ESPProposals)
	}

	log.Printf("Dumping connection object: %v", conn)

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	mm, err := vici.MarshalMessage(conn)
	if err != nil {
		log.Printf("Failed marshalling message")
		return err
	}

	log.Printf("Marshaled connection request: %v", mm)

	m := vici.NewMessage()
	if err := m.Set(conn.Name, mm); err != nil {
		log.Printf("Failed setting command")
		return err
	}

	_, err = s.CommandRequest("load-conn", m)

	log.Printf("command error return [%v]", err)

	return err
}

func unloadConn(connreq *pb.IPsecUnloadConnRequest) error {
	// Build the connection object
	conn := &unloadConnectionParams{
		Name: connreq.GetName(),
	}

	log.Printf("Dumping connection to unload: %v", conn)

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(conn)
	if err != nil {
		log.Printf("Failed marshalling message")
		return err
	}

	log.Printf("Marshaled vici message: %v", c)

	_, err = s.CommandRequest("unload-conn", c)

	log.Printf("command error return [%v]", err)

	return err
}

func initiateConn(initreq *pb.IPsecInitiateRequest) error {
	params := &initConnectionParams{}

	if initreq.GetChild() != "" {
		params.Child = initreq.GetChild()
	}
	if initreq.GetIke() != "" {
		params.Ike = initreq.GetIke()
	}
	if initreq.GetTimeout() != "" {
		timeout, _ := strconv.Atoi(initreq.GetTimeout())
		params.Timeout = timeout
	}
	if initreq.GetLoglevel() != "" {
		params.LogLevel = initreq.GetLoglevel()
	}

	log.Printf("Dumping connection to initiate: %v", params)

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return err
	}

	log.Printf("Marshaled vici message: %v", c)

	_, err = s.CommandRequest("initiate", c)

	log.Printf("command error return [%v]", err)

	return err
}

func terminateConn(termreq *pb.IPsecTerminateRequest) (uint32, error) {
	params := &terminateConnectionParams{}

	if termreq.GetChild() != "" {
		params.Child = termreq.GetChild()
	}
	if termreq.GetIke() != "" {
		params.Ike = termreq.GetIke()
	}
	if termreq.GetChildId() != 0 {
		params.ChildID = termreq.GetChildId()
	}
	if termreq.GetIkeId() != 0 {
		params.IkeID = termreq.GetIkeId()
	}
	if termreq.GetTimeout() != "" {
		timeout, _ := strconv.Atoi(termreq.GetTimeout())
		params.Timeout = timeout
	}
	if termreq.GetForce() != "" {
		params.Force = termreq.GetForce()
	}
	if termreq.GetLoglevel() != "" {
		params.LogLevel = termreq.GetLoglevel()
	}

	log.Printf("Dumping connection to terminate: %v", params)

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return 0, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return 0, err
	}

	log.Printf("Marshaled vici message: %v", c)

	_, err = s.CommandRequest("terminate", c)

	log.Printf("command error return [%v]", err)

	return 1, err
}

func rekeyConn(rekeyreq *pb.IPsecRekeyRequest) (string, uint32, error) {
	params := &rekeyConnectionParams{}

	if rekeyreq.GetChild() != "" {
		params.Child = rekeyreq.GetChild()
	}
	if rekeyreq.GetIke() != "" {
		params.Ike = rekeyreq.GetIke()
	}
	if rekeyreq.GetChildId() != 0 {
		params.ChildID = rekeyreq.GetChildId()
	}
	if rekeyreq.GetIkeId() != 0 {
		params.IkeID = rekeyreq.GetIkeId()
	}
	if rekeyreq.GetReauth() == "yes" {
		params.Reauth = true
	}

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return "", 0, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return "", 0, err
	}

	log.Printf("Marshaled vici message: %v", c)

	m, err := s.CommandRequest("rekey", c)
	if err != nil {
		log.Printf("Failed getting stats")
		return "", 0, err
	}

	success := m.Get("success").(string)
	strmatches := m.Get("matches").(string)
	matches, err := strconv.ParseUint(strmatches, 10, 32)
	if err != nil {
		log.Printf("Error converting string %s", strmatches)
		return "", 0, err
	}

	return success, uint32(matches), nil
}

func listSas(listreq *pb.IPsecListSasRequest) (*pb.IPsecListSasResponse, error) {
	params := &listSasParams{}

	if listreq.GetChild() != "" {
		params.Child = listreq.GetChild()
	}
	if listreq.GetIke() != "" {
		params.Ike = listreq.GetIke()
	}
	if listreq.GetChildId() != 0 {
		params.ChildID = listreq.GetChildId()
	}
	if listreq.GetIkeId() != 0 {
		params.IkeID = listreq.GetIkeId()
	}
	if listreq.GetNoblock() != "" {
		params.Noblock = listreq.GetNoblock()
	}

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return nil, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return nil, err
	}

	log.Printf("Marshaled vici message: %v", c)

	listMessages, err := s.StreamedCommandRequest("list-sas", "list-sa", c)
	if err != nil {
		log.Printf("Failed getting sas")
		return nil, err
	}

	var sasReply pb.IPsecListSasResponse

	// We stream responses, so build responses now
	for _, mess := range listMessages {
		for _, k := range mess.Keys() {
			listSas := listIkeSaParams{}
			log.Printf("K IS EQUAL TO %v", k)
			sa := mess.Get(k).(*vici.Message)
			err := vici.UnmarshalMessage(sa, &listSas)
			if err != nil {
				log.Printf("Failed marshalling message: %v", err)
				return nil, err
			}
			log.Printf("Found message: %v", listSas)

			ike, err := parseIkeListSas(&listSas, k)
			if err != nil {
				log.Printf("Failed parsing IKE_SA: %v", err)
				return nil, err
			}
			sasReply.Ikesas = append(sasReply.Ikesas, ike)
		}
	}

	return &sasReply, nil
}

func listConns(listreq *pb.IPsecListConnsRequest) (*pb.IPsecListConnsResponse, error) {
	params := &listConnsParams{}

	if listreq.GetIke() != "" {
		params.Ike = listreq.GetIke()
	}

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return nil, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return nil, err
	}

	log.Printf("Marshaled vici message: %v", c)

	listMessages, err := s.StreamedCommandRequest("list-conns", "list-conn", c)
	if err != nil {
		log.Printf("Failed getting conns")
		return nil, err
	}

	var connsReply pb.IPsecListConnsResponse

	// We stream responses, so build responses now
	for _, mess := range listMessages {
		for _, k := range mess.Keys() {
			conn := listIkeParams{}
			log.Printf("K IS EQUAL TO %v", k)
			sa := mess.Get(k).(*vici.Message)
			err := vici.UnmarshalMessage(sa, &conn)
			if err != nil {
				log.Printf("Failed marshalling message: %v", err)
				return nil, err
			}
			log.Printf("Found message: %v", conn)

			parsedConn, err := parseConnection(&conn, k)
			if err != nil {
				log.Printf("Failed parsing connection: %v", err)
				return nil, err
			}
			connsReply.Connection = append(connsReply.Connection, parsedConn)
		}
	}

	return &connsReply, nil
}

func listCerts(listreq *pb.IPsecListCertsRequest) (*pb.IPsecListCertsResponse, error) {
	params := &listCertsParams{}

	if listreq.GetType() != "" {
		params.Type = listreq.GetType()
	}
	if listreq.GetFlag() != "" {
		params.Flag = listreq.GetFlag()
	}
	if listreq.GetSubject() != "" {
		params.Subject = listreq.GetSubject()
	}

	s, err := vici.NewSession()
	if err != nil {
		log.Printf("Failed creating vici session")
		return nil, err
	}
	defer func(conn *vici.Session) {
		err := conn.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(s)

	c, err := vici.MarshalMessage(params)
	if err != nil {
		log.Printf("Failed marshalling message")
		return nil, err
	}

	log.Printf("Marshaled vici message: %v", c)

	listMessages, err := s.StreamedCommandRequest("list-certs", "list-cert", c)
	if err != nil {
		log.Printf("Failed getting certs")
		return nil, err
	}

	var certsReply pb.IPsecListCertsResponse

	// We stream responses, so build responses now
	for _, mess := range listMessages {
		cert := listCertParams{}
		err := vici.UnmarshalMessage(mess, &cert)
		if err != nil {
			log.Printf("Failed marshalling message: %v", err)
			return nil, err
		}

		parsedCert, err := parseCertificate(&cert)
		if err != nil {
			log.Printf("Failed parsing certificate: %v", err)
			return nil, err
		}
		certsReply.Certs = append(certsReply.Certs, parsedCert)
	}

	return &certsReply, nil
}
