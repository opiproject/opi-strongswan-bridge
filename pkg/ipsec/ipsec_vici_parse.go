// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"encoding/base64"
	"errors"
	"log"
	"strings"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
)

func parseChildListSas(childsa listChildSaParams, name string) (*pb.ListChildSa, error) {
	log.Printf("Found key %v", childsa)
	if name == "" {
		return nil, errors.New("name can't be empty")
	}
	child := &pb.ListChildSa{Name: name}
	if childsa.Protocol != "" {
		child.Protocol = childsa.Protocol
	}
	if childsa.Encap != "" {
		child.Encap = childsa.Encap
	}
	if childsa.SpiIn != "" {
		child.SpiIn = childsa.SpiIn
	}
	if childsa.SpiOut != "" {
		child.SpiOut = childsa.SpiOut
	}
	if childsa.CpiIn != "" {
		child.CpiIn = childsa.CpiIn
	}
	if childsa.CpiOut != "" {
		child.CpiOut = childsa.CpiOut
	}
	if childsa.MarkIn != "" {
		child.MarkIn = childsa.MarkIn
	}
	if childsa.MarkMaskIn != "" {
		child.MarkMaskIn = childsa.MarkMaskIn
	}
	if childsa.MarkOut != "" {
		child.MarkOut = childsa.MarkOut
	}
	if childsa.MarkMaskOut != "" {
		child.MarkMaskOut = childsa.MarkMaskOut
	}
	if childsa.IfIDIn != "" {
		child.IfIdIn = childsa.IfIDIn
	}
	if childsa.IfIDOut != "" {
		child.IfIdOut = childsa.IfIDOut
	}
	if childsa.EncrAlg != "" {
		child.EncrAlg = childsa.EncrAlg
	}
	if childsa.EncKeysize != "" {
		child.EncrKeysize = childsa.EncKeysize
	}
	if childsa.IntegAlg != "" {
		child.IntegAlg = childsa.IntegAlg
	}
	if childsa.IntegKeysize != "" {
		child.IntegKeysize = childsa.IntegKeysize
	}
	if childsa.DhGroup != "" {
		child.DhGroup = childsa.DhGroup
	}
	if childsa.Esn != "" {
		child.Esn = childsa.Esn
	}
	return child, nil
}

//nolint:funlen,gocognit,gocyclo
func parseIkeListSas(ikesa *listIkeSaParams, km string) (*pb.ListIkeSa, error) {
	if km == "" {
		return nil, errors.New("name can't be empty")
	}
	ret := &pb.ListIkeSa{Name: km}
	if ikesa.UniqueID != "" {
		ret.Uniqueid = ikesa.UniqueID
	}
	if ikesa.Version != "" {
		ret.Version = ikesa.Version
	}
	if ikesa.State != "" {
		ret.Ikestate = pb.IkeSaState(pb.IkeSaState_value[ikesa.State])
	}
	if ikesa.LocalHost != "" {
		ret.LocalHost = ikesa.LocalHost
	}
	if ikesa.LocalPort != "" {
		ret.LocalPort = ikesa.LocalPort
	}
	if ikesa.LocalID != "" {
		ret.LocalId = ikesa.LocalID
	}
	if ikesa.RemoteHost != "" {
		ret.RemoteHost = ikesa.RemoteHost
	}
	if ikesa.RemotePort != "" {
		ret.RemotePort = ikesa.RemotePort
	}
	if ikesa.RemoteID != "" {
		ret.RemoteId = ikesa.RemoteID
	}
	if ikesa.RemoteXauthID != "" {
		ret.RemoteXauthId = ikesa.RemoteXauthID
	}
	if ikesa.RemoteEapID != "" {
		ret.RemoteEapId = ikesa.RemoteEapID
	}
	if ikesa.Initiator != "" {
		ret.Initiator = ikesa.Initiator
	}
	if ikesa.InitiatorSpi != "" {
		ret.InitiatorSpi = ikesa.InitiatorSpi
	}
	if ikesa.ResponderSpi != "" {
		ret.ResponderSpi = ikesa.ResponderSpi
	}
	if ikesa.NatLocal != "" {
		ret.NatLocal = ikesa.NatLocal
	}
	if ikesa.NatRemote != "" {
		ret.NatRemote = ikesa.NatRemote
	}
	if ikesa.NatFake != "" {
		ret.NatFake = ikesa.NatFake
	}
	if ikesa.NatAny != "" {
		ret.NatAny = ikesa.NatAny
	}
	if ikesa.IfIDIn != "" {
		ret.IfIdIn = ikesa.IfIDIn
	}
	if ikesa.IfIDOut != "" {
		ret.IfIdOut = ikesa.IfIDOut
	}
	if ikesa.EncrAlg != "" {
		ret.EncrAlg = ikesa.EncrAlg
	}
	if ikesa.EncrKeysize != "" {
		ret.EncrKeysize = ikesa.EncrKeysize
	}
	if ikesa.IntegAlg != "" {
		ret.IntegAlg = ikesa.IntegAlg
	}
	if ikesa.IntegKeysize != "" {
		ret.IntegKeysize = ikesa.IntegKeysize
	}
	if ikesa.PrfAlg != "" {
		ret.PrfAlg = ikesa.PrfAlg
	}
	if ikesa.DhGroup != "" {
		ret.DhGroup = ikesa.DhGroup
	}
	if ikesa.Ppk != "" {
		ret.Ppk = ikesa.Ppk
	}
	if ikesa.Established != "" {
		ret.Established = ikesa.Established
	}
	if ikesa.RekeyTime != "" {
		ret.RekeyTime = ikesa.RekeyTime
	}
	if ikesa.ReauthTime != "" {
		ret.ReauthTime = ikesa.ReauthTime
	}
	if ikesa.LocalVips != nil {
		ret.LocalVips = ikesa.LocalVips
	}
	if ikesa.RemoteVips != nil {
		ret.RemoteVips = ikesa.RemoteVips
	}
	if ikesa.TasksQueued != nil {
		ret.TasksQueued = ikesa.TasksQueued
	}
	if ikesa.TasksActive != nil {
		ret.TasksActive = ikesa.TasksActive
	}
	if ikesa.TasksPassive != nil {
		ret.TasksPassive = ikesa.TasksPassive
	}
	if ikesa.ChildSas != nil {
		log.Printf("Looking at ChildSas %v", ikesa.ChildSas)
		for k, mess := range ikesa.ChildSas {
			childsa, err := parseChildListSas(mess, k)
			if err != nil {
				log.Printf("Error parsing CHILD_SA")
				return nil, nil
			}
			ret.Childsas = append(ret.Childsas, childsa)
		}
	}
	return ret, nil
}

func parseAuth(conn listAuthParams, name string) (*pb.ListConnAuth, error) {
	log.Printf("Found key %v", conn)
	if name == "" {
		return nil, errors.New("name can't be empty")
	}
	auth := &pb.ListConnAuth{}
	if conn.Class != "" {
		auth.Class = conn.Class
	}
	if conn.EapType != "" {
		auth.Eaptype = conn.EapType
	}
	if conn.EapVendor != "" {
		auth.Eapvendor = conn.EapVendor
	}
	if conn.Xauth != "" {
		auth.Xauth = conn.Xauth
	}
	if conn.Revocation != "" {
		auth.Revocation = conn.Revocation
	}
	if conn.ID != "" {
		auth.Id = conn.ID
	}
	if conn.CaID != "" {
		auth.CaId = conn.CaID
	}
	if conn.AaaID != "" {
		auth.AaaId = conn.AaaID
	}
	if conn.EapID != "" {
		auth.EapId = conn.EapID
	}
	if conn.XauthID != "" {
		auth.XauthId = conn.XauthID
	}
	if conn.Groups != nil {
		for k := 0; k < len(conn.Groups); k++ {
			auth.Group.Group = append(auth.Group.Group, conn.Groups[k])
		}
	}
	if conn.CertPolicy != nil {
		for k := 0; k < len(conn.CertPolicy); k++ {
			auth.CertPolicy.CertPolicy = append(auth.CertPolicy.CertPolicy, conn.CertPolicy[k])
		}
	}
	if conn.Certs != nil {
		for k := 0; k < len(conn.Certs); k++ {
			auth.Certs.Cert = append(auth.Certs.Cert, conn.Certs[k])
		}
	}
	if conn.CaCerts != nil {
		for k := 0; k < len(conn.CaCerts); k++ {
			auth.Cacerts.Cacert = append(auth.Cacerts.Cacert, conn.CaCerts[k])
		}
	}
	return auth, nil
}

//nolint:gocognit,gocyclo
func parseConnectionChild(params listChildParams, name string) (*pb.ListChild, error) {
	log.Printf("Found key %v", params)
	if name == "" {
		return nil, errors.New("name can't be empty")
	}
	child := &pb.ListChild{Name: name}
	if params.Mode != "" {
		child.Mode = params.Mode
	}
	if params.Label != "" {
		child.Label = params.Label
	}
	if params.RekeyTime != 0 {
		child.RekeyTime = params.RekeyTime
	}
	if params.RekeyBytes != 0 {
		child.RekeyBytes = params.RekeyBytes
	}
	if params.RekeyPackets != 0 {
		child.RekeyPackets = params.RekeyPackets
	}
	if params.DpdAction != "" {
		child.DpdAction = params.DpdAction
	}
	if params.CloseAction != "" {
		child.CloseAction = params.CloseAction
	}
	if params.RemoteTS != nil {
		for k := 0; k < len(params.RemoteTS); k++ {
			s := strings.Split(params.RemoteTS[k], ":")
			ts := &pb.TrafficSelectors_TrafficSelector{}
			if len(s) >= 1 && s[0] != "" {
				ts.Cidr = s[0]
			}
			if len(s) >= 2 && s[1] != "" {
				ts.Proto = s[1]
			}
			if len(s) >= 3 && s[2] != "" {
				ts.Port = s[2]
			}

			child.RemoteTs = &pb.TrafficSelectors{}
			child.RemoteTs.Ts = []*pb.TrafficSelectors_TrafficSelector{}
			child.RemoteTs.Ts = append(child.RemoteTs.Ts, ts)
		}
	}
	if params.LocalTS != nil {
		for k := 0; k < len(params.LocalTS); k++ {
			s := strings.Split(params.LocalTS[k], ":")
			ts := &pb.TrafficSelectors_TrafficSelector{}
			if len(s) >= 1 && s[0] != "" {
				ts.Cidr = s[0]
			}
			if len(s) >= 2 && s[1] != "" {
				ts.Proto = s[1]
			}
			if len(s) >= 3 && s[2] != "" {
				ts.Port = s[2]
			}

			child.LocalTs = &pb.TrafficSelectors{}
			child.LocalTs.Ts = []*pb.TrafficSelectors_TrafficSelector{}
			child.LocalTs.Ts = append(child.LocalTs.Ts, ts)
		}
	}
	if params.Interface != "" {
		child.Interface = params.Interface
	}
	if params.Priority != "" {
		child.Priority = params.Priority
	}
	return child, nil
}

func parseConnection(conn *listIkeParams, km string) (*pb.ListConnResp, error) {
	if km == "" {
		return nil, errors.New("name can't be empty")
	}
	ret := &pb.ListConnResp{Name: km}
	for i := 0; i < len(conn.LocalAddrs); i++ {
		addr := &pb.Addrs{Addr: conn.LocalAddrs[i]}
		ret.LocalAddrs = append(ret.LocalAddrs, addr)
	}
	for i := 0; i < len(conn.RemoteAddrs); i++ {
		addr := &pb.Addrs{Addr: conn.RemoteAddrs[i]}
		ret.RemoteAddrs = append(ret.RemoteAddrs, addr)
	}
	if conn.Version != "" {
		ret.Version = conn.Version
	}
	if conn.ReauthTime != 0 {
		ret.ReauthTime = conn.ReauthTime
	}
	if conn.RekeyTime != 0 {
		ret.RekeyTime = conn.RekeyTime
	}
	if conn.Unique != "" {
		ret.Unique = conn.Unique
	}
	if conn.DpdDelay != 0 {
		ret.DpdDelay = conn.DpdDelay
	}
	if conn.DpdTimeout != 0 {
		ret.DpdTimeout = conn.DpdTimeout
	}
	if conn.Ppk != "" {
		ret.Ppk = conn.Ppk
	}
	if conn.PpkRequired != "" {
		ret.PpkRequired = conn.PpkRequired
	}
	if conn.Local != nil {
		log.Printf("Looking at Local Auth%v", conn.Local)
		for k, mess := range conn.Local {
			local, err := parseAuth(mess, k)
			if err != nil {
				log.Printf("Error parsing local auth")
				return nil, nil
			}
			ret.LocalAuth = append(ret.LocalAuth, local)
		}
	}
	if conn.Remote != nil {
		log.Printf("Looking at Remote Auth%v", conn.Remote)
		for k, mess := range conn.Remote {
			remote, err := parseAuth(mess, k)
			if err != nil {
				log.Printf("Error parsing remote auth")
				return nil, nil
			}
			ret.RemoteAuth = append(ret.RemoteAuth, remote)
		}
	}
	if conn.Children != nil {
		log.Printf("Looking at Children%v", conn.Children)
		for k, mess := range conn.Children {
			child, err := parseConnectionChild(mess, k)
			if err != nil {
				log.Printf("Error parsing child")
				return nil, nil
			}
			ret.Children = append(ret.Children, child)
		}
	}

	return ret, nil
}

func parseCertificate(cert *listCertParams) (*pb.ListCert, error) {
	ret := &pb.ListCert{}

	if cert.Type != "" {
		s1 := strings.ToUpper(cert.Type)
		switch {
		case strings.Contains(s1, "X509_AC"):
			ret.Type = pb.CertificateType_CERT_X509
		case strings.Contains(s1, "X509_CRL"):
			ret.Type = pb.CertificateType_CERT_X509_CRL
		case strings.Contains(s1, "X509"):
			ret.Type = pb.CertificateType_CERT_X509
		case strings.Contains(s1, "OCSP_RESPONSE"):
			ret.Type = pb.CertificateType_CERT_OCSP_RESPONSE
		case strings.Contains(s1, "PUBKEY"):
			ret.Type = pb.CertificateType_CERT_PUBKEY
		default:
			return nil, errors.New("unknown cert type")
		}
	}
	if cert.Flag != "" {
		s1 := strings.ToUpper(cert.Flag)
		switch {
		case strings.Contains(s1, "OCSP"):
			ret.Flag = pb.X509CertificateFlag_X509_CERT_FLAG_OCSP
		case strings.Contains(s1, "AA"):
			ret.Flag = pb.X509CertificateFlag_X509_CERT_FLAG_AA
		case strings.Contains(s1, "CA"):
			ret.Flag = pb.X509CertificateFlag_X509_CERT_FLAG_CA
		case strings.Contains(s1, "NONE"):
			ret.Flag = pb.X509CertificateFlag_X509_CERT_FLAG_NONE
		default:
			return nil, errors.New("unknown cert flag")
		}
	}
	if cert.HasPrivKey != "" {
		ret.Hasprivkey = cert.HasPrivKey
	}
	if cert.Data != "" {
		encodedText := base64.StdEncoding.EncodeToString([]byte(cert.Data))
		ret.Data = encodedText
	}
	if cert.Subject != "" {
		ret.Subject = cert.Subject
	}
	if cert.NotBefore != "" {
		ret.Notbefore = cert.NotBefore
	}
	if cert.NotAfter != "" {
		ret.Notafter = cert.NotAfter
	}
	return ret, nil
}
