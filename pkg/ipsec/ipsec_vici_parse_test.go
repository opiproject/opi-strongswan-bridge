// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"encoding/base64"
	"errors"
	"testing"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestParseConnection(t *testing.T) {
	tests := []struct {
		name          string
		conn          *listIkeParams
		km            string
		expected      *pb.ListConnResp
		expectedError error
	}{
		{
			name: "Valid Input with All Fields Populated",
			conn: &listIkeParams{
				LocalAddrs:  []string{"192.168.1.1", "192.168.1.2"},
				RemoteAddrs: []string{"10.0.0.1"},
				Version:     "2",
				ReauthTime:  3600,
				RekeyTime:   7200,
				Unique:      "yes",
				DpdDelay:    30,
				DpdTimeout:  120,
				Ppk:         "yes",
				PpkRequired: "no",
				Local: map[string]listAuthParams{
					"local1": {Class: "cert", EapType: "PEAP"},
				},
				Remote: map[string]listAuthParams{
					"remote1": {Class: "cert", EapType: "TLS"},
				},
				Children: map[string]listChildParams{
					"child1": {Mode: "tunnel", Label: "test-child"},
				},
			},
			km: "test-connection",
			expected: &pb.ListConnResp{
				Name: "test-connection",
				LocalAddrs: []*pb.Addrs{
					{Addr: "192.168.1.1"},
					{Addr: "192.168.1.2"},
				},
				RemoteAddrs: []*pb.Addrs{
					{Addr: "10.0.0.1"},
				},
				Version:     "2",
				ReauthTime:  3600,
				RekeyTime:   7200,
				Unique:      "yes",
				DpdDelay:    30,
				DpdTimeout:  120,
				Ppk:         "yes",
				PpkRequired: "no",
				LocalAuth: []*pb.ListConnAuth{
					{Class: "cert", Eaptype: "PEAP"},
				},
				RemoteAuth: []*pb.ListConnAuth{
					{Class: "cert", Eaptype: "TLS"},
				},
				Children: []*pb.ListChild{
					{Name: "child1", Mode: "tunnel", Label: "test-child"},
				},
			},
			expectedError: nil,
		},
		{
			name: "Valid Input with Minimal Fields",
			conn: &listIkeParams{
				Version: "1",
			},
			km: "minimal-connection",
			expected: &pb.ListConnResp{
				Name:    "minimal-connection",
				Version: "1",
			},
			expectedError: nil,
		},
		{
			name:          "Empty Input Object",
			conn:          &listIkeParams{},
			km:            "empty-connection",
			expected:      &pb.ListConnResp{Name: "empty-connection"},
			expectedError: nil,
		},
		{
			name:          "Invalid Input with Empty Connection Name",
			conn:          &listIkeParams{},
			km:            "",
			expected:      nil,
			expectedError: errors.New("name can't be empty"),
		},
		{
			name: "Valid Input with Children Only",
			conn: &listIkeParams{
				Children: map[string]listChildParams{
					"child1": {Mode: "tunnel", Label: "child-test"},
				},
			},
			km: "children-connection",
			expected: &pb.ListConnResp{
				Name: "children-connection",
				Children: []*pb.ListChild{
					{Name: "child1", Mode: "tunnel", Label: "child-test"},
				},
			},
			expectedError: nil,
		},
		{
			name: "Valid Input with Local Authentication Only",
			conn: &listIkeParams{
				Local: map[string]listAuthParams{
					"local1": {Class: "psk"},
				},
			},
			km: "local-auth-connection",
			expected: &pb.ListConnResp{
				Name: "local-auth-connection",
				LocalAuth: []*pb.ListConnAuth{
					{Class: "psk"},
				},
			},
			expectedError: nil,
		},
		{
			name: "Valid Input with Remote Authentication Only",
			conn: &listIkeParams{
				Remote: map[string]listAuthParams{
					"remote1": {Class: "rsa"},
				},
			},
			km: "remote-auth-connection",
			expected: &pb.ListConnResp{
				Name: "remote-auth-connection",
				RemoteAuth: []*pb.ListConnAuth{
					{Class: "rsa"},
				},
			},
			expectedError: nil,
		},
		{
			name: "Input with Non-Zero DpdDelay and DpdTimeout",
			conn: &listIkeParams{
				DpdDelay:   45,
				DpdTimeout: 120,
			},
			km: "dpd-connection",
			expected: &pb.ListConnResp{
				Name:       "dpd-connection",
				DpdDelay:   45,
				DpdTimeout: 120,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := parseConnection(tt.conn, tt.km)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.True(t, proto.Equal(tt.expected, resp), "expected and actual do not match")
			}
		})
	}
}

func TestParseChildListSas(t *testing.T) {
	tests := []struct {
		name      string
		childsa   listChildSaParams
		inputName string
		expected  *pb.ListChildSa
		expectErr error
	}{
		{
			name: "Valid parameters",
			childsa: listChildSaParams{
				Protocol:     "ESP",
				Encap:        "none",
				SpiIn:        "0x100",
				SpiOut:       "0x200",
				CpiIn:        "0x300",
				CpiOut:       "0x400",
				MarkIn:       "0x1",
				MarkMaskIn:   "0x2",
				MarkOut:      "0x3",
				MarkMaskOut:  "0x4",
				IfIDIn:       "1",
				IfIDOut:      "2",
				EncrAlg:      "AES",
				EncKeysize:   "128",
				IntegAlg:     "SHA256",
				IntegKeysize: "256",
				DhGroup:      "14",
				Esn:          "no",
			},
			inputName: "child_sa_1",
			expected: &pb.ListChildSa{
				Name:         "child_sa_1",
				Protocol:     "ESP",
				Encap:        "none",
				SpiIn:        "0x100",
				SpiOut:       "0x200",
				CpiIn:        "0x300",
				CpiOut:       "0x400",
				MarkIn:       "0x1",
				MarkMaskIn:   "0x2",
				MarkOut:      "0x3",
				MarkMaskOut:  "0x4",
				IfIdIn:       "1",
				IfIdOut:      "2",
				EncrAlg:      "AES",
				EncrKeysize:  "128",
				IntegAlg:     "SHA256",
				IntegKeysize: "256",
				DhGroup:      "14",
				Esn:          "no",
			},
			expectErr: nil,
		},
		{
			name:      "Empty name",
			childsa:   listChildSaParams{},
			inputName: "",
			expected:  nil,
			expectErr: errors.New("name can't be empty"),
		},
		{
			name:      "Empty fields",
			childsa:   listChildSaParams{},
			inputName: "child_sa_2",
			expected: &pb.ListChildSa{
				Name: "child_sa_2",
			},
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseChildListSas(tt.childsa, tt.inputName)
			if tt.expectErr != nil {
				if err == nil || err.Error() != tt.expectErr.Error() {
					t.Fatalf("Expected error: %v, got: %v", tt.expectErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if !compareChildSah(result, tt.expected) {
					t.Errorf("Expected: %+v, got: %+v", tt.expected, result)
				}
			}
		})
	}
}

func compareChildSah(a, b *pb.ListChildSa) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Name == b.Name &&
		a.Protocol == b.Protocol &&
		a.Encap == b.Encap &&
		a.SpiIn == b.SpiIn &&
		a.SpiOut == b.SpiOut &&
		a.CpiIn == b.CpiIn &&
		a.CpiOut == b.CpiOut &&
		a.MarkIn == b.MarkIn &&
		a.MarkMaskIn == b.MarkMaskIn &&
		a.MarkOut == b.MarkOut &&
		a.MarkMaskOut == b.MarkMaskOut &&
		a.IfIdIn == b.IfIdIn &&
		a.IfIdOut == b.IfIdOut &&
		a.EncrAlg == b.EncrAlg &&
		a.EncrKeysize == b.EncrKeysize &&
		a.IntegAlg == b.IntegAlg &&
		a.IntegKeysize == b.IntegKeysize &&
		a.DhGroup == b.DhGroup &&
		a.Esn == b.Esn
}

func TestParseIkeListSas(t *testing.T) {
	tests := []struct {
		name      string
		ikesa     *listIkeSaParams
		inputName string
		expected  *pb.ListIkeSa
		expectErr error
	}{
		{
			name: "Full fields with Child SAs",
			ikesa: &listIkeSaParams{
				UniqueID:      "12345",
				Version:       "2",
				State:         "ESTABLISHED",
				LocalHost:     "192.168.0.1",
				LocalPort:     "500",
				LocalID:       "local-id",
				RemoteHost:    "192.168.0.2",
				RemotePort:    "4500",
				RemoteID:      "remote-id",
				RemoteXauthID: "xauth-id",
				RemoteEapID:   "eap-id",
				Initiator:     "yes",
				InitiatorSpi:  "spi-init",
				ResponderSpi:  "spi-resp",
				NatLocal:      "true",
				NatRemote:     "false",
				NatFake:       "yes",
				NatAny:        "no",
				IfIDIn:        "100",
				IfIDOut:       "200",
				EncrAlg:       "AES",
				EncrKeysize:   "256",
				IntegAlg:      "SHA256",
				IntegKeysize:  "256",
				PrfAlg:        "HMAC-SHA256",
				DhGroup:       "14",
				Ppk:           "ppk-val",
				Established:   "true",
				RekeyTime:     "3600",
				ReauthTime:    "7200",
				LocalVips:     []string{"192.168.0.10", "192.168.0.11"},
				RemoteVips:    []string{"192.168.0.20"},
				TasksQueued:   []string{"task1", "task2"},
				TasksActive:   []string{"task3"},
				TasksPassive:  []string{"task4"},
				ChildSas: map[string]listChildSaParams{
					"child1": {
						Protocol:     "ESP",
						Encap:        "yes",
						SpiIn:        "0x01",
						SpiOut:       "0x02",
						CpiIn:        "cpi-in",
						CpiOut:       "cpi-out",
						MarkIn:       "mark-in",
						MarkMaskIn:   "mark-mask-in",
						MarkOut:      "mark-out",
						MarkMaskOut:  "mark-mask-out",
						IfIDIn:       "if-id-in",
						IfIDOut:      "if-id-out",
						EncrAlg:      "AES",
						EncKeysize:   "128",
						IntegAlg:     "SHA1",
						IntegKeysize: "128",
						DhGroup:      "14",
						Esn:          "true",
					},
				},
			},
			inputName: "ike_sa_test",
			expected: &pb.ListIkeSa{
				Name:          "ike_sa_test",
				Uniqueid:      "12345",
				Version:       "2",
				Ikestate:      pb.IkeSaState(pb.IkeSaState_value["ESTABLISHED"]),
				LocalHost:     "192.168.0.1",
				LocalPort:     "500",
				LocalId:       "local-id",
				RemoteHost:    "192.168.0.2",
				RemotePort:    "4500",
				RemoteId:      "remote-id",
				RemoteXauthId: "xauth-id",
				RemoteEapId:   "eap-id",
				Initiator:     "yes",
				InitiatorSpi:  "spi-init",
				ResponderSpi:  "spi-resp",
				NatLocal:      "true",
				NatRemote:     "false",
				NatFake:       "yes",
				NatAny:        "no",
				IfIdIn:        "100",
				IfIdOut:       "200",
				EncrAlg:       "AES",
				EncrKeysize:   "256",
				IntegAlg:      "SHA256",
				IntegKeysize:  "256",
				PrfAlg:        "HMAC-SHA256",
				DhGroup:       "14",
				Ppk:           "ppk-val",
				Established:   "true",
				RekeyTime:     "3600",
				ReauthTime:    "7200",
				LocalVips:     []string{"192.168.0.10", "192.168.0.11"},
				RemoteVips:    []string{"192.168.0.20"},
				TasksQueued:   []string{"task1", "task2"},
				TasksActive:   []string{"task3"},
				TasksPassive:  []string{"task4"},
				Childsas: []*pb.ListChildSa{
					{
						Name:         "child1",
						Protocol:     "ESP",
						Encap:        "yes",
						SpiIn:        "0x01",
						SpiOut:       "0x02",
						CpiIn:        "cpi-in",
						CpiOut:       "cpi-out",
						MarkIn:       "mark-in",
						MarkMaskIn:   "mark-mask-in",
						MarkOut:      "mark-out",
						MarkMaskOut:  "mark-mask-out",
						IfIdIn:       "if-id-in",
						IfIdOut:      "if-id-out",
						EncrAlg:      "AES",
						IntegAlg:     "SHA1",
						IntegKeysize: "128",
						DhGroup:      "14",
						Esn:          "true",
					},
				},
			},
			expectErr: nil,
		},
		{
			name:      "Missing name",
			ikesa:     &listIkeSaParams{},
			inputName: "",
			expected:  nil,
			expectErr: errors.New("name can't be empty"),
		},
		{
			name: "Empty fields",
			ikesa: &listIkeSaParams{
				UniqueID: "",
			},
			inputName: "ike_sa_empty",
			expected: &pb.ListIkeSa{
				Name: "ike_sa_empty",
			},
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseIkeListSas(tt.ikesa, tt.inputName)
			if tt.expectErr != nil {
				if err == nil || err.Error() != tt.expectErr.Error() {
					t.Fatalf("Expected error: %v, got: %v", tt.expectErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if !compareIkeSa(result, tt.expected) {
					t.Errorf("Expected: %+v, got: %+v", tt.expected, result)
				}
			}
		})
	}
}

func compareIkeSa(a, b *pb.ListIkeSa) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Childsas) != len(b.Childsas) {
		return false
	}
	for i, child := range a.Childsas {
		if !compareChildSa(child, b.Childsas[i]) {
			return false
		}
	}
	return a.Name == b.Name &&
		a.Uniqueid == b.Uniqueid &&
		a.Version == b.Version &&
		a.Ikestate == b.Ikestate &&
		a.LocalHost == b.LocalHost &&
		a.LocalPort == b.LocalPort &&
		a.LocalId == b.LocalId &&
		a.RemoteHost == b.RemoteHost &&
		a.RemotePort == b.RemotePort &&
		a.RemoteId == b.RemoteId
}

func compareChildSa(a, b *pb.ListChildSa) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Name == b.Name &&
		a.Protocol == b.Protocol &&
		a.SpiIn == b.SpiIn &&
		a.SpiOut == b.SpiOut
}

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		name      string
		cert      *listCertParams
		expected  *pb.ListCert
		expectErr error
	}{
		{
			name: "Valid X509_AC Certificate",
			cert: &listCertParams{
				Type:       "X509_AC",
				Flag:       "CA",
				HasPrivKey: "true",
				Data:       "certificate-data",
				Subject:    "CN=example.com",
				NotBefore:  "2024-01-01T00:00:00Z",
				NotAfter:   "2025-01-01T00:00:00Z",
			},
			expected: &pb.ListCert{
				Type:       pb.CertificateType_CERTIFICATE_TYPE_X509_AC,
				Flag:       pb.X509CertificateFlag_X509_CERTIFICATE_FLAG_CA,
				Hasprivkey: "true",
				Data:       base64.StdEncoding.EncodeToString([]byte("certificate-data")),
				Subject:    "CN=example.com",
				Notbefore:  "2024-01-01T00:00:00Z",
				Notafter:   "2025-01-01T00:00:00Z",
			},
			expectErr: nil,
		},
		{
			name: "Valid PUBKEY Certificate with OCSP Flag",
			cert: &listCertParams{
				Type:       "PUBKEY",
				Flag:       "OCSP",
				HasPrivKey: "false",
				Data:       "public-key-data",
			},
			expected: &pb.ListCert{
				Type:       pb.CertificateType_CERTIFICATE_TYPE_PUBKEY,
				Flag:       pb.X509CertificateFlag_X509_CERTIFICATE_FLAG_OCSP,
				Hasprivkey: "false",
				Data:       base64.StdEncoding.EncodeToString([]byte("public-key-data")),
			},
			expectErr: nil,
		},
		{
			name: "Unknown Certificate Type",
			cert: &listCertParams{
				Type: "UNKNOWN_TYPE",
			},
			expected:  nil,
			expectErr: errors.New("unknown cert type"),
		},
		{
			name: "Unknown Certificate Flag",
			cert: &listCertParams{
				Type: "X509",
				Flag: "UNKNOWN_FLAG",
			},
			expected:  nil,
			expectErr: errors.New("unknown cert flag"),
		},
		{
			name: "Missing Type and Flag",
			cert: &listCertParams{
				HasPrivKey: "true",
			},
			expected: &pb.ListCert{
				Hasprivkey: "true",
			},
			expectErr: nil,
		},
		{
			name:      "Empty Certificate",
			cert:      &listCertParams{},
			expected:  &pb.ListCert{},
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCertificate(tt.cert)
			if tt.expectErr != nil {
				if err == nil || err.Error() != tt.expectErr.Error() {
					t.Fatalf("Expected error: %v, got: %v", tt.expectErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if !compareCert(result, tt.expected) {
					t.Errorf("Expected: %+v, got: %+v", tt.expected, result)
				}
			}
		})
	}
}

func compareCert(actual, expected *pb.ListCert) bool {
	if actual == nil || expected == nil {
		return actual == expected
	}
	return actual.Type == expected.Type &&
		actual.Flag == expected.Flag &&
		actual.Hasprivkey == expected.Hasprivkey &&
		actual.Data == expected.Data &&
		actual.Subject == expected.Subject &&
		actual.Notbefore == expected.Notbefore &&
		actual.Notafter == expected.Notafter
}

func TestParseConnectionChildl(t *testing.T) {
	tests := []struct {
		name        string
		params      listChildParams
		inputName   string
		expected    *pb.ListChild
		expectedErr error
	}{
		{
			name: "Empty Rekey Parameters",
			params: listChildParams{
				Mode:         "passive",
				Label:        "label2",
				RekeyTime:    0,
				RekeyBytes:   0,
				RekeyPackets: 0,
			},
			inputName: "child2",
			expected: &pb.ListChild{
				Name:         "child2",
				Mode:         "passive",
				Label:        "label2",
				RekeyTime:    0,
				RekeyBytes:   0,
				RekeyPackets: 0,
			},
			expectedErr: nil,
		},
		{
			name: "Nil Traffic Selectors",
			params: listChildParams{
				Mode:     "active",
				RemoteTS: nil,
				LocalTS:  nil,
			},
			inputName: "child3",
			expected: &pb.ListChild{
				Name:     "child3",
				Mode:     "active",
				RemoteTs: nil,
				LocalTs:  nil,
			},
			expectedErr: nil,
		},
		{
			name: "Incomplete Traffic Selector Format",
			params: listChildParams{
				RemoteTS: []string{"10.0.0.1::"},
				LocalTS:  []string{"10.0.0.2:tcp"},
			},
			inputName: "child4",
			expected: &pb.ListChild{
				Name: "child4",
				RemoteTs: &pb.TrafficSelectors{
					Ts: []*pb.TrafficSelectors_TrafficSelector{
						{Cidr: "10.0.0.1", Proto: "", Port: ""},
					},
				},
				LocalTs: &pb.TrafficSelectors{
					Ts: []*pb.TrafficSelectors_TrafficSelector{
						{Cidr: "10.0.0.2", Proto: "tcp", Port: ""},
					},
				},
			},
			expectedErr: nil,
		},
		{
			name: "Invalid CloseAction",
			params: listChildParams{
				CloseAction: "unknown-action",
			},
			inputName:   "child5",
			expected:    &pb.ListChild{Name: "child5", CloseAction: "unknown-action"},
			expectedErr: nil, // The function doesn't validate close actions
		},
		{
			name: "Missing Parameters",
			params: listChildParams{
				Mode: "active",
			},
			inputName: "child6",
			expected: &pb.ListChild{
				Name: "child6",
				Mode: "active",
			},
			expectedErr: nil,
		},
		{
			name: "Zero Priority",
			params: listChildParams{
				Mode:     "passive",
				Priority: "0",
			},
			inputName: "child7",
			expected: &pb.ListChild{
				Name:     "child7",
				Mode:     "passive",
				Priority: "0",
			},
			expectedErr: nil,
		},
		{
			name: "Invalid Characters in Traffic Selector",
			params: listChildParams{
				RemoteTS: []string{"invalid@@ip:tcp:80"},
			},
			inputName: "child8",
			expected: &pb.ListChild{
				Name: "child8",
				RemoteTs: &pb.TrafficSelectors{
					Ts: []*pb.TrafficSelectors_TrafficSelector{
						{Cidr: "invalid@@ip", Proto: "tcp", Port: "80"},
					},
				},
			},
			expectedErr: nil,
		},
		{
			name: "Interface Only",
			params: listChildParams{
				Interface: "eth1",
			},
			inputName: "child9",
			expected: &pb.ListChild{
				Name:      "child9",
				Interface: "eth1",
			},
			expectedErr: nil,
		},
		{
			name: "Empty Input Name",
			params: listChildParams{
				Mode: "active",
			},
			inputName:   "",
			expected:    nil,
			expectedErr: errors.New("name can't be empty"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function under test
			child, err := parseConnectionChild(tt.params, tt.inputName)

			// Assert the error
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}

			// Assert the result
			assert.Equal(t, tt.expected, child)
		})
	}
}

func TestParseAuth(t *testing.T) {
	tests := []struct {
		name        string
		conn        listAuthParams
		inputName   string
		expected    *pb.ListConnAuth
		expectedErr error
	}{
		{
			name: "All Fields Populated",
			conn: listAuthParams{
				Class:      "class1",
				EapType:    "eap-type1",
				EapVendor:  "eap-vendor1",
				Xauth:      "xauth1",
				Revocation: "revoked",
				ID:         "id1",
				CaID:       "ca-id1",
				AaaID:      "aaa-id1",
				EapID:      "eap-id1",
				XauthID:    "xauth-id1",
				Groups:     []string{"group1", "group2"},
				CertPolicy: []string{"policy1", "policy2"},
				Certs:      []string{"cert1", "cert2"},
				CaCerts:    []string{"cacert1", "cacert2"},
			},
			inputName: "auth1",
			expected: &pb.ListConnAuth{
				Class:      "class1",
				Eaptype:    "eap-type1",
				Eapvendor:  "eap-vendor1",
				Xauth:      "xauth1",
				Revocation: "revoked",
				Id:         "id1",
				CaId:       "ca-id1",
				AaaId:      "aaa-id1",
				EapId:      "eap-id1",
				XauthId:    "xauth-id1",
				Group: &pb.Groups{
					Group: []string{"group1", "group2"},
				},
				CertPolicy: &pb.CertPolicy{
					CertPolicy: []string{"policy1", "policy2"},
				},
				Certs: &pb.Certs{
					Cert: []string{"cert1", "cert2"},
				},
				Cacerts: &pb.CaCerts{
					Cacert: []string{"cacert1", "cacert2"},
				},
			},
			expectedErr: nil,
		},
		{
			name: "Empty Name",
			conn: listAuthParams{
				Class: "class1",
			},
			inputName:   "",
			expected:    nil,
			expectedErr: errors.New("name can't be empty"),
		},
		{
			name:        "Nil Slices and Empty Name",
			conn:        listAuthParams{},
			inputName:   "",
			expected:    nil,
			expectedErr: errors.New("name can't be empty"),
		},
		{
			name: "Nil Slices",
			conn: listAuthParams{
				Class: "class2",
			},
			inputName: "auth2",
			expected: &pb.ListConnAuth{
				Class: "class2",
			},
			expectedErr: nil,
		},

		{
			name: "Partial Fields Populated",
			conn: listAuthParams{
				Class: "class4",
				Groups: []string{
					"groupA",
				},
			},
			inputName: "auth4",
			expected: &pb.ListConnAuth{
				Class: "class4",
				Group: &pb.Groups{
					Group: []string{"groupA"},
				},
			},
			expectedErr: nil,
		},
		{
			name: "Only Certificates Populated",
			conn: listAuthParams{
				Certs:   []string{"certOnly1", "certOnly2"},
				CaCerts: []string{"caCert1", "caCert2"},
			},
			inputName: "auth5",
			expected: &pb.ListConnAuth{
				Certs: &pb.Certs{
					Cert: []string{"certOnly1", "certOnly2"},
				},
				Cacerts: &pb.CaCerts{
					Cacert: []string{"caCert1", "caCert2"},
				},
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function under test
			var auth *pb.ListConnAuth
			auth, err := parseAuth(tt.conn, tt.inputName)

			// Assert the error
			if tt.expectedErr != nil {
				assert.EqualError(t, err, tt.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}

			// Assert the result
			assert.Equal(t, tt.expected, auth)
		})
	}
}
