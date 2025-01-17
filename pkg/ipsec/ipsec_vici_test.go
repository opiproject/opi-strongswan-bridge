// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"errors"
	"log"
	"strings"
	"testing"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
	"github.com/stretchr/testify/assert"
)

func TestBuildProposal(t *testing.T) {
	tests := []struct {
		name     string
		prop     *pb.Proposals
		expected string
		err      error
	}{
		{
			name:     "Nil Proposal",
			prop:     nil,
			expected: "",
			err:      errors.New("proposal can't be nil"),
		},
		{
			name:     "Empty Proposal",
			prop:     &pb.Proposals{},
			expected: "",
			err:      nil,
		},
		{
			name: "only Crypto Algorithm",
			prop: &pb.Proposals{
				CryptoAlg: []pb.CryptoAlgorithm{pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES128},
			},
			expected: "aes128",
			err:      nil,
		},
		{
			name: "Multiple Crypto and Integrity Algorithms",
			prop: &pb.Proposals{
				CryptoAlg: []pb.CryptoAlgorithm{pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES128, pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES256},
				IntegAlg:  []pb.IntegAlgorithm{pb.IntegAlgorithm_INTEG_ALGORITHM_SHA256, pb.IntegAlgorithm_INTEG_ALGORITHM_SHA512},
			},
			expected: "aes128-aes256-sha256-sha512",
			err:      nil,
		},
		{
			name: "Complete Proposal with All Fields",
			prop: &pb.Proposals{
				CryptoAlg: []pb.CryptoAlgorithm{pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES128},
				IntegAlg:  []pb.IntegAlgorithm{pb.IntegAlgorithm_INTEG_ALGORITHM_SHA256},
				Prf:       []pb.PRFunction{pb.PRFunction_PR_FUNCTION_SHA1},
				Dhgroups:  []pb.DHGroups{pb.DHGroups_DH_GROUPS_MODP2048},
			},
			expected: "aes128-sha256-sha1-modp2048",
			err:      nil,
		},
		{
			name: "Only prf Group",
			prop: &pb.Proposals{
				Prf: []pb.PRFunction{pb.PRFunction_PR_FUNCTION_AESCMAC, pb.PRFunction_PR_FUNCTION_SHA1, pb.PRFunction_PR_FUNCTION_SHA256, pb.PRFunction_PR_FUNCTION_SHA384, pb.PRFunction_PR_FUNCTION_SHA512},
			},
			expected: "aescmac-sha1-sha256-sha384-sha512",
			err:      nil,
		},
		{
			name: "Only DH Group",
			prop: &pb.Proposals{
				Dhgroups: []pb.DHGroups{pb.DHGroups_DH_GROUPS_CURVE25519, pb.DHGroups_DH_GROUPS_MODP1024S160, pb.DHGroups_DH_GROUPS_MODP2048, pb.DHGroups_DH_GROUPS_MODP4096, pb.DHGroups_DH_GROUPS_MODP8192},
			},
			expected: "curve25519-modp1024s160-modp2048-modp4096-modp8192",
			err:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildProposal(tt.prop)
			if tt.err != nil {
				if err == nil || !strings.Contains(err.Error(), tt.err.Error()) {
					t.Errorf("Expected error: %v, got: %v", tt.err, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected: %s, got: %s", tt.expected, result)
				}
			}
		})
	}
}

func TestListConn(t *testing.T) {
	tests := []struct {
		name        string
		listreq     *pb.IPsecListConnsRequest
		want        *pb.IPsecListConnsResponse
		expectedErr bool
	}{
		{
			name: "successes",
			listreq: &pb.IPsecListConnsRequest{
				Ike: "home",
			},
			want: &pb.IPsecListConnsResponse{
				Connection: []*pb.ListConnResp{
					{
						Name: "home",
						RemoteAddrs: []*pb.Addrs{
							{
								Addr: "192.168.0.2",
							},
						},
						Version:  "IKEv2",
						Unique:   "UNIQUE_NO",
						DpdDelay: 60,
						Children: []*pb.ListChild{
							{
								Name:        "host",
								Mode:        "TUNNEL",
								DpdAction:   "trap",
								CloseAction: "none",
							},
						},
					},
				},
			},
			expectedErr: false,
		},

		{
			name: "fail",
			listreq: &pb.IPsecListConnsRequest{
				Ike: "fail",
			},
			want:        nil,
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := listConns(tt.listreq)

			if tt.expectedErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}
			if tt.want != nil && resp != nil {
				assert.Equal(t, tt.want.Connection[0].Name, resp.Connection[0].Name)
				assert.Equal(t, tt.want.Connection[0].Version, resp.Connection[0].Version)
				assert.Equal(t, tt.want.Connection[0].Unique, resp.Connection[0].Unique)
				assert.Equal(t, tt.want.Connection[0].DpdDelay, resp.Connection[0].DpdDelay)
				assert.Equal(t, tt.want.Connection[0].Children[0].CloseAction, resp.Connection[0].Children[0].CloseAction)
				assert.Equal(t, tt.want.Connection[0].Children[0].Mode, resp.Connection[0].Children[0].Mode)
			}
		})
	}
}

func TestIpsecVersion(t *testing.T) {
	resp, err := ipsecVersion()

	assert.NoError(t, err)
	assert.Equal(t, "charon", resp.Daemon)
	assert.Equal(t, "6.0.0", resp.Version)
	assert.Equal(t, "Linux", resp.Sysname)
	assert.Equal(t, "x86_64", resp.Machine)
}
func TestIpsecStats(t *testing.T) {
	resp, err := ipsecStats()
	if err != nil {
		t.Fatalf("ipsecStats failed: %v", err)
	}

	t.Log("IPsec Stats Output:\n", resp.Status)

	assert.NotNil(t, resp)
}

func TestInitiateConn(t *testing.T) {
	tests := []struct {
		name          string
		initReq       *pb.IPsecInitiateRequest
		expectedError bool
	}{
		{
			name: "Valid Input",
			initReq: &pb.IPsecInitiateRequest{
				Child:    "eap",
				Timeout:  "300",
				Loglevel: "2",
			},
			expectedError: false,
		},
		{
			name: "Empty Fields",
			initReq: &pb.IPsecInitiateRequest{
				Child:    "",
				Ike:      "",
				Timeout:  "",
				Loglevel: "",
			},
			expectedError: true,
		},
		{
			name: "child only",
			initReq: &pb.IPsecInitiateRequest{
				Child: "host",
				Ike:   "",
			},
			expectedError: false,
		},
		{
			name: "invlaid child",
			initReq: &pb.IPsecInitiateRequest{
				Child:    "hostdummy",
				Ike:      "",
				Timeout:  "20",
				Loglevel: "",
			},
			expectedError: true,
		},
		{
			name: "incorrect connection and child",
			initReq: &pb.IPsecInitiateRequest{
				Child:    "net",
				Ike:      "incorrectike",
				Timeout:  "",
				Loglevel: "2",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := initiateConn(tt.initReq)
			if tt.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
			}
		})
	}
}
func TestRekeyConn(t *testing.T) {
	tests := []struct {
		name      string
		rekeyReq  *pb.IPsecRekeyRequest
		expectErr bool
	}{
		{
			name: "Success case",
			rekeyReq: &pb.IPsecRekeyRequest{
				Child:  "host",
				Ike:    "home",
				Reauth: "yes",
			},
			expectErr: false,
		},
		{
			name: "Child Only",
			rekeyReq: &pb.IPsecRekeyRequest{
				Child: "eap",
			},
			expectErr: false,
		},

		{
			name: "Chile correct incorrect IKE",
			rekeyReq: &pb.IPsecRekeyRequest{
				Child: "net",
				Ike:   "hom",
			},
			expectErr: true,
		},

		{
			name: "Incorrect ID",
			rekeyReq: &pb.IPsecRekeyRequest{
				IkeId:   14,
				ChildId: 44,
			},
			expectErr: true,
		},
		{
			name:      "Empty Response",
			rekeyReq:  &pb.IPsecRekeyRequest{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			success, matches, err := rekeyConn(tt.rekeyReq)

			log.Printf("Test Case: %s -> success=%s, matches=%d, err=%v", tt.name, success, matches, err)

			if tt.expectErr {
				assert.NotNil(t, err, "Expected an error")
			} else {
				assert.Nil(t, err, "Expected no error")
				assert.NotEmpty(t, success, "Success should not be empty")
				assert.GreaterOrEqual(t, matches, uint32(0), "Matches should be 0 or more")
			}
		})
	}
}

func TestListSas(t *testing.T) {
	tests := []struct {
		name      string
		req       *pb.IPsecListSasRequest
		want      *pb.IPsecListSasResponse
		expectErr bool
	}{
		{
			name: "Invalid IKE/Child ID",
			req: &pb.IPsecListSasRequest{
				IkeId:   99999,
				ChildId: 99999,
			},
			want:      nil,
			expectErr: false,
		},
		{
			name: "Empty Request",
			req:  &pb.IPsecListSasRequest{},
			want: &pb.IPsecListSasResponse{
				Ikesas: []*pb.ListIkeSa{
					{Name: "home",
						Uniqueid:     "2",
						Version:      "2",
						LocalHost:    "192.168.0.3",
						LocalPort:    "4500",
						LocalId:      "client.strongswan.org",
						RemoteHost:   "192.168.0.2",
						RemotePort:   "4500",
						RemoteId:     "server.strongswan.org",
						Initiator:    "yes",
						InitiatorSpi: "d47e69ccced1b166",
						ResponderSpi: "5e8efa64e7a67d47",
						EncrAlg:      "AES_CBC",
						EncrKeysize:  "256",
						IntegAlg:     "HMAC_SHA2_256_128",
						PrfAlg:       "PRF_HMAC_SHA2_256",
						DhGroup:      "CURVE_25519",
						Established:  "820",
						RekeyTime:    "13497",
						LocalVips:    []string{"10.3.0.1"},
						Childsas: []*pb.ListChildSa{

							{Name: "eap-tls-3",
								Protocol:    "ESP",
								SpiIn:       "c844bfee",
								SpiOut:      "c924d144",
								EncrAlg:     "AES_GCM_16",
								EncrKeysize: "256",
							}},
					},
					{
						Name:     "eap",
						Uniqueid: "2", Version: "2", LocalHost: "192.168.0.3",
						LocalPort: "4500", LocalId: "192.168.0.3",
						RemoteHost:   "192.168.0.2",
						RemotePort:   "4500",
						RemoteId:     "server.strongswan.org",
						Initiator:    "yes",
						InitiatorSpi: "1c3638ad340706b5",
						ResponderSpi: "74eb0bcde7b51c8e",
						EncrAlg:      "AES_CBC",
						EncrKeysize:  "256",
						IntegAlg:     "HMAC_SHA2_256_128",
						PrfAlg:       "PRF_HMAC_SHA2_256",
						DhGroup:      "CURVE_25519",
						Established:  "824",
						RekeyTime:    "12189",
						LocalVips:    []string{"10.3.0.2"},
						Childsas: []*pb.ListChildSa{{Name: "eap-2",
							Protocol:    "ESP",
							SpiIn:       "ce647fcb",
							SpiOut:      "cd0fa5df",
							EncrAlg:     "AES_GCM_16",
							EncrKeysize: "256",
						},
						}},
					{
						Name:         "home",
						Uniqueid:     "1",
						Version:      "2",
						LocalHost:    "192.168.0.3",
						LocalPort:    "4500",
						LocalId:      "client.strongswan.org",
						RemoteHost:   "192.168.0.2",
						RemotePort:   "4500",
						RemoteId:     "server.strongswan.org",
						Initiator:    "yes",
						InitiatorSpi: "37e96a6869718fb9",
						ResponderSpi: "af188e5f2d56669b",
						EncrAlg:      "AES_CBC",
						EncrKeysize:  "256",
						IntegAlg:     "HMAC_SHA2_256_128",
						PrfAlg:       "PRF_HMAC_SHA2_256",
						DhGroup:      "CURVE_25519",
						Established:  "42",
						RekeyTime:    "13179",
						LocalVips:    []string{"10.3.0.1"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "Partial Request - Ike Only",
			req: &pb.IPsecListSasRequest{
				Ike: "eap",
			},
			want: &pb.IPsecListSasResponse{
				Ikesas: []*pb.ListIkeSa{
					{
						Name:     "eap",
						Uniqueid: "1", Version: "2", LocalHost: "192.168.0.3",
						LocalPort: "4500", LocalId: "192.168.0.3",
						RemoteHost:   "192.168.0.2",
						RemotePort:   "4500",
						RemoteId:     "server.strongswan.org",
						Initiator:    "yes",
						InitiatorSpi: "1c3638ad340706b5",
						ResponderSpi: "74eb0bcde7b51c8e",
						EncrAlg:      "AES_CBC",
						EncrKeysize:  "256",
						IntegAlg:     "HMAC_SHA2_256_128",
						PrfAlg:       "PRF_HMAC_SHA2_256",
						DhGroup:      "CURVE_25519",
						Established:  "824",
						RekeyTime:    "12189",
						LocalVips:    []string{"10.3.0.2"},
						Childsas: []*pb.ListChildSa{{Name: "eap-2",
							Protocol:    "ESP",
							SpiIn:       "ce647fcb",
							SpiOut:      "cd0fa5df",
							EncrAlg:     "AES_GCM_16",
							EncrKeysize: "256",
							DhGroup:     "CURVE_25519",
						},
						}},
				},
			},
			expectErr: false,
		},
		{
			name: "Partial Request - Child Only",
			req: &pb.IPsecListSasRequest{
				Child: "eap-tls",
			},
			want: &pb.IPsecListSasResponse{
				Ikesas: []*pb.ListIkeSa{

					{Name: "home",
						Uniqueid:     "2",
						Version:      "2",
						LocalHost:    "192.168.0.3",
						LocalPort:    "4500",
						LocalId:      "client.strongswan.org",
						RemoteHost:   "192.168.0.2",
						RemotePort:   "4500",
						RemoteId:     "server.strongswan.org",
						Initiator:    "yes",
						InitiatorSpi: "d47e69ccced1b166",
						ResponderSpi: "5e8efa64e7a67d47",
						EncrAlg:      "AES_CBC",
						EncrKeysize:  "256",
						IntegAlg:     "HMAC_SHA2_256_128",
						PrfAlg:       "PRF_HMAC_SHA2_256",
						DhGroup:      "CURVE_25519",

						LocalVips: []string{"10.3.0.1"},
						Childsas: []*pb.ListChildSa{

							{Name: "eap-tls-3",
								Protocol:    "ESP",
								SpiIn:       "c844bfee",
								SpiOut:      "c924d144",
								EncrAlg:     "AES_GCM_16",
								EncrKeysize: "256",
							}},
					},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := listSas(tt.req)

			if tt.expectErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}
			if tt.want != nil && resp != nil {
				assert.Equal(t, resp.Ikesas[0].Name, tt.want.Ikesas[0].Name)
				assert.Equal(t, resp.Ikesas[0].Uniqueid, tt.want.Ikesas[0].Uniqueid)
				assert.Equal(t, resp.Ikesas[0].Version, tt.want.Ikesas[0].Version)
				assert.Equal(t, resp.Ikesas[0].LocalHost, tt.want.Ikesas[0].LocalHost)
				assert.Equal(t, resp.Ikesas[0].LocalPort, tt.want.Ikesas[0].LocalPort)
				assert.Equal(t, resp.Ikesas[0].LocalId, tt.want.Ikesas[0].LocalId)
				assert.Equal(t, resp.Ikesas[0].RemoteHost, tt.want.Ikesas[0].RemoteHost)
				assert.Equal(t, resp.Ikesas[0].RemotePort, tt.want.Ikesas[0].RemotePort)
				assert.Equal(t, resp.Ikesas[0].RemoteId, tt.want.Ikesas[0].RemoteId)
				assert.Equal(t, resp.Ikesas[0].Initiator, tt.want.Ikesas[0].Initiator)
				assert.Equal(t, resp.Ikesas[0].EncrAlg, tt.want.Ikesas[0].EncrAlg)
				assert.Equal(t, resp.Ikesas[0].EncrKeysize, tt.want.Ikesas[0].EncrKeysize)
				assert.Equal(t, resp.Ikesas[0].IntegAlg, tt.want.Ikesas[0].IntegAlg)
				assert.Equal(t, resp.Ikesas[0].PrfAlg, tt.want.Ikesas[0].PrfAlg)
				assert.Equal(t, resp.Ikesas[0].DhGroup, tt.want.Ikesas[0].DhGroup)
				assert.Equal(t, resp.Ikesas[0].Name, tt.want.Ikesas[0].Name)
			}
		})
	}
}
func TestTerminateConn(t *testing.T) {
	tests := []struct {
		name          string
		termReq       *pb.IPsecTerminateRequest
		expectedError bool
	}{
		{
			name: "Valid Input",
			termReq: &pb.IPsecTerminateRequest{
				Child:    "eap",
				Timeout:  "30",
				Force:    "yes",
				Loglevel: "2",
			},
			expectedError: false,
		},
		{
			name: "no Timeout",
			termReq: &pb.IPsecTerminateRequest{
				Child:    "host",
				Force:    "yes",
				Loglevel: "2",
			},
			expectedError: false,
		},

		{
			name: "Empty Fields",
			termReq: &pb.IPsecTerminateRequest{
				Child:    "",
				Ike:      "",
				ChildId:  0,
				IkeId:    0,
				Timeout:  "",
				Force:    "",
				Loglevel: "",
			},
			expectedError: true,
		},

		{
			name: "incorrect id",
			termReq: &pb.IPsecTerminateRequest{

				ChildId:  4,
				IkeId:    4,
				Timeout:  "",
				Force:    "",
				Loglevel: "",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := terminateConn(tt.termReq)

			if tt.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
			}
		})
	}
} // go test -timeout 30s -run ^TestInitiateConn$ github.com/opiproject/opi-strongswan-bridge/pkg/ipsec
func TestLoadConn(t *testing.T) {
	tests := []struct {
		name      string
		connReq   *pb.IPsecLoadConnRequest
		expectErr bool
	}{{
		name: "Valid LoadConnRequest",
		connReq: &pb.IPsecLoadConnRequest{Connection: &pb.Connection{
			Name:       "ikev1-l2tp-chap-auth-in-l2tp",
			Version:    "1",
			RekeyTime:  2,
			DpdDelay:   30,
			DpdTimeout: 90,
			ReauthTime: 2,
			Children: []*pb.Child{
				{
					Name:      "ikev1-l2tp-chap-auth-in-l2tp",
					RekeyTime: 0,
				},
			},
		}},
		expectErr: false,
	}, {
		name: "Valid LoadConnRequest all fields",
		connReq: &pb.IPsecLoadConnRequest{Connection: &pb.Connection{
			Name:    "conn",
			Version: "2",
			Proposals: &pb.Proposals{
				CryptoAlg: []pb.CryptoAlgorithm{
					pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES256GCM128,
				},
				IntegAlg: []pb.IntegAlgorithm{
					pb.IntegAlgorithm_INTEG_ALGORITHM_SHA256,
				},
				Prf: []pb.PRFunction{
					pb.PRFunction_PR_FUNCTION_SHA1,
				},
				Dhgroups: []pb.DHGroups{
					pb.DHGroups_DH_GROUPS_MODP768,
				},
			},
			Pools: &pb.Pools{
				Pool: []string{
					"10.3.0.0/24",
				},
			},
			DpdDelay: 30,
			LocalAuth: &pb.LocalAuth{
				Auth: pb.AuthType_AUTH_TYPE_PUBKEY,
				Id:   "server.strongswan.org",

				Certs: &pb.Certs{
					Cert: []string{
						"MIICADCCAYWgAwIBAgIIWpEKfsh+QqYwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTIwMDMwOTEyMDMzOFoXDTI0MDMwOTEyMDMzOFowPTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMR4wHAYDVQQDExVzZXJ2ZXIuc3Ryb25nc3dhbi5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASvt8McyFuyGVggth+Izf/qB+SQHgKxHEgvAB+6Gj52xrcdxZl0/cXwL5NG3rxur3dzBzEuJRb/oYxqgNcZrT/28239tAN8PHkST0u+kFwZF3PTDXdyrkGT3PKv7Kb6dWWjWjBYMB8GA1UdIwQYMBaAFLjSYIqHz0jucV3YUSAjWsGq5feyMCAGA1UdEQQZMBeCFXNlcnZlci5zdHJvbmdzd2FuLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAwNpADBmAjEA9TJ6mQykJfTD/MK4FqxAX4bTowM3LvMzniEBbDVCct3oLW2VqU8A12MEwYlj4FulAjEAlYCiquZUoPrV19gdN3MaXJe/7dwEjXczD1/5T4UjrWUbS+D7J5/DsEMYM10LNXgB",
					},
				},
			},
			RemoteAuth: &pb.RemoteAuth{
				Auth: pb.AuthType_AUTH_TYPE_PUBKEY,
				CaCerts: &pb.CaCerts{
					Cacert: []string{
						"MIIB3zCCAWWgAwIBAgIIY2hNABEgfdwwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTM0MDMyMDE1MDEwNFowNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaBYrQANrXYQ18O9V2vKhBL7ovUm08g/R8wqFGvUe00bnvD/abQ/TITDhi/OYt2mw6TjCNGbcfoR4g4sc8nbm4SWCDklPCchiBUE3U038Q1pgurYil4SEP9aN770ik4PGo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDGF7Wkdff6c4YPYn0r66emv6elcwCgYIKoZIzj0EAwMDaAAwZQIwMbH3l4rQkFpr8Hh4yRBOn7BedBLgXehNXRpG15zHN+DmgGdZOQ5+3kiOjLTqBWYSAjEA0WDLGsF3XSHCQfEWF5zyXomMpPdg8ZuqBHeSBJQMvmL4S+dfkLd/TP1L+R+7nQjn",
					},
				},
			},
			Children: []*pb.Child{

				{
					Name: "nett",
					LocalTs: &pb.TrafficSelectors{
						Ts: []*pb.TrafficSelectors_TrafficSelector{
							{
								Cidr: "10.1.0.0/24",
							},
						},
					},
					RekeyTime: 0,
				},
				{
					Name: "hostt",

					RekeyTime: 0,
				},
			},
		}},
		expectErr: false,
	},
		{
			name: "with multiple chiilds",
			connReq: &pb.IPsecLoadConnRequest{
				Connection: &pb.Connection{
					Name:       "Con",
					Version:    "2",
					RekeyTime:  0,
					DpdDelay:   30,
					DpdTimeout: 90,
					LocalAddrs: []*pb.Addrs{
						{Addr: "192.168.1.1"},
						{Addr: "192.168.1.2"},
					},
					RemoteAddrs: []*pb.Addrs{
						{Addr: "10.0.0.1"},
					},
					LocalPort:  500,
					RemotePort: 500,
					Proposals: &pb.Proposals{
						CryptoAlg: []pb.CryptoAlgorithm{
							pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES256GCM128,
						},
						IntegAlg: []pb.IntegAlgorithm{
							pb.IntegAlgorithm_INTEG_ALGORITHM_SHA256,
						},
						Prf: []pb.PRFunction{
							pb.PRFunction_PR_FUNCTION_SHA1,
						},
						Dhgroups: []pb.DHGroups{
							pb.DHGroups_DH_GROUPS_MODP768,
						},
					},
					Vips: &pb.Vips{
						Vip: []string{
							"1.1.1.1",
							"2.2.2.2",
						},
					},
					Dscp:       000001,
					Encap:      "no",
					Mobike:     "yes",
					ReauthTime: 0,
					Pools: &pb.Pools{
						Pool: []string{
							"1.1.1.1",
							"2.2.2.2",
						},
					},
					LocalAuth: &pb.LocalAuth{
						Auth:    pb.AuthType_AUTH_TYPE_EAP,
						Id:      "id",
						EapId:   "id",
						AaaId:   "id",
						XauthId: "id",
					},
					RemoteAuth: &pb.RemoteAuth{
						Auth: pb.AuthType_AUTH_TYPE_EAP,
						Id:   "id",
					},
					Children: []*pb.Child{
						{
							Name:      "ikev1",
							RekeyTime: 2,
							LifeTime:  2,
							RandTime:  2,
							EspProposals: &pb.Proposals{
								CryptoAlg: []pb.CryptoAlgorithm{
									pb.CryptoAlgorithm_CRYPTO_ALGORITHM_AES256GCM128,
								},
								IntegAlg: []pb.IntegAlgorithm{
									pb.IntegAlgorithm_INTEG_ALGORITHM_SHA256,
								},
								Prf: []pb.PRFunction{
									pb.PRFunction_PR_FUNCTION_SHA1,
								},
								Dhgroups: []pb.DHGroups{
									pb.DHGroups_DH_GROUPS_MODP768,
								},
							},
							MarkIn:     uint32(0x00000000),
							MarkOut:    uint32(0x00000000),
							SetMarkIn:  uint32(0x00000000),
							SetMarkOut: uint32(0x00000000),
							Inactivity: uint32(0),

							LocalTs: &pb.TrafficSelectors{
								Ts: []*pb.TrafficSelectors_TrafficSelector{
									{
										Cidr: "10.1.0.0/16",
									},
									{
										Cidr: "10.2.0.0/16",
									},
								},
							},

							RemoteTs: &pb.TrafficSelectors{
								Ts: []*pb.TrafficSelectors_TrafficSelector{
									{
										Cidr: "10.1.0.2/16",
									},
									{
										Cidr: "10.2.0.2/16",
									},
								},
							},
						},
					}},
			},
			expectErr: false,
		},
	}

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log.Printf("Running test case: %s", tc.name)
			err := loadConn(tc.connReq)

			if tc.expectErr && err == nil {
				t.Fatalf("Expected an error but got nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("Did not expect an error but got: %v", err)
			}
			log.Printf("Test case passed: %s", tc.name)
		})
	}
}
func TestUnloadConn(t *testing.T) {
	type args struct {
		connreq *pb.IPsecUnloadConnRequest
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Unload Connection",
			args: args{
				connreq: &pb.IPsecUnloadConnRequest{
					Name: "conn",
				},
			},
			wantErr: false,
		},
		{

			name: "Empty Name",
			args: args{
				connreq: &pb.IPsecUnloadConnRequest{
					Name: "",
				},
			},
			wantErr: true,
		},

		{
			name: "Invalid Name",
			args: args{
				connreq: &pb.IPsecUnloadConnRequest{
					Name: "noo",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := unloadConn(tt.args.connreq); (err != nil) != tt.wantErr {
				t.Errorf("unloadConn() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestListCert(t *testing.T) {
	type args struct {
		listreq *pb.IPsecListCertsRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *pb.IPsecListCertsResponse
		wantErr bool
	}{
		{
			name: "All Fields",
			args: args{
				listreq: &pb.IPsecListCertsRequest{
					Type:    "ANY",
					Flag:    "X509_CERTIFICATE_FLAG_CA ",
					Subject: "C=CH, O=Cyber, CN=Cyber Root CA",
				},
			},
			want: &pb.IPsecListCertsResponse{
				Certs: []*pb.ListCert{

					{
						Flag: pb.X509CertificateFlag_X509_CERTIFICATE_FLAG_CA,
						Data: "MIIB3zCCAWWgAwIBAgIIY2hNABEgfdwwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTM0MDMyMDE1MDEwNFowNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaBYrQANrXYQ18O9V2vKhBL7ovUm08g/R8wqFGvUe00bnvD/abQ/TITDhi/OYt2mw6TjCNGbcfoR4g4sc8nbm4SWCDklPCchiBUE3U038Q1pgurYil4SEP9aN770ik4PGo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDGF7Wkdff6c4YPYn0r66emv6elcwCgYIKoZIzj0EAwMDaAAwZQIwMbH3l4rQkFpr8Hh4yRBOn7BedBLgXehNXRpG15zHN+DmgGdZOQ5+3kiOjLTqBWYSAjEA0WDLGsF3XSHCQfEWF5zyXomMpPdg8ZuqBHeSBJQMvmL4S+dfkLd/TP1L+R+7nQjn",
					},
					{},
				},
			},
			wantErr: false,
		},
		{
			name: "Any type",
			args: args{
				listreq: &pb.IPsecListCertsRequest{
					Type: "ANY",
				},
			},
			want: &pb.IPsecListCertsResponse{
				Certs: []*pb.ListCert{
					{
						Data: "MIIB/jCCAYWgAwIBAgIIdjhAuCUYRAowCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTI4MDMyMDE1MDEwNFowPTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMR4wHAYDVQQDExVzZXJ2ZXIuc3Ryb25nc3dhbi5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASg6vN2xsiEnhYhyUsSaR/36nLeaFiWaQNWg2yDs1s7uUd1cV5blykLCLlZkWrsCevAUSd31bk0zwE5sejbmpr6QT/gx1vk0SX00X8J5fBJuWrc11t8zibT0M3DSizMkCKjWjBYMB8GA1UdIwQYMBaAFAxhe1pHX3+nOGD2J9K+unpr+npXMCAGA1UdEQQZMBeCFXNlcnZlci5zdHJvbmdzd2FuLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAwNnADBkAjB9FEikOg5H7G0nLi32b76gs/+hQc1bD76aUGlB9jMM0194Xv6np2WXW1vaJEcdPzICMFqJeIPbztLv5dXZ48vX9jsOAxFfL5hF+noqP2XEyWWjdFoOdl2OOCItO6Vtgj5wFw==",
					},
					{
						Hasprivkey: "yes",
						Data:       "MIIB/jCCAYWgAwIBAgIICMc07G3AzUkwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTI4MDMyMDE1MDEwNFowPTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMR4wHAYDVQQDExVjbGllbnQuc3Ryb25nc3dhbi5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATDL1oHZ5vUCPHuehNQEu6QBSLCgmHPgumNgvuN7mJGonygw9NQIRL1OD/gBAgy+6uaq/EjGv0+8/wK+wvOW6z+nJbm2fR51z+ix7OjkBOvSBv+v8QbcUsEsU72LvBTLeqjWjBYMB8GA1UdIwQYMBaAFAxhe1pHX3+nOGD2J9K+unpr+npXMCAGA1UdEQQZMBeCFWNsaWVudC5zdHJvbmdzd2FuLm9yZzATBgNVHSUEDDAKBggrBgEFBQcDAjAKBggqhkjOPQQDAwNnADBkAjAo+M9G3gKmrYY+flGXN3VqztMvtil9vTXeFYABQ+UUXtDz5pY379bvV/rHdcamJCQCMB1ilfGVHqrcDzcAwp4QlzEboXwcXOx9QZSVbSXafRIJZ8zSxZePmRAVC1DsSTXjdA==",
					},
					{
						Flag: pb.X509CertificateFlag_X509_CERTIFICATE_FLAG_CA,
						Data: "MIIB3zCCAWWgAwIBAgIIY2hNABEgfdwwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTM0MDMyMDE1MDEwNFowNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaBYrQANrXYQ18O9V2vKhBL7ovUm08g/R8wqFGvUe00bnvD/abQ/TITDhi/OYt2mw6TjCNGbcfoR4g4sc8nbm4SWCDklPCchiBUE3U038Q1pgurYil4SEP9aN770ik4PGo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDGF7Wkdff6c4YPYn0r66emv6elcwCgYIKoZIzj0EAwMDaAAwZQIwMbH3l4rQkFpr8Hh4yRBOn7BedBLgXehNXRpG15zHN+DmgGdZOQ5+3kiOjLTqBWYSAjEA0WDLGsF3XSHCQfEWF5zyXomMpPdg8ZuqBHeSBJQMvmL4S+dfkLd/TP1L+R+7nQjn",
					},
					{},
				},
			},
			wantErr: false,
		},

		{
			name: "only subject",
			args: args{
				listreq: &pb.IPsecListCertsRequest{
					Subject: "C=CH, O=Cyber, CN=Cyber Root CA",
				},
			},
			want: &pb.IPsecListCertsResponse{
				Certs: []*pb.ListCert{
					{
						Flag: pb.X509CertificateFlag_X509_CERTIFICATE_FLAG_CA,
						Data: "MIIB3zCCAWWgAwIBAgIIY2hNABEgfdwwCgYIKoZIzj0EAwMwNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMB4XDTI0MDMyMDE1MDEwNFoXDTM0MDMyMDE1MDEwNFowNTELMAkGA1UEBhMCQ0gxDjAMBgNVBAoTBUN5YmVyMRYwFAYDVQQDEw1DeWJlciBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEaBYrQANrXYQ18O9V2vKhBL7ovUm08g/R8wqFGvUe00bnvD/abQ/TITDhi/OYt2mw6TjCNGbcfoR4g4sc8nbm4SWCDklPCchiBUE3U038Q1pgurYil4SEP9aN770ik4PGo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDGF7Wkdff6c4YPYn0r66emv6elcwCgYIKoZIzj0EAwMDaAAwZQIwMbH3l4rQkFpr8Hh4yRBOn7BedBLgXehNXRpG15zHN+DmgGdZOQ5+3kiOjLTqBWYSAjEA0WDLGsF3XSHCQfEWF5zyXomMpPdg8ZuqBHeSBJQMvmL4S+dfkLd/TP1L+R+7nQjn",
					},
					{},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listCerts(tt.args.listreq)
			if (err != nil) != tt.wantErr {
				t.Errorf("listCerts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, len(got.Certs), len(tt.want.Certs))
			assert.Equal(t, tt.want, got)
		})
	}
}
