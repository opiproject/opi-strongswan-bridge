// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"context"
	"log"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
)

// Server represents the Server object
type Server struct {
	pb.UnimplementedIPsecServer
}

// IPsecVersion executes the ipsecVersion
func (s *Server) IPsecVersion(ctx context.Context, in *pb.IPsecVersionReq) (*pb.IPsecVersionResp, error) {
	ver, err := ipsecVersion()
	if err != nil {
		log.Printf("IPsecVersion: Failed %v", err)
		return nil, err
	}

	return ver, nil
}

// IPsecStats executes the ipsecStats
func (s *Server) IPsecStats(ctx context.Context, in *pb.IPsecStatsReq) (*pb.IPsecStatsResp, error) {
	stats, err := ipsecStats()
	if err != nil {
		log.Printf("IPsecStats: Failed %v", err)
		return nil, err
	}

	return stats, nil
}

// IPsecInitiate executes the initiateConn
func (s *Server) IPsecInitiate(ctx context.Context, in *pb.IPsecInitiateReq) (*pb.IPsecInitiateResp, error) {
	log.Printf("IPsecInitiate: Received: %v", in)

	err := initiateConn(in)
	if err != nil {
		log.Printf("IPsecInitiate: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecInitiateResp{}

	return &ret, nil
}

// IPsecTerminate executes the terminateConn
func (s *Server) IPsecTerminate(ctx context.Context, in *pb.IPsecTerminateReq) (*pb.IPsecTerminateResp, error) {
	log.Printf("IPsecTerminate: Received: %v", in)

	matches, err := terminateConn(in)
	if err != nil {
		log.Printf("IPsecTerminate: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecTerminateResp{
		Success: "Yes",
		Matches: matches,
	}

	return &ret, nil
}

// IPsecRekey executes the rekeyConn
func (s *Server) IPsecRekey(ctx context.Context, in *pb.IPsecRekeyReq) (*pb.IPsecRekeyResp, error) {
	log.Printf("IPsecRekey: Received: %v", in)

	success, matches, err := rekeyConn(in)
	if err != nil {
		log.Printf("IPsecRekey: Failed: %v", err)
		return nil, err
	}

	ret := pb.IPsecRekeyResp{
		Success: success,
		Matches: matches,
	}

	return &ret, nil
}

// IPsecListSas executes the listSas
func (s *Server) IPsecListSas(ctx context.Context, in *pb.IPsecListSasReq) (*pb.IPsecListSasResp, error) {
	log.Printf("IPsecListSas: Received %v", in)

	ret, err := listSas(in)
	if err != nil {
		log.Printf("IPsecListSas: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecListConns executes the listConns
func (s *Server) IPsecListConns(ctx context.Context, in *pb.IPsecListConnsReq) (*pb.IPsecListConnsResp, error) {
	log.Printf("IPsecListConns: Received: %v", in)

	ret, err := listConns(in)
	if err != nil {
		log.Printf("IPsecListConns: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecListCerts executes the listCerts
func (s *Server) IPsecListCerts(ctx context.Context, in *pb.IPsecListCertsReq) (*pb.IPsecListCertsResp, error) {
	log.Printf("IPsecListCerts: Received: %v", in)

	ret, err := listCerts(in)
	if err != nil {
		log.Printf("IPsecListConns: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecLoadConn executes the loadConn
func (s *Server) IPsecLoadConn(ctx context.Context, in *pb.IPsecLoadConnReq) (*pb.IPsecLoadConnResp, error) {
	log.Printf("IPsecLoadConn: Received: %v", in.GetConnection())

	err := loadConn(in)
	if err != nil {
		log.Printf("IPsecLoadConn: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecLoadConnResp{
		Success: "Yes",
	}

	return &ret, nil
}

// IPsecUnloadConn executes the unloadConn
func (s *Server) IPsecUnloadConn(ctx context.Context, in *pb.IPsecUnloadConnReq) (*pb.IPsecUnloadConnResp, error) {
	log.Printf("IPsecUnloadConn: Received: %v", in.GetName())

	err := unloadConn(in)
	if err != nil {
		log.Printf("IPsecUnloadConn: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecUnloadConnResp{
		Success: "Yes",
	}

	return &ret, nil
}
