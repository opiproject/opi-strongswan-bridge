// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2022-2023 Intel Corporation, or its subsidiaries.

// Package ipsec is the main package of the application
package ipsec

import (
	"context"
	"log"

	pb "github.com/opiproject/opi-api/security/v1/gen/go"
)

// Server represents the Server object
type Server struct {
	pb.UnimplementedIPsecServiceServer
}

// IPsecVersion executes the ipsecVersion
func (s *Server) IPsecVersion(_ context.Context, _ *pb.IPsecVersionRequest) (*pb.IPsecVersionResponse, error) {
	ver, err := ipsecVersion()
	if err != nil {
		log.Printf("IPsecVersion: Failed %v", err)
		return nil, err
	}

	return ver, nil
}

// IPsecStats executes the ipsecStats
func (s *Server) IPsecStats(_ context.Context, _ *pb.IPsecStatsRequest) (*pb.IPsecStatsResponse, error) {
	stats, err := ipsecStats()
	if err != nil {
		log.Printf("IPsecStats: Failed %v", err)
		return nil, err
	}

	return stats, nil
}

// IPsecInitiate executes the initiateConn
func (s *Server) IPsecInitiate(_ context.Context, in *pb.IPsecInitiateRequest) (*pb.IPsecInitiateResponse, error) {
	log.Printf("IPsecInitiate: Received: %v", in)

	err := initiateConn(in)
	if err != nil {
		log.Printf("IPsecInitiate: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecInitiateResponse{}

	return &ret, nil
}

// IPsecTerminate executes the terminateConn
func (s *Server) IPsecTerminate(_ context.Context, in *pb.IPsecTerminateRequest) (*pb.IPsecTerminateResponse, error) {
	log.Printf("IPsecTerminate: Received: %v", in)

	matches, err := terminateConn(in)
	if err != nil {
		log.Printf("IPsecTerminate: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecTerminateResponse{
		Success: "Yes",
		Matches: matches,
	}

	return &ret, nil
}

// IPsecRekey executes the rekeyConn
func (s *Server) IPsecRekey(_ context.Context, in *pb.IPsecRekeyRequest) (*pb.IPsecRekeyResponse, error) {
	log.Printf("IPsecRekey: Received: %v", in)

	success, matches, err := rekeyConn(in)
	if err != nil {
		log.Printf("IPsecRekey: Failed: %v", err)
		return nil, err
	}

	ret := pb.IPsecRekeyResponse{
		Success: success,
		Matches: matches,
	}

	return &ret, nil
}

// IPsecListSas executes the listSas
func (s *Server) IPsecListSas(_ context.Context, in *pb.IPsecListSasRequest) (*pb.IPsecListSasResponse, error) {
	log.Printf("IPsecListSas: Received %v", in)

	ret, err := listSas(in)
	if err != nil {
		log.Printf("IPsecListSas: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecListConns executes the listConns
func (s *Server) IPsecListConns(_ context.Context, in *pb.IPsecListConnsRequest) (*pb.IPsecListConnsResponse, error) {
	log.Printf("IPsecListConns: Received: %v", in)

	ret, err := listConns(in)
	if err != nil {
		log.Printf("IPsecListConns: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecListCerts executes the listCerts
func (s *Server) IPsecListCerts(_ context.Context, in *pb.IPsecListCertsRequest) (*pb.IPsecListCertsResponse, error) {
	log.Printf("IPsecListCerts: Received: %v", in)

	ret, err := listCerts(in)
	if err != nil {
		log.Printf("IPsecListConns: Failed: %v", err)
		return nil, err
	}

	return ret, nil
}

// IPsecLoadConn executes the loadConn
func (s *Server) IPsecLoadConn(_ context.Context, in *pb.IPsecLoadConnRequest) (*pb.IPsecLoadConnResponse, error) {
	log.Printf("IPsecLoadConn: Received: %v", in.GetConnection())

	err := loadConn(in)
	if err != nil {
		log.Printf("IPsecLoadConn: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecLoadConnResponse{
		Success: "Yes",
	}

	return &ret, nil
}

// IPsecUnloadConn executes the unloadConn
func (s *Server) IPsecUnloadConn(_ context.Context, in *pb.IPsecUnloadConnRequest) (*pb.IPsecUnloadConnResponse, error) {
	log.Printf("IPsecUnloadConn: Received: %v", in.GetName())

	err := unloadConn(in)
	if err != nil {
		log.Printf("IPsecUnloadConn: Failed %v", err)
		return nil, err
	}

	ret := pb.IPsecUnloadConnResponse{
		Success: "Yes",
	}

	return &ret, nil
}
