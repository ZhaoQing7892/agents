/*
Copyright 2025 The OpenKruise Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// csi-mount-cli is a debug tool that simulates AgentRuntime's CSI NodePublishVolume request
// to invoke CSI Sidecar directly via gRPC over Unix socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// Default socket paths
	defaultSocketPath = "/var/run/csi/mount.sock"

	// Default access mode
	defaultAccessMode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER

	// Default volume context path
	defaultVolumePath = "/"
)

type MountRequest struct {
	Source  string            `json:"source,omitempty"`
	Target  string            `json:"target,omitempty"`
	Fstype  string            `json:"fstype,omitempty"`
	Options []string          `json:"options,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

type repeatedString []string

func (r *repeatedString) String() string {
	return fmt.Sprintf("%v", *r)
}

func (r *repeatedString) Set(value string) error {
	*r = append(*r, value)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		source  = flag.String("source", "", "Source (e.g., bucket name or NAS path)")
		target  = flag.String("target", "", "Target mount path on host")
		fstype  = flag.String("fstype", "", "Filesystem type (e.g., ossfs, nfs)")
		options repeatedString
		secrets repeatedString // format: key=value
	)
	flag.Var(&options, "option", "Mount options (can be repeated)")
	flag.Var(&secrets, "secret", "Secrets in key=value format (can be repeated)")

	flag.Parse()

	if err := validateFlags(*source, *target, *fstype); err != nil {
		return err
	}

	secretMap, err := parseSecrets(secrets)
	if err != nil {
		return err
	}
	for _, s := range secrets {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid secret format: %s, expected key=value", s)
		}
		secretMap[parts[0]] = parts[1]
	}

	req := &MountRequest{
		Source:  *source,
		Target:  *target,
		Fstype:  *fstype,
		Options: options,
		Secrets: secretMap,
	}

	if err := SetupVolume(req); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}
	fmt.Println("Volume mounted successfully")
	return nil
}

func SetupVolume(req *MountRequest) error {
	// Step 1: Map fstype to CSI socket path
	socketPath := defaultSocketPath

	// Step 2: Build CSI NodePublishVolumeRequest
	csiReq := buildNodePublishVolumeRequest(req)

	// Step 3: Dial CSI socket via gRPC
	conn, err := dialCSISocket(socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to CSI socket %s: %w", socketPath, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Warning: failed to close connection: %v", closeErr)
		}
	}()

	client := csi.NewNodeClient(conn)
	_, err = client.NodePublishVolume(context.Background(), csiReq)
	return err
}

func validateFlags(source, target, fstype string) error {
	if source == "" || target == "" || fstype == "" {
		return fmt.Errorf("--source, --target, and --fstype are required")
	}

	// Validate that target path is absolute
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("--target must be an absolute path")
	}

	return nil
}

func parseSecrets(secrets repeatedString) (map[string]string, error) {
	secretMap := make(map[string]string)
	for _, s := range secrets {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid secret format: %s, expected key=value", s)
		}
		secretMap[parts[0]] = parts[1]
	}
	return secretMap, nil
}
func buildNodePublishVolumeRequest(req *MountRequest) *csi.NodePublishVolumeRequest {
	csiReq := &csi.NodePublishVolumeRequest{
		VolumeId:   fmt.Sprintf("%s-%s", req.Fstype, req.Source), // simple ID
		TargetPath: req.Target,
		VolumeCapability: &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Mount{
				Mount: &csi.VolumeCapability_MountVolume{
					FsType:     req.Fstype,
					MountFlags: req.Options,
				},
			},
			AccessMode: &csi.VolumeCapability_AccessMode{
				Mode: defaultAccessMode,
			},
		},
		Readonly: false,
		Secrets:  req.Secrets,
		VolumeContext: map[string]string{
			"path":   defaultVolumePath,
			"bucket": req.Source, // for OSS; for NAS this could be server:path
		},
	}

	// Add PublishContext for OSS if applicable
	// TODO: Add specific request parameters based on fstype
	if req.Fstype == "ossfs" {
		csiReq.PublishContext = getOSSPublishContext()
		csiReq.StagingTargetPath = ""
	}

	return csiReq
}

func getOSSPublishContext() map[string]string {
	return map[string]string{
		"fusePod":          "ack-csi-fuse/csi-fuse-ossfs-xxxxx",
		"mountProxySocket": "/run/fuse.ossfs/.../mounter.sock", // TODO: how to get?
	}
}

func dialCSISocket(socketPath string) (*grpc.ClientConn, error) {
	return grpc.Dial(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", addr)
		}),
	)
}
