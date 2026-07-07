/*
Copyright 2026.

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

package e2b

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"k8s.io/klog/v2"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
	"github.com/openkruise/agents/pkg/servers/web"
)

// labelSandboxID is the label key used to associate TrafficPolicy CRs with sandbox.
const labelSandboxID = agentsv1alpha1.AnnotationSandboxID

// allTrafficCIDR represents all IPv4 addresses, used when allowInternetAccess
// is set to false (equivalent to denyOut: ["0.0.0.0/0"]).
const allTrafficCIDR = "0.0.0.0/0"

// isCIDROrIP returns true if the entry is a valid CIDR or bare IP address.
func isCIDROrIP(entry string) bool {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return true
	}
	return net.ParseIP(entry) != nil
}

// validateDenyOut checks that all denyOut entries are valid CIDR or bare IP addresses.
func validateDenyOut(denyOut []string) error {
	for _, entry := range denyOut {
		if !isCIDROrIP(entry) {
			return fmt.Errorf("domains are not supported in denyOut: %q is not a valid CIDR or IP address", entry)
		}
	}
	return nil
}

// applyAllowInternetAccess merges the allowInternetAccess flag into denyOut.
func applyAllowInternetAccess(allowInternetAccess *bool, denyOut []string) []string {
	if allowInternetAccess == nil || *allowInternetAccess {
		return denyOut
	}
	for _, entry := range denyOut {
		if entry == allTrafficCIDR {
			return denyOut
		}
	}
	return append(denyOut, allTrafficCIDR)
}

// validateAndBuildNetworkConfig is the single entry point for validating raw
// network parameters and producing a normalized SandboxNetworkConfig ready for CR creation.
func validateAndBuildNetworkConfig(allowInternetAccess *bool, network *models.SandboxNetworkConfig) (*models.SandboxNetworkConfig, error) {
	// Step 1: Merge allowInternetAccess: false → denyOut: ["0.0.0.0/0"]
	if allowInternetAccess != nil && !*allowInternetAccess {
		if network == nil {
			network = &models.SandboxNetworkConfig{}
		}
		network.DenyOut = applyAllowInternetAccess(allowInternetAccess, network.DenyOut)
	}

	// Step 2: Return nil if no network rules are needed
	if network == nil || (len(network.AllowOut) == 0 && len(network.DenyOut) == 0) {
		return nil, nil
	}

	// Step 3: Validate denyOut — domains are not supported in deny lists
	if err := validateDenyOut(network.DenyOut); err != nil {
		return nil, err
	}

	return network, nil
}

// UpdateSandboxNetwork replaces the sandbox's network rules with the new configuration.
func (sc *Controller) UpdateSandboxNetwork(r *http.Request) (web.ApiResponse[struct{}], *web.ApiError) {
	ctx := r.Context()
	log := klog.FromContext(ctx)
	sandboxID := r.PathValue("sandboxID")

	var req models.SandboxNetworkUpdateConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return web.ApiResponse[struct{}]{}, &web.ApiError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Failed to decode request body: %v", err),
		}
	}

	// Validate and build the network config in one step.
	network, err := validateAndBuildNetworkConfig(req.AllowInternetAccess, req.SandboxNetworkConfig)
	if err != nil {
		return web.ApiResponse[struct{}]{}, &web.ApiError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}
	}

	sbx, apiErr := sc.getSandboxOfUser(ctx, sandboxID, liveSandboxStates)
	if apiErr != nil {
		return web.ApiResponse[struct{}]{}, apiErr
	}

	if network == nil {
		// No network rules: delete any existing CRs (replace-semantics).
		if err := sbx.DeleteSandboxNetwork(ctx); err != nil {
			log.Error(err, "failed to delete network CRs")
			return web.ApiResponse[struct{}]{}, &web.ApiError{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("Failed to update network: %v", err),
			}
		}
	} else {
		if err := sbx.UpdateSandboxNetwork(ctx, infra.SandboxNetworkConfig{
			AllowOut: network.AllowOut,
			DenyOut:  network.DenyOut,
		}); err != nil {
			log.Error(err, "failed to reconcile network CRs")
			return web.ApiResponse[struct{}]{}, &web.ApiError{
				Code:    http.StatusInternalServerError,
				Message: fmt.Sprintf("Failed to update network: %v", err),
			}
		}
	}

	log.Info("sandbox network updated", "sandboxID", sandboxID)
	return web.ApiResponse[struct{}]{
		Code: http.StatusNoContent,
	}, nil
}
