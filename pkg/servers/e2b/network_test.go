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
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/cache"
	"github.com/openkruise/agents/pkg/servers/e2b/keys"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
)

// generateCIDREntries returns n unique valid CIDR entries for testing
// entry-count limits.
func generateCIDREntries(n int) []string {
	entries := make([]string, n)
	for i := range entries {
		entries[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	return entries
}

func TestValidateDenyOut(t *testing.T) {
	tests := []struct {
		name        string
		denyOut     []string
		expectError string
	}{
		{
			name:        "valid CIDR entries",
			denyOut:     []string{"10.0.0.0/8", "192.168.1.0/24"},
			expectError: "",
		},
		{
			name:        "valid bare IP entries",
			denyOut:     []string{"8.8.8.8", "1.1.1.1"},
			expectError: "",
		},
		{
			name:        "valid mixed CIDR and IP",
			denyOut:     []string{"10.0.0.0/8", "8.8.8.8"},
			expectError: "",
		},
		{
			name:        "valid IPv6 CIDR",
			denyOut:     []string{"::1/128", "2001:db8::/32"},
			expectError: "",
		},
		{
			name:        "empty list is valid",
			denyOut:     []string{},
			expectError: "",
		},
		{
			name:        "nil list is valid",
			denyOut:     nil,
			expectError: "",
		},
		{
			name:        "plain domain rejected",
			denyOut:     []string{"example.com"},
			expectError: "domains are not supported in denyOut",
		},
		{
			name:        "wildcard domain rejected",
			denyOut:     []string{"*.example.com"},
			expectError: "domains are not supported in denyOut",
		},
		{
			name:        "multi-level domain rejected",
			denyOut:     []string{"api.openai.com"},
			expectError: "domains are not supported in denyOut",
		},
		{
			name:        "domain mixed with valid CIDR rejected",
			denyOut:     []string{"10.0.0.0/8", "evil.com"},
			expectError: "domains are not supported in denyOut",
		},
		{
			name:        "all-traffic CIDR is valid",
			denyOut:     []string{"0.0.0.0/0"},
			expectError: "",
		},
		{
			name:        "denyOut exceeds max entries",
			denyOut:     generateCIDREntries(maxNetworkEntriesPerList + 1),
			expectError: "denyOut list exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDenyOut(tt.denyOut)
			if tt.expectError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			}
		})
	}
}

func TestValidateAllowOut(t *testing.T) {
	tests := []struct {
		name        string
		allowOut    []string
		expectError string
	}{
		{
			name:        "valid CIDR entries",
			allowOut:    []string{"10.0.0.0/8", "192.168.1.0/24"},
			expectError: "",
		},
		{
			name:        "valid bare IP entries",
			allowOut:    []string{"8.8.8.8", "1.1.1.1"},
			expectError: "",
		},
		{
			name:        "valid domain entries",
			allowOut:    []string{"example.com", "api.openai.com"},
			expectError: "",
		},
		{
			name:        "wildcard prefix rejected",
			allowOut:    []string{"*.example.com", "*.openai.com"},
			expectError: "wildcard domains are not supported",
		},
		{
			name:        "wildcard in middle rejected",
			allowOut:    []string{"api.*.github.com"},
			expectError: "wildcard domains are not supported",
		},
		{
			name:        "wildcard at end rejected",
			allowOut:    []string{"example.com.*"},
			expectError: "wildcard domains are not supported",
		},
		{
			name:        "wildcard without dot rejected",
			allowOut:    []string{"*example.com"},
			expectError: "wildcard domains are not supported",
		},
		{
			name:        "wildcard mixed with valid entries rejected",
			allowOut:    []string{"10.0.0.0/8", "8.8.8.8", "api.example.com", "*.github.com"},
			expectError: "wildcard domains are not supported",
		},
		{
			name:        "valid mixed CIDR IP and domain",
			allowOut:    []string{"10.0.0.0/8", "8.8.8.8", "api.example.com", "github.com"},
			expectError: "",
		},
		{
			name:        "empty list is valid",
			allowOut:    []string{},
			expectError: "",
		},
		{
			name:        "nil list is valid",
			allowOut:    nil,
			expectError: "",
		},
		{
			name:        "garbage string rejected",
			allowOut:    []string{">>>invalid"},
			expectError: "invalid allowOut entry",
		},
		{
			name:        "single label rejected",
			allowOut:    []string{"localhost"},
			expectError: "invalid allowOut entry",
		},
		{
			name:        "empty string rejected",
			allowOut:    []string{""},
			expectError: "invalid allowOut entry",
		},
		{
			name:        "TLD too short rejected",
			allowOut:    []string{"example.a"},
			expectError: "invalid allowOut entry",
		},
		{
			name:        "invalid entry mixed with valid rejected",
			allowOut:    []string{"10.0.0.0/8", ">>>bad"},
			expectError: "invalid allowOut entry",
		},
		{
			name:        "allowOut exceeds max entries",
			allowOut:    generateCIDREntries(maxNetworkEntriesPerList + 1),
			expectError: "allowOut list exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAllowOut(tt.allowOut)
			if tt.expectError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			}
		})
	}
}

func TestValidateAndBuildNetworkConfig_DenyOutDomainError(t *testing.T) {
	// Validation is centralized in validateAndBuildNetworkConfig.
	_, err := validateAndBuildNetworkConfig(nil, &models.SandboxNetworkConfig{
		DenyOut: []string{"example.com"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domains are not supported in denyOut")
}

func TestApplyAllowInternetAccess(t *testing.T) {
	falseVal := false
	trueVal := true

	tests := []struct {
		name                string
		allowInternetAccess *bool
		denyOut             []string
		wantDenyOut         []string
	}{
		{
			name:                "nil pointer: no change",
			allowInternetAccess: nil,
			denyOut:             []string{"10.0.0.0/8"},
			wantDenyOut:         []string{"10.0.0.0/8"},
		},
		{
			name:                "true: no change",
			allowInternetAccess: &trueVal,
			denyOut:             []string{"10.0.0.0/8"},
			wantDenyOut:         []string{"10.0.0.0/8"},
		},
		{
			name:                "false: adds 0.0.0.0/0 and ::/0",
			allowInternetAccess: &falseVal,
			denyOut:             []string{"10.0.0.0/8"},
			wantDenyOut:         []string{"10.0.0.0/8", "0.0.0.0/0", "::/0"},
		},
		{
			name:                "false with empty denyOut: adds 0.0.0.0/0 and ::/0",
			allowInternetAccess: &falseVal,
			denyOut:             nil,
			wantDenyOut:         []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:                "false with existing 0.0.0.0/0: adds ::/0",
			allowInternetAccess: &falseVal,
			denyOut:             []string{"0.0.0.0/0"},
			wantDenyOut:         []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:                "false with existing ::/0: adds 0.0.0.0/0",
			allowInternetAccess: &falseVal,
			denyOut:             []string{"::/0"},
			wantDenyOut:         []string{"::/0", "0.0.0.0/0"},
		},
		{
			name:                "false with existing both: not duplicated",
			allowInternetAccess: &falseVal,
			denyOut:             []string{"0.0.0.0/0", "::/0"},
			wantDenyOut:         []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:                "false with existing 0.0.0.0/0 among others: adds ::/0",
			allowInternetAccess: &falseVal,
			denyOut:             []string{"10.0.0.0/8", "0.0.0.0/0", "8.8.8.8"},
			wantDenyOut:         []string{"10.0.0.0/8", "0.0.0.0/0", "8.8.8.8", "::/0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyAllowInternetAccess(tt.allowInternetAccess, tt.denyOut)
			assert.Equal(t, tt.wantDenyOut, got)
		})
	}
}

func TestValidateAndBuildNetworkConfig(t *testing.T) {
	falseVal := false
	trueVal := true

	tests := []struct {
		name                string
		allowInternetAccess *bool
		network             *models.SandboxNetworkConfig
		wantNil             bool
		wantAllow           []string
		wantDeny            []string
		expectError         string
	}{
		{
			name:                "nil allowInternetAccess, nil network: returns nil",
			allowInternetAccess: nil,
			network:             nil,
			wantNil:             true,
			expectError:         "",
		},
		{
			name:                "true allowInternetAccess, nil network: returns nil",
			allowInternetAccess: &trueVal,
			network:             nil,
			wantNil:             true,
			expectError:         "",
		},
		{
			name:                "nil allowInternetAccess, network with allowOut: returns as-is",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"10.0.0.0/8"},
			},
			wantNil:     false,
			wantAllow:   []string{"10.0.0.0/8"},
			wantDeny:    nil,
			expectError: "",
		},
		{
			name:                "nil allowInternetAccess, network with denyOut: returns as-is",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				DenyOut: []string{"10.0.0.0/8"},
			},
			wantNil:     false,
			wantAllow:   nil,
			wantDeny:    []string{"10.0.0.0/8"},
			expectError: "",
		},
		{
			name:                "false allowInternetAccess, nil network: creates config with 0.0.0.0/0 and ::/0",
			allowInternetAccess: &falseVal,
			network:             nil,
			wantNil:             false,
			wantDeny:            []string{"0.0.0.0/0", "::/0"},
			expectError:         "",
		},
		{
			name:                "false allowInternetAccess, network with allowOut: merges 0.0.0.0/0 and ::/0 into denyOut",
			allowInternetAccess: &falseVal,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"10.0.0.0/8"},
				DenyOut:  []string{"8.8.4.4"},
			},
			wantNil:     false,
			wantAllow:   []string{"10.0.0.0/8"},
			wantDeny:    []string{"8.8.4.4", "0.0.0.0/0", "::/0"},
			expectError: "",
		},
		{
			name:                "false allowInternetAccess, network with existing 0.0.0.0/0: adds ::/0",
			allowInternetAccess: &falseVal,
			network: &models.SandboxNetworkConfig{
				DenyOut: []string{"0.0.0.0/0"},
			},
			wantNil:     false,
			wantDeny:    []string{"0.0.0.0/0", "::/0"},
			expectError: "",
		},
		{
			name:                "domain in denyOut rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				DenyOut: []string{"example.com"},
			},
			wantNil:     true,
			expectError: "domains are not supported in denyOut",
		},
		{
			name:                "wildcard domain in denyOut rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				DenyOut: []string{"*.evil.com"},
			},
			wantNil:     true,
			expectError: "domains are not supported in denyOut",
		},
		{
			name:                "false allowInternetAccess, domain in denyOut rejected",
			allowInternetAccess: &falseVal,
			network: &models.SandboxNetworkConfig{
				DenyOut: []string{"bad.com"},
			},
			wantNil:     true,
			expectError: "domains are not supported in denyOut",
		},
		{
			name:                "empty allowOut and denyOut with nil allowInternetAccess: returns nil",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{},
				DenyOut:  []string{},
			},
			wantNil:     true,
			expectError: "",
		},
		{
			name:                "mixed allowOut (bare IP + domain) and mixed denyOut (CIDR + bare IP): valid",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"1.2.3.4", "api.example.com"},
				DenyOut:  []string{"10.0.0.0/8", "8.8.8.8"},
			},
			wantNil:     false,
			wantAllow:   []string{"1.2.3.4", "api.example.com"},
			wantDeny:    []string{"10.0.0.0/8", "8.8.8.8"},
			expectError: "",
		},
		{
			name:                "wildcard domain in allowOut rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"192.168.1.0/24", "*.openai.com"},
				DenyOut:  []string{"172.16.0.0/12", "1.1.1.1"},
			},
			wantNil:     true,
			expectError: "wildcard domains are not supported",
		},
		{
			name:                "mixed allowOut (CIDR + domain) and mixed denyOut (CIDR + bare IP): valid",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"192.168.1.0/24", "api.openai.com"},
				DenyOut:  []string{"172.16.0.0/12", "1.1.1.1"},
			},
			wantNil:     false,
			wantAllow:   []string{"192.168.1.0/24", "api.openai.com"},
			wantDeny:    []string{"172.16.0.0/12", "1.1.1.1"},
			expectError: "",
		},
		{
			name:                "mixed allowOut (IP + domain) and denyOut with domain: rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"1.2.3.4", "api.example.com"},
				DenyOut:  []string{"10.0.0.0/8", "evil.com"},
			},
			wantNil:     true,
			expectError: "domains are not supported in denyOut",
		},
		{
			name:                "invalid allowOut entry rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{">>>invalid"},
			},
			wantNil:     true,
			expectError: "invalid allowOut entry",
		},
		{
			name:                "single label in allowOut rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"localhost"},
			},
			wantNil:     true,
			expectError: "invalid allowOut entry",
		},
		{
			name:                "invalid allowOut mixed with valid CIDR rejected",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: []string{"10.0.0.0/8", ">>>bad"},
				DenyOut:  []string{"8.8.8.8"},
			},
			wantNil:     true,
			expectError: "invalid allowOut entry",
		},
		{
			name:                "allowOut exceeds max entries",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				AllowOut: generateCIDREntries(maxNetworkEntriesPerList + 1),
			},
			wantNil:     true,
			expectError: "allowOut list exceeds maximum",
		},
		{
			name:                "denyOut exceeds max entries",
			allowInternetAccess: nil,
			network: &models.SandboxNetworkConfig{
				DenyOut: generateCIDREntries(maxNetworkEntriesPerList + 1),
			},
			wantNil:     true,
			expectError: "denyOut list exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndBuildNetworkConfig(tt.allowInternetAccess, tt.network)
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantAllow, got.AllowOut)
			assert.Equal(t, tt.wantDeny, got.DenyOut)
		})
	}
}

// TestUpdateSandboxNetwork_InvalidBody verifies that a malformed JSON body
// results in a 400 Bad Request response.
func TestUpdateSandboxNetwork_InvalidBody(t *testing.T) {
	controller, _, teardown := Setup(t)
	defer teardown()
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	// Construct a request with invalid JSON body that cannot be decoded.
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("http://127.0.0.1:%d", TestServerPort),
		strings.NewReader("invalid json"))
	require.NoError(t, err)
	req.SetPathValue("sandboxID", "non-existent--sandbox")
	req = req.WithContext(context.WithValue(req.Context(), "user", user))

	resp, apiErr := controller.UpdateSandboxNetwork(req)
	require.NotNil(t, apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.Code)
	assert.Contains(t, apiErr.Message, "Failed to decode request body")
	_ = resp
}

// TestUpdateSandboxNetwork_ValidationError verifies that invalid network
// parameters are rejected with a 400 Bad Request before the sandbox is looked up.
func TestUpdateSandboxNetwork_ValidationError(t *testing.T) {
	controller, _, teardown := Setup(t)
	defer teardown()
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	tests := []struct {
		name        string
		req         models.SandboxNetworkUpdateConfig
		expectError string
	}{
		{
			name: "wildcard domain in allowOut rejected",
			req: models.SandboxNetworkUpdateConfig{
				AllowOut: []string{"*.example.com"},
			},
			expectError: "wildcard domains are not supported",
		},
		{
			name: "domain in denyOut rejected",
			req: models.SandboxNetworkUpdateConfig{
				DenyOut: []string{"example.com"},
			},
			expectError: "domains are not supported in denyOut",
		},
		{
			name: "invalid allowOut entry rejected",
			req: models.SandboxNetworkUpdateConfig{
				AllowOut: []string{">>>invalid"},
			},
			expectError: "invalid allowOut entry",
		},
		{
			name: "allowOut exceeds max entries",
			req: models.SandboxNetworkUpdateConfig{
				AllowOut: generateCIDREntries(maxNetworkEntriesPerList + 1),
			},
			expectError: "allowOut list exceeds maximum",
		},
		{
			name: "denyOut exceeds max entries",
			req: models.SandboxNetworkUpdateConfig{
				DenyOut: generateCIDREntries(maxNetworkEntriesPerList + 1),
			},
			expectError: "denyOut list exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, apiErr := controller.UpdateSandboxNetwork(NewRequest(t, nil, tt.req, map[string]string{
				"sandboxID": "non-existent--sandbox",
			}, user))
			require.NotNil(t, apiErr)
			assert.Equal(t, http.StatusBadRequest, apiErr.Code)
			assert.Contains(t, apiErr.Message, tt.expectError)
			_ = resp
		})
	}
}

// TestUpdateSandboxNetwork_SandboxNotFound verifies that updating the network
// of a non-existent sandbox returns an error.
func TestUpdateSandboxNetwork_SandboxNotFound(t *testing.T) {
	controller, _, teardown := Setup(t)
	defer teardown()
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	resp, apiErr := controller.UpdateSandboxNetwork(NewRequest(t, nil, models.SandboxNetworkUpdateConfig{
		AllowOut: []string{"1.2.3.4"},
	}, map[string]string{
		"sandboxID": "non-existent--sandbox",
	}, user))
	require.NotNil(t, apiErr)
	assert.Contains(t, apiErr.Message, "Cannot get sandbox")
	_ = resp
}

// TestUpdateSandboxNetwork_Success verifies successful network updates,
// including TrafficPolicy CR creation and deletion.
func TestUpdateSandboxNetwork_Success(t *testing.T) {
	controller, _, teardown := Setup(t)
	defer teardown()
	templateName := "test-network-template"
	cleanup := CreateSandboxPool(t, controller, templateName, 10)
	defer cleanup()
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	createResp, err := controller.CreateSandbox(NewRequest(t, nil, models.NewSandboxRequest{
		TemplateID: templateName,
		Metadata: map[string]string{
			models.ExtensionKeySkipInitRuntime: agentsv1alpha1.True,
		},
	}, nil, user))
	require.Nil(t, err)
	sandboxID := createResp.Body.SandboxID

	tests := []struct {
		name       string
		req        models.SandboxNetworkUpdateConfig
		expectCode int
		expectTP   bool // whether a TrafficPolicy CR should exist after the update
	}{
		{
			name: "update with allowOut and denyOut creates TP",
			req: models.SandboxNetworkUpdateConfig{
				AllowOut: []string{"1.2.3.4"},
				DenyOut:  []string{"10.0.0.0/8"},
			},
			expectCode: http.StatusNoContent,
			expectTP:   true,
		},
		{
			name: "update with allowInternetAccess false creates TP",
			req: models.SandboxNetworkUpdateConfig{
				AllowInternetAccess: ptr.To(false),
			},
			expectCode: http.StatusNoContent,
			expectTP:   true,
		},
		{
			name: "update with FQDN in allowOut creates TP",
			req: models.SandboxNetworkUpdateConfig{
				AllowOut: []string{"api.example.com"},
			},
			expectCode: http.StatusNoContent,
			expectTP:   true,
		},
		{
			name:       "update with empty config clears TP",
			req:        models.SandboxNetworkUpdateConfig{},
			expectCode: http.StatusNoContent,
			expectTP:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, apiErr := controller.UpdateSandboxNetwork(NewRequest(t, nil, tt.req, map[string]string{
				"sandboxID": sandboxID,
			}, user))
			require.Nil(t, apiErr)
			assert.Equal(t, tt.expectCode, resp.Code)

			// Verify TrafficPolicy CR state matches expectations.
			fc := getTestCRClient(controller)
			tpList := &agentsv1alpha1.TrafficPolicyList{}
			listErr := fc.List(t.Context(), tpList,
				ctrlclient.InNamespace(Namespace),
				ctrlclient.MatchingFields{cache.IndexTrafficPolicySandboxID: sandboxID},
			)
			require.NoError(t, listErr)
			if tt.expectTP {
				assert.Len(t, tpList.Items, 1, "expected one TrafficPolicy CR")
			} else {
				assert.Empty(t, tpList.Items, "expected no TrafficPolicy CRs")
			}
		})
	}
}
