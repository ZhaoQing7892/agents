/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sandboxcr

import (
	"context"
	"fmt"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
)

const labelSandboxID = agentsv1alpha1.AnnotationSandboxID

const defaultDenyCIDR = "0.0.0.0/0"

// sandboxOwnerRef returns an OwnerReference that points to the given Sandbox CR.
// Setting this on TrafficPolicy CRs ensures they are garbage-collected
// when the owning Sandbox is deleted (including timeout-driven deletion by the controller).
func sandboxOwnerRef(owner *agentsv1alpha1.Sandbox) metav1.OwnerReference {
	controller := true
	blockOwnerDeletion := true
	return metav1.OwnerReference{
		APIVersion:         agentsv1alpha1.GroupVersion.String(),
		Kind:               "Sandbox",
		Name:               owner.Name,
		UID:                owner.UID,
		Controller:         &controller,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}
}

// isCIDROrIP returns true if the entry is a valid CIDR or bare IP address.
func isCIDROrIP(entry string) bool {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return true
	}
	return net.ParseIP(entry) != nil
}

// normalizeToCIDR converts a bare IP to CIDR notation.
// IPv4 becomes /32, IPv6 becomes /128.
// If the entry is already a CIDR, it is returned as-is.
func normalizeToCIDR(entry string) string {
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return entry
	}
	if ip := net.ParseIP(entry); ip != nil {
		if ip.To4() != nil {
			return entry + "/32"
		}
		return entry + "/128"
	}
	return entry
}

// splitAllowOut separates allowOut entries into CIDR/IP entries and domain entries.
func splitAllowOut(allowOut []string) (cidrs, domains []string) {
	for _, entry := range allowOut {
		if isCIDROrIP(entry) {
			cidrs = append(cidrs, normalizeToCIDR(entry))
		} else {
			domains = append(domains, entry)
		}
	}
	return cidrs, domains
}

// containsAllTrafficCIDR returns true if the CIDR list contains 0.0.0.0/0
func containsAllTrafficCIDR(cidrs []string) bool {
	for _, cidr := range cidrs {
		if cidr == defaultDenyCIDR || cidr == "::/0" {
			return true
		}
	}
	return false
}

// buildTrafficPolicy builds a TrafficPolicy CR that encodes both CIDR/IP and
// domain rules. Domain entries use the FQDN peer field
func buildTrafficPolicy(allowOutCIDRs, allowOutDomains, denyOut []string, namespace, sandboxID string, owner *agentsv1alpha1.Sandbox) *agentsv1alpha1.TrafficPolicy {
	if len(allowOutCIDRs) == 0 && len(allowOutDomains) == 0 && len(denyOut) == 0 {
		return nil
	}

	hasAllowOut := len(allowOutCIDRs) > 0 || len(allowOutDomains) > 0
	rules := make([]agentsv1alpha1.TrafficPolicyRule, 0, 3)

	if hasAllowOut {
		// Whitelist mode: allow CIDR/IP and FQDN entries, explicit deny, then default deny
		allowPeers := make([]agentsv1alpha1.TrafficPolicyPeer, 0, len(allowOutCIDRs)+len(allowOutDomains))
		for _, cidr := range allowOutCIDRs {
			allowPeers = append(allowPeers, agentsv1alpha1.TrafficPolicyPeer{CIDR: cidr})
		}
		for _, fqdn := range allowOutDomains {
			allowPeers = append(allowPeers, agentsv1alpha1.TrafficPolicyPeer{FQDN: fqdn})
		}
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionAllow,
			To:     allowPeers,
		})
		// Explicit deny rules (preserved for round-trip fidelity)
		if len(denyOut) > 0 {
			denyPeers := make([]agentsv1alpha1.TrafficPolicyPeer, 0, len(denyOut))
			for _, entry := range denyOut {
				denyPeers = append(denyPeers, agentsv1alpha1.TrafficPolicyPeer{CIDR: normalizeToCIDR(entry)})
			}
			rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
				Action: agentsv1alpha1.RuleActionReject,
				To:     denyPeers,
			})
		}
		if !containsAllTrafficCIDR(allowOutCIDRs) {
			rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
				Action: agentsv1alpha1.RuleActionReject,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: defaultDenyCIDR}},
			})
		}
	} else {
		// Blacklist mode: reject denyOut entries only
		denyPeers := make([]agentsv1alpha1.TrafficPolicyPeer, 0, len(denyOut))
		for _, entry := range denyOut {
			denyPeers = append(denyPeers, agentsv1alpha1.TrafficPolicyPeer{CIDR: normalizeToCIDR(entry)})
		}
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionReject,
			To:     denyPeers,
		})
	}

	return &agentsv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName:    "tp-",
			Namespace:       namespace,
			Labels:          map[string]string{labelSandboxID: sandboxID},
			OwnerReferences: []metav1.OwnerReference{sandboxOwnerRef(owner)},
		},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 1000,
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					labelSandboxID: sandboxID,
				},
			},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: rules,
			},
		},
	}
}

// CreateSandboxNetwork creates a TrafficPolicy CR for the sandbox.
func (s *Sandbox) CreateSandboxNetwork(ctx context.Context, network infra.SandboxNetworkConfig) error {
	if len(network.AllowOut) == 0 && len(network.DenyOut) == 0 {
		return nil
	}
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	k8sClient := s.Cache.GetClient()
	sandboxID := s.GetSandboxID()
	namespace := s.GetNamespace()

	allowCIDRs, allowDomains := splitAllowOut(network.AllowOut)

	tp := buildTrafficPolicy(allowCIDRs, allowDomains, network.DenyOut, namespace, sandboxID, s.Sandbox)
	if tp != nil {
		if err := k8sClient.Create(ctx, tp); err != nil {
			log.Error(err, "failed to create TrafficPolicy for sandbox")
			return fmt.Errorf("failed to create TrafficPolicy: %w", err)
		}
		log.Info("TrafficPolicy created", "name", tp.Name)
	}

	return nil
}

// UpdateSandboxNetwork updates the TrafficPolicy CR for the sandbox.
func (s *Sandbox) UpdateSandboxNetwork(ctx context.Context, network infra.SandboxNetworkConfig) error {
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	k8sClient := s.Cache.GetClient()
	sandboxID := s.GetSandboxID()
	namespace := s.GetNamespace()

	allowCIDRs, allowDomains := splitAllowOut(network.AllowOut)

	// --- Reconcile TrafficPolicy ---
	tpList := &agentsv1alpha1.TrafficPolicyList{}
	if err := k8sClient.List(ctx, tpList,
		client.InNamespace(namespace),
		client.MatchingLabels{labelSandboxID: sandboxID},
	); err != nil {
		return fmt.Errorf("failed to list TrafficPolicies: %w", err)
	}

	newTP := buildTrafficPolicy(allowCIDRs, allowDomains, network.DenyOut, namespace, sandboxID, s.Sandbox)

	if newTP == nil {
		// No network rules needed, delete existing CRs
		for i := range tpList.Items {
			tp := &tpList.Items[i]
			if err := client.IgnoreNotFound(k8sClient.Delete(ctx, tp)); err != nil {
				log.Error(err, "failed to delete TrafficPolicy", "name", tp.Name)
			} else {
				log.Info("TrafficPolicy deleted", "name", tp.Name)
			}
		}
	} else if len(tpList.Items) > 0 {
		// Update existing TrafficPolicy with new spec and ensure OwnerReference is set
		existing := &tpList.Items[0]
		existing.Spec = newTP.Spec
		existing.OwnerReferences = newTP.OwnerReferences
		if err := k8sClient.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update TrafficPolicy %s: %w", existing.Name, err)
		}
		log.Info("TrafficPolicy updated", "name", existing.Name)
		// Delete any extra TrafficPolicies (shouldn't happen, but clean up)
		for i := 1; i < len(tpList.Items); i++ {
			tp := &tpList.Items[i]
			if err := client.IgnoreNotFound(k8sClient.Delete(ctx, tp)); err != nil {
				log.Error(err, "failed to delete extra TrafficPolicy", "name", tp.Name)
			}
		}
	} else {
		// No existing TrafficPolicy, create new one
		if err := k8sClient.Create(ctx, newTP); err != nil {
			return fmt.Errorf("failed to create TrafficPolicy: %w", err)
		}
		log.Info("TrafficPolicy created", "name", newTP.Name)
	}

	log.Info("network CRs reconciled")
	return nil
}

// SelectSandboxNetwork queries the existing TrafficPolicy CR and returns the
// effective network configuration. Both CIDR and FQDN entries are read back
// from the single TrafficPolicy CR.
func (s *Sandbox) SelectSandboxNetwork(ctx context.Context) (*infra.SandboxNetworkConfig, error) {
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	k8sClient := s.Cache.GetClient()
	sandboxID := s.GetSandboxID()
	namespace := s.GetNamespace()

	config := &infra.SandboxNetworkConfig{}

	// Read TrafficPolicy to extract allowOut (CIDRs + FQDNs) and denyOut (CIDRs)
	tpList := &agentsv1alpha1.TrafficPolicyList{}
	if err := k8sClient.List(ctx, tpList,
		client.InNamespace(namespace),
		client.MatchingLabels{labelSandboxID: sandboxID},
	); err != nil {
		return nil, fmt.Errorf("failed to list TrafficPolicies: %w", err)
	}
	if len(tpList.Items) > 0 {
		tp := &tpList.Items[0]
		if tp.Spec.Egress != nil {
			for _, rule := range tp.Spec.Egress.Rules {
				switch rule.Action {
				case agentsv1alpha1.RuleActionAllow:
					for _, peer := range rule.To {
						if peer.CIDR != "" {
							config.AllowOut = append(config.AllowOut, peer.CIDR)
						}
						if peer.FQDN != "" {
							config.AllowOut = append(config.AllowOut, peer.FQDN)
						}
					}
				case agentsv1alpha1.RuleActionReject:
					for _, peer := range rule.To {
						if peer.CIDR == defaultDenyCIDR && len(rule.To) == 1 {
							continue
						}
						if peer.CIDR != "" {
							config.DenyOut = append(config.DenyOut, peer.CIDR)
						}
					}
				}
			}
		}
	}

	if len(config.AllowOut) == 0 && len(config.DenyOut) == 0 {
		log.Info("no network CRs found for sandbox")
		return nil, nil
	}

	return config, nil
}

// DeleteSandboxNetwork deletes the TrafficPolicy CR associated with the sandbox.
func (s *Sandbox) DeleteSandboxNetwork(ctx context.Context) error {
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	k8sClient := s.Cache.GetClient()
	sandboxID := s.GetSandboxID()
	namespace := s.GetNamespace()

	// Delete TrafficPolicies
	tpList := &agentsv1alpha1.TrafficPolicyList{}
	if err := k8sClient.List(ctx, tpList,
		client.InNamespace(namespace),
		client.MatchingLabels{labelSandboxID: sandboxID},
	); err != nil {
		log.Error(err, "failed to list TrafficPolicies for cleanup")
	} else {
		for i := range tpList.Items {
			tp := &tpList.Items[i]
			if err := client.IgnoreNotFound(k8sClient.Delete(ctx, tp)); err != nil {
				log.Error(err, "failed to delete TrafficPolicy", "name", tp.Name)
			} else {
				log.Info("TrafficPolicy deleted during cleanup", "name", tp.Name)
			}
		}
	}

	return nil
}
