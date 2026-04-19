package pod

import (
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/openkruise/agents/pkg/webhook/pod/validating"
	"github.com/openkruise/agents/pkg/webhook/types"
)

func GetHandlerGetters() []types.HandlerGetter {
	return []types.HandlerGetter{
		func(mgr manager.Manager) types.Handler {
			return &validating.PodValidatingHandler{
				Client:  mgr.GetClient(),
				Decoder: admission.NewDecoder(mgr.GetScheme()),
			}
		},
	}
}
