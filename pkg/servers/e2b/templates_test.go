package e2b

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-manager/clients"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra/sandboxcr"
	"github.com/openkruise/agents/pkg/servers/e2b/keys"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
)

func TestDeleteTemplate(t *testing.T) {
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	tests := []struct {
		name               string
		templateID         string
		setupTemplate      bool                      // whether to create checkpoint + template using CreateCheckpointAndTemplate
		mockDeleteTemplate error                     // mock error for DefaultDeleteSandboxTemplate
		user               *models.CreatedTeamAPIKey // user for the request
		expectStatus       int
		expectError        bool
	}{
		{
			name:          "delete template successfully",
			templateID:    "test-tmpl-delete-success",
			setupTemplate: true,
			user:          user,
			expectStatus:  http.StatusNoContent,
		},
		{
			name:               "delete template with infra error",
			templateID:         "test-tmpl-delete-error",
			setupTemplate:      true,
			mockDeleteTemplate: fmt.Errorf("mock delete template error"),
			user:               user,
			expectStatus:       http.StatusInternalServerError,
			expectError:        true,
		},
		{
			name:          "user is nil returns unauthorized",
			templateID:    "test-tmpl-no-user",
			setupTemplate: false,
			user:          nil,
			expectStatus:  http.StatusUnauthorized,
			expectError:   true,
		},
		{
			name:          "non-owner user returns 204 (idempotent)",
			templateID:    "test-tmpl-non-owner",
			setupTemplate: true,
			user: &models.CreatedTeamAPIKey{
				ID:   uuid.New(),
				Key:  "different-key",
				Name: "different-user",
			},
			expectStatus: http.StatusNoContent,
		},
		{
			name:          "template not found",
			templateID:    "test-tmpl-not-found",
			setupTemplate: false,
			user:          user,
			expectStatus:  http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, _, teardown := Setup(t)
			defer teardown()

			if tt.setupTemplate {
				_ = CreateCheckpointAndTemplate(t, controller, tt.templateID)
				// Set owner annotation on the checkpoint
				cp, err := controller.client.SandboxClient.ApiV1alpha1().Checkpoints(Namespace).Get(t.Context(), tt.templateID, metav1.GetOptions{})
				require.NoError(t, err)
				if cp.Annotations == nil {
					cp.Annotations = map[string]string{}
				}
				cp.Annotations[v1alpha1.AnnotationOwner] = user.ID.String()
				_, err = controller.client.SandboxClient.ApiV1alpha1().Checkpoints(Namespace).Update(t.Context(), cp, metav1.UpdateOptions{})
				require.NoError(t, err)
				time.Sleep(50 * time.Millisecond) // wait for cache sync
			}

			// Set up decorator mock for template deletion
			if tt.mockDeleteTemplate != nil {
				orig := sandboxcr.DefaultDeleteSandboxTemplate
				sandboxcr.DefaultDeleteSandboxTemplate = func(ctx context.Context, c *clients.ClientSet, namespace, name string) error {
					return tt.mockDeleteTemplate
				}
				t.Cleanup(func() { sandboxcr.DefaultDeleteSandboxTemplate = orig })
			}

			req := NewRequest(t, nil, nil, map[string]string{
				"templateID": tt.templateID,
			}, tt.user)

			resp, apiErr := controller.DeleteTemplate(req)

			if tt.expectError {
				require.NotNil(t, apiErr)
				if apiErr.Code == 0 {
					apiErr.Code = http.StatusInternalServerError
				}
				assert.Equal(t, tt.expectStatus, apiErr.Code)
			} else {
				require.Nil(t, apiErr)
				assert.Equal(t, tt.expectStatus, resp.Code)
			}
		})
	}
}

// TestListTemplates tests the ListTemplates method
func TestListTemplates(t *testing.T) {
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	tests := []struct {
		name         string
		setupPools   func(t *testing.T, controller *Controller) []func()
		queryTeamID  string
		user         *models.CreatedTeamAPIKey
		expectStatus int
		expectError  bool
		expectCount  int
		validateFunc func(t *testing.T, templates []*models.TemplateInfo)
	}{
		{
			name: "list templates successfully",
			setupPools: func(t *testing.T, controller *Controller) []func() {
				// Create pools in sandbox-system namespace (systemNamespace) so they can be found by ListTemplates
				cleanup1 := CreateSandboxPoolInNamespace(t, controller, "test-pool-1", 2, "sandbox-system")
				cleanup2 := CreateSandboxPoolInNamespace(t, controller, "test-pool-2", 1, "sandbox-system")
				return []func(){cleanup1, cleanup2}
			},
			queryTeamID:  "",
			user:         user,
			expectStatus: http.StatusOK,
			expectError:  false,
			expectCount:  2,
			validateFunc: func(t *testing.T, templates []*models.TemplateInfo) {
				templateNames := make(map[string]bool)
				for _, tmpl := range templates {
					templateNames[tmpl.TemplateID] = true
					assert.NotEmpty(t, tmpl.TemplateID)
					assert.NotEmpty(t, tmpl.BuildID)
					assert.Equal(t, tmpl.TemplateID, tmpl.BuildID)
					assert.True(t, tmpl.Public)
					assert.NotEmpty(t, tmpl.Aliases)
					assert.NotEmpty(t, tmpl.Names)
					assert.Equal(t, "0.1.1", tmpl.EnvdVersion)
					assert.NotEmpty(t, tmpl.BuildStatus)
				}
				assert.True(t, templateNames["test-pool-1"])
				assert.True(t, templateNames["test-pool-2"])
			},
		},
		{
			name: "list templates with teamID filter",
			setupPools: func(t *testing.T, controller *Controller) []func() {
				cleanup1 := CreateSandboxPoolInNamespace(t, controller, "team-a-pool", 1, "team-a")
				return []func(){cleanup1}
			},
			queryTeamID:  "team-a",
			user:         user,
			expectStatus: http.StatusOK,
			expectError:  false,
			expectCount:  1, // team-a namespace has one pool
			validateFunc: func(t *testing.T, templates []*models.TemplateInfo) {
				assert.Len(t, templates, 1)
				assert.Equal(t, "team-a-pool", templates[0].TemplateID)
			},
		},
		{
			name:         "list templates with no pools",
			setupPools:   func(t *testing.T, controller *Controller) []func() { return nil },
			queryTeamID:  "",
			user:         user,
			expectStatus: http.StatusOK,
			expectError:  false,
			expectCount:  0,
		},
		{
			name:         "user is nil returns error",
			setupPools:   func(t *testing.T, controller *Controller) []func() { return nil },
			queryTeamID:  "",
			user:         nil,
			expectStatus: http.StatusInternalServerError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, _, teardown := Setup(t)
			defer teardown()

			var cleanups []func()
			if tt.setupPools != nil {
				cleanups = tt.setupPools(t, controller)
			}
			for _, cleanup := range cleanups {
				defer cleanup()
			}

			// Create request with query parameters
			req := NewRequest(t, map[string]string{"teamID": tt.queryTeamID}, nil, nil, tt.user)

			resp, apiErr := controller.ListTemplates(req)

			if tt.expectError {
				require.NotNil(t, apiErr)
				assert.Equal(t, tt.expectStatus, apiErr.Code)
			} else {
				require.Nil(t, apiErr)
				assert.Equal(t, tt.expectStatus, resp.Code)
				assert.NotNil(t, resp.Body)
				assert.Equal(t, tt.expectCount, len(resp.Body))
				if tt.validateFunc != nil {
					tt.validateFunc(t, resp.Body)
				}
			}
		})
	}
}

// TestGetTemplate tests the GetTemplate method
func TestGetTemplate(t *testing.T) {
	user := &models.CreatedTeamAPIKey{
		ID:   keys.AdminKeyID,
		Key:  InitKey,
		Name: "admin",
	}

	tests := []struct {
		name         string
		setupPool    func(t *testing.T, controller *Controller) func()
		templateID   string
		user         *models.CreatedTeamAPIKey
		expectStatus int
		expectError  bool
		validateFunc func(t *testing.T, template *models.Template)
	}{
		{
			name: "get template successfully",
			setupPool: func(t *testing.T, controller *Controller) func() {
				// Create pool in sandbox-system namespace (systemNamespace) so it can be found by GetTemplate
				return CreateSandboxPoolInNamespace(t, controller, "test-tmpl-get", 2, "sandbox-system")
			},
			templateID:   "test-tmpl-get",
			user:         user,
			expectStatus: http.StatusOK,
			expectError:  false,
			validateFunc: func(t *testing.T, template *models.Template) {
				assert.Equal(t, "test-tmpl-get", template.TemplateID)
				assert.True(t, template.Public)
				assert.NotEmpty(t, template.Aliases)
				assert.NotEmpty(t, template.Names)
				assert.NotEmpty(t, template.Builds)
				assert.Len(t, template.Builds, 1)

				build := template.Builds[0]
				assert.Equal(t, "test-tmpl-get", build.BuildID)
				assert.Equal(t, "0.1.1", build.EnvdVersion)
				assert.NotEmpty(t, build.Status)
				assert.True(t, build.CPUCount >= 0)
				assert.True(t, build.MemoryMB >= 0)
			},
		},
		{
			name:         "template not found",
			setupPool:    func(t *testing.T, controller *Controller) func() { return nil },
			templateID:   "non-existent-template",
			user:         user,
			expectStatus: http.StatusNotFound,
			expectError:  true,
		},
		{
			name:         "user is nil returns error",
			setupPool:    func(t *testing.T, controller *Controller) func() { return nil },
			templateID:   "test-tmpl",
			user:         nil,
			expectStatus: http.StatusInternalServerError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, _, teardown := Setup(t)
			defer teardown()

			var cleanup func()
			if tt.setupPool != nil {
				cleanup = tt.setupPool(t, controller)
			}
			if cleanup != nil {
				defer cleanup()
			}

			req := NewRequest(t, nil, nil, map[string]string{
				"templateID": tt.templateID,
			}, tt.user)

			resp, apiErr := controller.GetTemplate(req)

			if tt.expectError {
				require.NotNil(t, apiErr)
				assert.Equal(t, tt.expectStatus, apiErr.Code)
			} else {
				require.Nil(t, apiErr)
				assert.Equal(t, tt.expectStatus, resp.Code)
				assert.NotNil(t, resp.Body)
				if tt.validateFunc != nil {
					tt.validateFunc(t, resp.Body)
				}
			}
		})
	}
}

// CreateSandboxPoolInNamespace creates a sandbox pool in a specific namespace
func CreateSandboxPoolInNamespace(t *testing.T, controller *Controller, name string, available int, namespace string) func() {
	tmpl := v1alpha1.EmbeddedSandboxTemplate{
		Template: &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "main",
						Image: "old-image",
					},
				},
			},
		},
	}
	sbs := &v1alpha1.SandboxSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(uuid.NewString()),
		},
		Spec: v1alpha1.SandboxSetSpec{
			EmbeddedSandboxTemplate: tmpl,
		},
	}
	client := controller.client.SandboxClient
	_, err := client.ApiV1alpha1().SandboxSets(namespace).Create(t.Context(), sbs, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool {
		return controller.manager.GetInfra().HasTemplate(name)
	}, time.Second, 10*time.Millisecond)
	now := metav1.Now()
	for i := 0; i < available; i++ {
		sbx := &v1alpha1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%d", name, i),
				Namespace: namespace,
				Labels: map[string]string{
					v1alpha1.LabelSandboxTemplate:  name,
					v1alpha1.LabelSandboxIsClaimed: "false",
				},
				Annotations:       map[string]string{},
				OwnerReferences:   GetSbsOwnerReference(sbs),
				ResourceVersion:   "1",
				UID:               types.UID(uuid.NewString()),
				CreationTimestamp: now,
			},
			Spec: v1alpha1.SandboxSpec{
				EmbeddedSandboxTemplate: tmpl,
			},
			Status: v1alpha1.SandboxStatus{
				Phase: v1alpha1.SandboxRunning,
				Conditions: []metav1.Condition{
					{
						Type:   string(v1alpha1.SandboxConditionReady),
						Status: metav1.ConditionTrue,
					},
					{
						Type:   string(v1alpha1.SandboxConditionPaused),
						Status: metav1.ConditionTrue,
					},
					{
						Type:   string(v1alpha1.SandboxConditionResumed),
						Status: metav1.ConditionTrue,
					},
				},
				PodInfo: v1alpha1.PodInfo{
					PodIP: "1.2.3.4",
				},
			},
		}
		CreateSandboxWithStatus(t, client, sbx)
	}
	require.Eventually(t, func() bool {
		pool, _ := controller.cache.ListSandboxesInPool(name)
		return len(pool) == available && controller.manager.GetInfra().HasTemplate(name)
	}, time.Minute, 100*time.Millisecond)
	return func() {
		for i := 0; i < available; i++ {
			assert.NoError(t, client.ApiV1alpha1().Sandboxes(namespace).Delete(context.Background(), fmt.Sprintf("%s-%d", name, i), metav1.DeleteOptions{}))
		}
		assert.NoError(t, client.ApiV1alpha1().SandboxSets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{}))
	}
}

// TestBuildResource tests the BuildResource function
func TestBuildResource(t *testing.T) {
	cpuQuantity, _ := resource.ParseQuantity("2000m")
	memoryQuantity, _ := resource.ParseQuantity("2048Mi")
	storageQuantity, _ := resource.ParseQuantity("10Gi")

	tests := []struct {
		name           string
		sandboxSet     *v1alpha1.SandboxSet
		expectCPU      int
		expectMemoryMB int
		expectDiskMB   int
	}{
		{
			name: "single container with resources",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: &corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "main",
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    cpuQuantity,
												corev1.ResourceMemory: memoryQuantity,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectCPU:      2,
			expectMemoryMB: 2048,
			expectDiskMB:   0,
		},
		{
			name: "multiple containers with resources",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: &corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "main",
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    cpuQuantity,
												corev1.ResourceMemory: memoryQuantity,
											},
										},
									},
									{
										Name: "sidecar",
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    cpuQuantity,
												corev1.ResourceMemory: memoryQuantity,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectCPU:      4,
			expectMemoryMB: 4096,
			expectDiskMB:   0,
		},
		{
			name: "sandbox set with volume claim templates",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: &corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "main",
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    cpuQuantity,
												corev1.ResourceMemory: memoryQuantity,
											},
										},
									},
								},
							},
						},
						VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
							{
								ObjectMeta: metav1.ObjectMeta{
									Name: "data",
								},
								Spec: corev1.PersistentVolumeClaimSpec{
									AccessModes: []corev1.PersistentVolumeAccessMode{
										corev1.ReadWriteOnce,
									},
									Resources: corev1.VolumeResourceRequirements{
										Requests: corev1.ResourceList{
											corev1.ResourceStorage: storageQuantity,
										},
									},
								},
							},
						},
					},
				},
			},
			expectCPU:      2,
			expectMemoryMB: 2048,
			expectDiskMB:   10240, // 10Gi = 10240Mi
		},
		{
			name: "no resources specified",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: &corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "main",
									},
								},
							},
						},
					},
				},
			},
			expectCPU:      0,
			expectMemoryMB: 0,
			expectDiskMB:   0,
		},
		{
			name: "nil template",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: nil,
					},
				},
			},
			expectCPU:      0,
			expectMemoryMB: 0,
			expectDiskMB:   0,
		},
		{
			name: "multiple volume claim templates",
			sandboxSet: &v1alpha1.SandboxSet{
				Spec: v1alpha1.SandboxSetSpec{
					EmbeddedSandboxTemplate: v1alpha1.EmbeddedSandboxTemplate{
						Template: &corev1.PodTemplateSpec{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "main",
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    cpuQuantity,
												corev1.ResourceMemory: memoryQuantity,
											},
										},
									},
								},
							},
						},
						VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
							{
								ObjectMeta: metav1.ObjectMeta{
									Name: "data",
								},
								Spec: corev1.PersistentVolumeClaimSpec{
									AccessModes: []corev1.PersistentVolumeAccessMode{
										corev1.ReadWriteOnce,
									},
									Resources: corev1.VolumeResourceRequirements{
										Requests: corev1.ResourceList{
											corev1.ResourceStorage: storageQuantity,
										},
									},
								},
							},
							{
								ObjectMeta: metav1.ObjectMeta{
									Name: "logs",
								},
								Spec: corev1.PersistentVolumeClaimSpec{
									AccessModes: []corev1.PersistentVolumeAccessMode{
										corev1.ReadWriteOnce,
									},
									Resources: corev1.VolumeResourceRequirements{
										Requests: corev1.ResourceList{
											corev1.ResourceStorage: storageQuantity,
										},
									},
								},
							},
						},
					},
				},
			},
			expectCPU:      2,
			expectMemoryMB: 2048,
			expectDiskMB:   20480, // 2 * 10Gi = 20480Mi
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu, memory, disk := BuildResource(tt.sandboxSet)
			assert.Equal(t, tt.expectCPU, cpu)
			assert.Equal(t, tt.expectMemoryMB, memory)
			assert.Equal(t, tt.expectDiskMB, disk)
		})
	}
}
