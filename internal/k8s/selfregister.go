// Copyright (c) 2022 Doc.ai and/or its affiliates.
//
// Copyright (c) 2022 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package k8s contains k8s specific services for cmd-admission-webhook-k8s
package k8s

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	admissionregistrationv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/client-go/rest"

	"github.com/networkservicemesh/cmd-admission-webhook/internal/config"
)

// AdmissionWebhookRegisterClient is a simple client that can register and unregister MutatingWebhookConfiguration based on config.Config
type AdmissionWebhookRegisterClient struct {
	Logger *zap.SugaredLogger
	once   sync.Once
	client admissionregistrationv1.AdmissionregistrationV1Interface
}

func (a *AdmissionWebhookRegisterClient) initializeClient() {
	c, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(c)
	if err != nil {
		panic(err.Error())
	}
	a.client = clientset.AdmissionregistrationV1()
}

// Register registers MutatingWebhookConfiguration based on passed config.Config
func (a *AdmissionWebhookRegisterClient) Register(ctx context.Context, c *config.Config) error {
	a.once.Do(a.initializeClient)
	a.Logger.Infof("Starting to register MutatingWebhookConfiguration based config: %#v", c)
	defer a.Logger.Infof("Register for config %#v is done", c)

	// When node is restarted, all apps started in pods with old names.
	// Then we already have configuration with the same name but it can't be reused
	// because it contains different certs (certs are regenerated on every program restart)
	_, errExisting := a.client.MutatingWebhookConfigurations().Get(ctx, c.Name, metav1.GetOptions{})
	if errExisting == nil {
		a.Logger.Infof("Found existing MutatingWebhookConfiguration %s, unregistering", c.Name)
		err := a.Unregister(ctx, c)
		if err != nil {
			return err
		}
	} else if !apierrors.IsNotFound(errExisting) {
		a.Logger.Errorf("Failed to search for existing MutatingWebhookConfiguration %s", c.Name)
		return errExisting
	}

	path := "/mutate"
	policy := admissionv1.Fail
	sideEffects := admissionv1.SideEffectClassNone
	webhookConfig := &admissionv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.Name,
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{

				Name: fmt.Sprintf("%v.%v", c.Name, c.Annotation),
				Rules: []admissionv1.RuleWithOperations{
					{
						Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
						Rule: admissionv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods", "namespaces"},
						},
					},
					{
						Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
						Rule: admissionv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
						},
					},
				},
				SideEffects:             &sideEffects,
				AdmissionReviewVersions: []string{"v1"},
				FailurePolicy:           &policy,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{
						Namespace: c.Namespace,
						Name:      c.ServiceName,
						Path:      &path,
					},
					CABundle: c.GetOrResolveCABundle(),
				},
			},
		},
	}

	_, err := a.client.MutatingWebhookConfigurations().Create(ctx, webhookConfig, metav1.CreateOptions{})
	return err
}

// Unregister unregisters MutatingWebhookConfiguration based on passed config.Config
func (a *AdmissionWebhookRegisterClient) Unregister(ctx context.Context, c *config.Config) error {
	a.Logger.Infof("Starting to unregister MutatingWebhookConfiguration based config: %#v", c)
	defer a.Logger.Infof("Unregister for config %#v is done", c)
	a.once.Do(a.initializeClient)
	return a.client.MutatingWebhookConfigurations().Delete(ctx, c.Name, metav1.DeleteOptions{})
}
