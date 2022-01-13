// Copyright (c) 2021-2022 Doc.ai and/or its affiliates.
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

// Package config provides env based config and helper functions for cmd-admission-webhook-k8s
package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Config represents env configuration for cmd-admission-webhook-k8s
type Config struct {
	Name                      string            `default:"admission-webhook-k8s" desc:"Name of current admission webhook instance" split_words:"true"`
	ServiceName               string            `default:"default" desc:"Name of service that related to this admission webhook instance" split_words:"true"`
	Namespace                 string            `default:"default" desc:"Namespace where admission webhook is deployed" split_words:"true"`
	Annotation                string            `default:"networkservicemesh.io" desc:"Name of annotation that means that the resource can be handled by admission-webhook" split_words:"true"`
	Labels                    map[string]string `default:"" desc:"Map of labels and their values that should be appended for each deployment that has Config.Annotation" split_words:"true"`
	NSURLEnvName              string            `default:"NSM_NETWORK_SERVICES" desc:"Name of env that contains NSURL in initContainers/Containers" split_words:"true"`
	InitContainerImages       []string          `desc:"List of init containers that should be appended for each deployment that has Config.Annotation" split_words:"true"`
	ContainerImages           []string          `desc:"List of containers that should be appended for each deployment that has Config.Annotation" split_words:"true"`
	Envs                      []string          `desc:"Additional Envs that should be appended for each Config.ContainerImages and Config.InitContainerImages" split_words:"true"`
	CertFilePath              string            `desc:"Path to certificate" split_words:"true"`
	KeyFilePath               string            `desc:"Path to RSA/Ed25519 related to Config.CertFilePath" split_words:"true"`
	CABundleFilePath          string            `desc:"Path to cabundle file related to Config.CertFilePath" split_words:"true"`
	OpenTelemetryCollectorURL string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector URL"`
	envs                      []corev1.EnvVar
	caBundle                  []byte
	cert                      tls.Certificate
	once                      sync.Once
}

// GetOrResolveEnvs converts on the first call passed Config.Envs into []corev1.EnvVar or returns parsed values.
func (c *Config) GetOrResolveEnvs() []corev1.EnvVar {
	c.once.Do(c.initialize)
	return c.envs
}

// GetOrResolveCertificate tries to create certificate from Config.CertFilePath, Config.KeyFilePath or creates self signed in memory certificate.
func (c *Config) GetOrResolveCertificate() tls.Certificate {
	c.once.Do(c.initialize)
	return c.cert
}

// GetOrResolveCABundle tries to lookup CA bundle from passed Config.CABundleFilePath or returns ca bundle from self signed in memory certificate.
func (c *Config) GetOrResolveCABundle() []byte {
	c.once.Do(c.initialize)
	return c.caBundle
}

func (c *Config) initialize() {
	c.initializeEnvs()
	c.initializeCert()
	c.initializeCABundle()
}

func (c *Config) initializeEnvs() {
	for _, envRaw := range c.Envs {
		kv := strings.Split(envRaw, "=")
		c.envs = append(c.envs, corev1.EnvVar{
			Name:  kv[0],
			Value: kv[1],
		})
	}
	c.envs = append(c.envs,
		corev1.EnvVar{
			Name:  "SPIFFE_ENDPOINT_SOCKET",
			Value: "unix:///run/spire/sockets/agent.sock",
		},
		corev1.EnvVar{
			Name: "NSM_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
	)
}

func (c *Config) initializeCABundle() {
	if len(c.caBundle) != 0 {
		return
	}
	r, err := ioutil.ReadFile(c.CABundleFilePath)
	if err != nil {
		panic(err.Error())
	}
	c.caBundle = r
}

func (c *Config) initializeCert() {
	if c.CertFilePath != "" && c.KeyFilePath != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFilePath, c.KeyFilePath)
		if err != nil {
			panic(err.Error())
		}
		c.cert = cert
	}
	c.cert = c.selfSignedInMemoryCertificeate()
}

func (c *Config) selfSignedInMemoryCertificeate() tls.Certificate {
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("networkservicemesh.%v-ca", c.ServiceName),
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames: []string{
			fmt.Sprintf("%v.%v", c.ServiceName, c.Namespace),
			fmt.Sprintf("%v.%v.svc", c.ServiceName, c.Namespace),
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		panic(err.Error())
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)

	if err != nil {
		panic(err.Error())
	}

	pemCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	result, err := tls.X509KeyPair(pemCert, pemKey)

	if err != nil {
		panic(err.Error())
	}

	c.caBundle = pemCert
	return result
}
