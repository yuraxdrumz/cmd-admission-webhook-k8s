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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"

	"github.com/networkservicemesh/cmd-admission-webhook/internal/config"
	kubeutils "github.com/networkservicemesh/sdk-k8s/pkg/tools/k8s"
	"github.com/networkservicemesh/sdk/pkg/tools/nsurl"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
)

var deserializer = serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

type admissionWebhookServer struct {
	config    *config.Config
	logger    *zap.SugaredLogger
	clientset *kubernetes.Clientset
}

func (s *admissionWebhookServer) Review(ctx context.Context, in *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	var resp = &admissionv1.AdmissionResponse{
		UID: in.UID,
	}

	s.logger.Infof("Incoming request: %+v", in)
	defer s.logger.Infof("Outgoing response: %+v", resp)

	if in.Operation != admissionv1.Create {
		resp.Allowed = true
		return resp
	}
	podMetaPtr, spec := s.unmarshal(in)
	p := ""
	if in.Kind.Kind != "Pod" {
		p = "/spec/template"
	}
	p = path.Join("/", p)

	if spec == nil && podMetaPtr == nil {
		resp.Allowed = true
		return resp
	}
	annotation := podMetaPtr.Annotations[s.config.Annotation]

	if annotation == "" && in.Kind.Kind != "Pod" {
		resp.Allowed = true
		return resp
	}

	// use namespace annotation only if resource doesn't have it's own
	if annotation == "" && in.Kind.Kind == "Pod" {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		namespace, err := s.clientset.CoreV1().Namespaces().Get(timeoutCtx, in.Namespace, v1.GetOptions{})
		if err != nil {
			s.logger.Errorf("failed to get namespace by name", err)
		}
		annotation = namespace.Annotations[s.config.Annotation]
	}

	if annotation != "" {
		bytes, err := json.Marshal([]jsonpatch.JsonPatchOperation{
			s.createInitContainerPatch(p, annotation, spec.InitContainers),
			s.createContainerPatch(p, annotation, spec.Containers),
			s.createVolumesPatch(p, spec.Volumes),
			s.createLabelPatch(p, podMetaPtr.Labels),
		})
		if err != nil {
			resp.Result = &v1.Status{
				Status: err.Error(),
			}
			return resp
		}
		resp.Patch = bytes
		var t = admissionv1.PatchTypeJSONPatch
		resp.PatchType = &t
	}

	resp.Allowed = true
	return resp
}

func (s *admissionWebhookServer) unmarshal(in *admissionv1.AdmissionRequest) (podMetaPtr *v1.ObjectMeta, podSpec *corev1.PodSpec) {
	var target interface{}
	var metaPtr *v1.ObjectMeta
	switch in.Kind.Kind {
	case "Deployment":
		var deployment appsv1.Deployment
		metaPtr = &deployment.ObjectMeta
		podMetaPtr = &deployment.Spec.Template.ObjectMeta
		podSpec = &deployment.Spec.Template.Spec
		target = &deployment
	case "Pod":
		var pod corev1.Pod
		podMetaPtr = &pod.ObjectMeta
		podSpec = &pod.Spec
		target = &pod
	case "DaemonSet":
		var daemonSet appsv1.DaemonSet
		metaPtr = &daemonSet.ObjectMeta
		podMetaPtr = &daemonSet.Spec.Template.ObjectMeta
		podSpec = &daemonSet.Spec.Template.Spec
		target = &daemonSet
	case "StatefulSet":
		var statefulSet appsv1.StatefulSet
		metaPtr = &statefulSet.ObjectMeta
		podMetaPtr = &statefulSet.Spec.Template.ObjectMeta
		podSpec = &statefulSet.Spec.Template.Spec
		target = &statefulSet
	case "ReplicaSet":
		var replicaSet appsv1.ReplicaSet
		metaPtr = &replicaSet.ObjectMeta
		podMetaPtr = &replicaSet.Spec.Template.ObjectMeta
		podSpec = &replicaSet.Spec.Template.Spec
		target = &replicaSet
	default:
		return nil, nil
	}
	if err := json.Unmarshal(in.Object.Raw, target); err != nil {
		return nil, nil
	}
	podMetaPtr = s.postProcessPodMeta(podMetaPtr, metaPtr, in.Kind.Kind)
	if podMetaPtr == nil {
		return nil, nil
	}
	return podMetaPtr, podSpec
}

func (s *admissionWebhookServer) postProcessPodMeta(podMetaPtr, metaPtr *v1.ObjectMeta, kind string) *v1.ObjectMeta {
	if podMetaPtr.Labels == nil {
		podMetaPtr.Labels = make(map[string]string)
	}
	// Annotations shouldn't be applied second time.
	if kind != "Pod" {
		if podMetaPtr.Annotations == nil {
			podMetaPtr.Annotations = metaPtr.Annotations
		} else {
			s.logger.Errorf("Malformed specification. Annotations can't be provided in several places.")
			return nil
		}
	}
	if kind == "ReplicaSet" {
		for _, o := range metaPtr.OwnerReferences {
			if o.Kind == "Deployment" {
				return nil
			}
		}
	}
	return podMetaPtr
}

func (s *admissionWebhookServer) createVolumesPatch(p string, volumes []corev1.Volume) jsonpatch.JsonPatchOperation {
	hostPathDir := corev1.HostPathDirectory
	volumes = append(volumes,
		corev1.Volume{
			Name: "spire-agent-socket",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/run/spire/sockets",
					Type: &hostPathDir,
				},
			},
		},
		corev1.Volume{
			Name: "nsm-socket",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/lib/networkservicemesh",
					Type: &hostPathDir,
				},
			},
		},
	)
	return jsonpatch.NewOperation("add", path.Join(p, "spec", "volumes"), volumes)
}

func parseResources(v string, logger *zap.SugaredLogger) map[string]int {
	var nsmURLs []*nsurl.NSURL
	poolResources := make(map[string]int)

	for _, rawURL := range strings.Split(v, ",") {
		u, err := url.Parse(rawURL)

		if err != nil {
			logger.Errorf("Malformed NS annotation: %+v", rawURL)
			return nil
		}
		nsmURLs = append(nsmURLs, (*nsurl.NSURL)(u))
	}

	for _, nsmURL := range nsmURLs {
		labels := nsmURL.Labels()
		if _, ok := labels["sriovToken"]; ok {
			interfacePools := strings.Split(labels["sriovToken"], ",")
			poolResources[interfacePools[0]]++
		}
	}

	return poolResources
}

func (s *admissionWebhookServer) createInitContainerPatch(p, v string, initContainers []corev1.Container) jsonpatch.JsonPatchOperation {
	poolResources := parseResources(v, s.logger)
	for _, img := range s.config.InitContainerImages {
		initContainers = append(initContainers, corev1.Container{
			Name:            nameOf(img),
			Env:             append(s.config.GetOrResolveEnvs(), corev1.EnvVar{Name: s.config.NSURLEnvName, Value: v}),
			Image:           img,
			ImagePullPolicy: corev1.PullIfNotPresent,
		})
		s.addVolumeMounts(&initContainers[len(initContainers)-1])
		s.addResources(&initContainers[len(initContainers)-1], poolResources)
	}
	return jsonpatch.NewOperation("add", path.Join(p, "spec", "initContainers"), initContainers)
}

func (s *admissionWebhookServer) createContainerPatch(p, v string, containers []corev1.Container) jsonpatch.JsonPatchOperation {
	for _, img := range s.config.ContainerImages {
		containers = append(containers, corev1.Container{
			Name:            nameOf(img),
			Env:             append(s.config.GetOrResolveEnvs(), corev1.EnvVar{Name: s.config.NSURLEnvName, Value: v}),
			Image:           img,
			ImagePullPolicy: corev1.PullIfNotPresent,
		})
		s.addVolumeMounts(&containers[len(containers)-1])
	}
	return jsonpatch.NewOperation("add", path.Join(p, "spec", "containers"), containers)
}

func nameOf(img string) string {
	return strings.Split(path.Base(img), ":")[0]
}

func (s *admissionWebhookServer) addResources(c *corev1.Container, r map[string]int) {
	for key, value := range r {
		if c.Resources.Limits == nil {
			c.Resources.Limits = make(map[corev1.ResourceName]resource.Quantity)
		}
		c.Resources.Limits[corev1.ResourceName(key)] = resource.MustParse(strconv.Itoa(value))
	}
}

func (s *admissionWebhookServer) addVolumeMounts(c *corev1.Container) {
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
		Name:      "spire-agent-socket",
		MountPath: "/run/spire/sockets",
		ReadOnly:  true,
	}, corev1.VolumeMount{
		Name:      "nsm-socket",
		MountPath: "/var/lib/networkservicemesh",
		ReadOnly:  true,
	})
}

func (s *admissionWebhookServer) createLabelPatch(p string, v map[string]string) jsonpatch.JsonPatchOperation {
	for key, value := range s.config.Labels {
		v[key] = value
	}
	return jsonpatch.NewOperation("add", path.Join(p, "metadata", "labels"), v)
}

func main() {
	prod, err := zap.NewProduction()

	if err != nil {
		panic(err.Error())
	}

	var conf = new(config.Config)

	if err = envconfig.Usage("nsm", conf); err != nil {
		prod.Fatal(err.Error())
	}

	if err = envconfig.Process("nsm", conf); err != nil {
		prod.Fatal(err.Error())
	}

	var logger = prod.Sugar()

	logger.Infof("config.Config: %#v", conf)

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt,
		os.Kill,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	if opentelemetry.IsEnabled() { // Configure Open Telemetry
		collectorAddress := conf.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitMetricExporter(ctx, collectorAddress)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, conf.Name)
		defer func() {
			if err = o.Close(); err != nil {
				logger.Error(err.Error())
			}
		}()
	}

	// var registerClient = k8s.AdmissionWebhookRegisterClient{
	// 	Logger: logger.Named("admissionWebhookRegisterClient"),
	// }

	// err = registerClient.Register(ctx, conf)
	// if err != nil {
	// 	prod.Fatal(err.Error())
	// }

	// defer func() {
	// 	_ = registerClient.Unregister(context.Background(), conf)
	// }()

	s := echo.New()
	s.Use(middleware.Logger())
	s.Use(middleware.Recover())
	_, restConfig, err := kubeutils.NewVersionedClient()
	if err != nil {
		logger.Fatal(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	var handler = &admissionWebhookServer{
		config:    conf,
		logger:    logger.Named("admissionWebhookServer"),
		clientset: clientset,
	}

	s.POST("/mutate", func(c echo.Context) error {
		msg, err := ioutil.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		var review = new(admissionv1.AdmissionReview)

		_, _, err = deserializer.Decode(msg, nil, review)
		if err != nil {
			return err
		}

		review.Response = handler.Review(ctx, review.Request)
		response, err := json.Marshal(review)
		if err != nil {
			return err
		}
		_, err = c.Response().Write(response)
		return err
	})
	s.GET("/ready", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	var startServerErr = make(chan error)
	go func() {
		var certs = append([]tls.Certificate(nil), conf.GetOrResolveCertificate())

		var server = &http.Server{
			Addr: ":443",
			// #nosec
			TLSConfig: &tls.Config{
				Certificates: certs,
				MinVersion:   tls.VersionTLS12,
			},
		}
		startServerErr <- s.StartServer(server)
	}()

	select {
	case err := <-startServerErr:
		if ctx.Err() != nil {
			logger.Fatal(err.Error())
		}
	case <-ctx.Done():
		return
	}
}
