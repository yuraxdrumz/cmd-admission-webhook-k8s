module github.com/networkservicemesh/cmd-admission-webhook

go 1.16

require (
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/labstack/echo/v4 v4.6.1
	github.com/networkservicemesh/sdk v0.5.1-0.20220406090028-30f9f434db34
	go.uber.org/zap v1.16.0
	gomodules.xyz/jsonpatch/v2 v2.1.0
	google.golang.org/genproto v0.0.0-20211129164237-f09f9a12af12 // indirect
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v0.20.5
	k8s.io/klog/v2 v2.40.1 // indirect
)
