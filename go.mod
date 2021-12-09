module github.com/networkservicemesh/cmd-admission-webhook

go 1.16

require (
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/labstack/echo/v4 v4.6.1
	github.com/networkservicemesh/sdk v0.5.1-0.20211209141108-0b0a87acf8c7
	go.uber.org/zap v1.16.0
	gomodules.xyz/jsonpatch/v2 v2.1.0
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v0.20.5
)
