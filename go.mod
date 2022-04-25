module github.com/networkservicemesh/cmd-admission-webhook

go 1.16

require (
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/labstack/echo/v4 v4.6.1
	github.com/networkservicemesh/api v1.3.0-rc.1.0.20220405210054-fbcde048efa5 // indirect
	github.com/networkservicemesh/sdk v0.5.1-0.20220221172049-8ddd0be6e5d1
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20220307211146-efcb8507fb70 // indirect
	golang.org/x/sys v0.0.0-20220307203707-22a9840ba4d7 // indirect
	gomodules.xyz/jsonpatch/v2 v2.1.0
	google.golang.org/genproto v0.0.0-20211129164237-f09f9a12af12 // indirect
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v0.20.5
	k8s.io/klog/v2 v2.40.1 // indirect
)
