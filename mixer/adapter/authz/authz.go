//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/authz/config/config.proto

// RBAC adapter that proxies requests to authz service

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gogo/googleapis/google/rpc"
	"istio.io/istio/mixer/adapter/authz/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/authorization"
)

type (
	builder struct {
		adapterConfig *config.Params
	}
	handler struct {
		httpClient    *http.Client
		env           adapter.Env
		cacheDuration time.Duration
		serviceURL    string
	}
)

var (
	errUnauthenticated = fmt.Errorf("Unauthenticated")
)

///////////////// Configuration-time Methods ///////////////

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adapterConfig = cfg.(*config.Params)
}

func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	// ac := b.adapterConfig

	// // check if service url is correct
	// if _, err := url.Parse(ac.ServiceUrl); err != nil {
	// 	ce = ce.Append("configServiceUrl", err)
	// }

	return nil
}

func (b *builder) SetAuthorizationTypes(types map[string]*authorization.Type) {}

func (b *builder) Build(ctx context.Context, env adapter.Env) (adapter.Handler, error) {
	env.Logger().Infof("Building authz adapter...")
	h := &handler{
		httpClient:    http.DefaultClient,
		env:           env,
		cacheDuration: b.adapterConfig.CacheDuration,
		serviceURL:    b.adapterConfig.ServiceUrl,
	}
	return h, nil
}

////////////////// Request-time Methods //////////////////////////
// authorization.Handler#HandleAuthorization
func (h *handler) HandleAuthorization(ctx context.Context, inst *authorization.Instance) (adapter.CheckResult, error) {
	logger := h.env.Logger()
	logger.Infof("XXXX authz adapter HandleAuthorization")
	s := status.OK
	result, err := h.checkPermission(inst)
	if !result || err != nil {
		if err == errUnauthenticated {
			s = rpc.Status{Code: int32(rpc.UNAUTHENTICATED), Message: err.Error()}
		} else {
			s = status.WithPermissionDenied("RBAC: permission denied.")
		}
	}
	return adapter.CheckResult{
		Status:        s,
		ValidDuration: h.cacheDuration,
		ValidUseCount: 1000000000,
	}, nil
}

// adapter.Handler#Close
func (h *handler) Close() error {
	logger := h.env.Logger()
	logger.Infof("XXXX authz adapter close")
	return nil
}

// TODO move to an interface
// CheckPermission checks permission against authz-service
func (h *handler) checkPermission(inst *authorization.Instance) (bool, error) {
	logger := h.env.Logger()
	logger.Infof("XXXX check Permission of authz adapter")
	// namespace := inst.Action.Namespace

	// if namespace == "" {
	// 	return false, logger.Errorf("Missing namespace")
	// }

	serviceName := inst.Action.Service
	logger.Infof("serviceName: " + serviceName)
	if serviceName == "" {
		return false, logger.Errorf("Missing service")
	}

	path := inst.Action.Path
	logger.Infof("path: " + path)
	if path == "" {
		return false, logger.Errorf("Missing path")
	}

	method := inst.Action.Method
	logger.Infof("method: " + method)
	if method == "" {
		return false, logger.Errorf("Missing method")
	}

	// Bypass CORS pre-flight request and health check request
	if method == "OPTIONS" || strings.Contains(path, "/health") {
		return true, nil
	}

	properties := inst.Action.Properties
	tokenString := properties["token"].(string)

	token := strings.TrimSpace(strings.TrimPrefix(tokenString, "Bearer"))

	if len(token) != 0 {
		logger.Infof("Check against authz-service")
		// remove unused parts from service name
		parts := strings.Split(serviceName, ".")
		// my-svc.my-namespace.svc.cluster.local -> my-svc.my-namespace
		resourceURL := fmt.Sprintf("http://%s.%s%s", parts[0], parts[1], path)
		// validates against authz-service

		buf := new(bytes.Buffer)

		payload := &struct {
			Token       string `json:"token"`
			Method      string `json:"method"`
			ResourceURL string `json:"resource_url"`
		}{
			Token:       token,
			Method:      method,
			ResourceURL: resourceURL,
		}

		err := json.NewEncoder(buf).Encode(payload)
		if err != nil {
			logger.Errorf(err.Error())
			return false, err
		}

		req, err := http.NewRequest("POST", h.serviceURL, buf)
		if err != nil {
			logger.Errorf(err.Error())
			return false, err
		}

		resp, err := h.httpClient.Do(req)
		if err != nil {
			logger.Errorf(err.Error())
			return false, err
		}

		logger.Infof(fmt.Sprintf("Status code: %s", resp.Status))
		logger.Infof(fmt.Sprintf("%+v\n", resp))

		if resp.StatusCode == 401 {
			return false, errUnauthenticated
		}

		return resp.StatusCode == 200, nil
	}
	return false, nil
}

////////////////// Bootstrap //////////////////////////

// GetInfo returns the adapter.Info specific to this adapter.
func GetInfo() adapter.Info {
	fmt.Println("XXXX start get authz adapter info...")
	
	return adapter.Info{
		Name: "authz",
		//Impl:        "istio.io/istio/mixer/adapter/authz",
		Description: "Role Based Access Control for Istio services",
		SupportedTemplates: []string{
			authorization.TemplateName,
		},
		NewBuilder: func() adapter.HandlerBuilder { return &builder{} },
		DefaultConfig: &config.Params{
			ServiceUrl:    "http://authz/authz/v1/authorize",
			CacheDuration: 600 * time.Second,
		},
	}
}
