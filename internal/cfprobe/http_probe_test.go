package cfprobe

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPProbeMeasuresResponsesAndLoss(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/health/check" || r.URL.Query().Get("value") != "a+b&c" {
			t.Errorf("探测请求不完整: %s %s", r.Method, r.URL.String())
		}
		if calls.Add(1) == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	result := measureProbe(pingModeHTTP, server.URL+"/health/check?value=a%2Bb%26c", 3, 80, newLogger(false))
	if !result.OK || result.RTTMs < 1 || result.Loss != 33 || calls.Load() != 3 {
		t.Fatalf("HTTP 探测结果错误: %+v, 请求数=%d", result, calls.Load())
	}
}

func TestHTTPProbeRejectsErrorResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	result := measureProbe(pingModeHTTP, server.URL, 1, 80, newLogger(false))
	if result.OK || result.RTTMs != -1 || result.Loss != 100 {
		t.Fatalf("HTTP 500 应计为失败: %+v", result)
	}
}

func TestHTTPProbeUsesHTTPForBareHostAndFollowsRedirects(t *testing.T) {
	var arrived atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ready", http.StatusFound)
			return
		}
		arrived.Store(r.URL.Path == "/ready")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	result := measureProbe(pingModeHTTP, strings.TrimPrefix(server.URL, "http://"), 1, 80, newLogger(false))
	if !result.OK || !arrived.Load() {
		t.Fatalf("未完成 HTTP 重定向: %+v", result)
	}
}

func TestHTTPProbeHonorsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	if _, err := httpPing(server.URL, 50*time.Millisecond); err == nil {
		t.Fatal("HTTP 超时应返回错误")
	}
}

func TestHTTPSProbeChecksCertificates(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	if _, err := httpPing(server.URL, time.Second); err == nil {
		t.Fatal("未受信任的 HTTPS 证书不应通过验证")
	}
}

func TestHTTPProbeHistoryDoesNotReuseTCPMeasurements(t *testing.T) {
	if probeHistoryKey(pingModeHTTP, "example.com") == probeHistoryKey(pingModeTCP, "example.com") {
		t.Fatal("HTTP 和 TCP 不应共享历史窗口")
	}
}

func TestHTTPModeInstallFlagAndConfigPersistence(t *testing.T) {
	opts, err := parseInstallOptions([]string{"-ping_mode=http", "-ct=https://example.com/health?value=a+b&next=ready"})
	if err != nil || opts.PingMode != pingModeHTTP {
		t.Fatalf("HTTP 安装参数解析失败: %+v, %v", opts, err)
	}
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writeConfig(path, opts.Config); err != nil {
		t.Fatal(err)
	}
	config, err := readConfig(path)
	if err != nil || config.PingMode != pingModeHTTP || config.CTNode != opts.CTNode {
		t.Fatalf("HTTP 配置未正确保存: %+v, %v", config, err)
	}
}

func TestRemoteHTTPConfigPreservesEncodedURLs(t *testing.T) {
	tmp := t.TempDir()
	config := defaultConfig()
	config.ConnectionMode = connectionModeHTTP
	agent := Agent{cfg: config, paths: Paths{ConfigFile: filepath.Join(tmp, "config.conf"), TrafficFile: filepath.Join(tmp, "traffic.dat")}, log: newLogger(false)}
	target := "https://example.com/health/check?value=a+b&ping_mode=icmp&padding=" + strings.Repeat("x", 180)
	values := url.Values{
		"collect_interval": {"0"}, "report_interval": {"60"}, "reset_day": {"1"},
		"schema_version": {configSchemaVersion}, "connection_mode": {connectionModeHTTP}, "ping_mode": {pingModeHTTP},
	}
	for _, field := range []string{"custom_ct", "custom_cu", "custom_cm", "custom_bd", "node_1", "node_2", "node_3", "node_4"} {
		values.Set(field, target)
	}
	body := []byte(values.Encode())
	if len(body) <= 1024 {
		t.Fatal("测试必须覆盖超过旧上限的配置")
	}
	headers := http.Header{"X-Agent-Config-Md5": {strings.Repeat("a", 32)}}
	if err := agent.applyRemoteConfig(body, headers); err != nil {
		t.Fatal(err)
	}
	got, err := readConfig(agent.paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.PingMode != pingModeHTTP {
		t.Fatalf("网址参数污染了探测模式: %q", got.PingMode)
	}
	for i, node := range []string{got.CTNode, got.CUNode, got.CMNode, got.BDNode, got.Node1, got.Node2, got.Node3, got.Node4} {
		if node != target {
			t.Errorf("节点 %d 的网址发生变化: %q", i, node)
		}
	}
	if err := agent.applyRemoteConfig([]byte(strings.Repeat("x", 16*1024+1)), headers); err == nil {
		t.Fatal("配置长度必须保留上限")
	}
	values.Set("schema_version", "999")
	if err := agent.applyRemoteConfig([]byte(values.Encode()), headers); err == nil {
		t.Fatalf("应拒绝未知协议版本 %s", values.Get("schema_version"))
	}
}
