package protocol

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type WSOpts struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type RealityOpts struct {
	PublicKey string `yaml:"public-key,omitempty"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type Node struct {
	Type              string            `yaml:"type"`
	Name              string            `yaml:"name"`
	Server            string            `yaml:"server"`
	Port              int               `yaml:"port"`
	UUID              string            `yaml:"uuid"`
	Username          string            `yaml:"username,omitempty"`
	Password          string            `yaml:"password"`
	Method            string            `yaml:"method,omitempty"`
	SNI               string            `yaml:"sni,omitempty"`
	ALPN              []string          `yaml:"alpn"`
	SkipCertVerify    bool              `yaml:"skip-cert-verify,omitempty"`
	DisableSNI        bool              `yaml:"disable-sni,omitempty"`
	ReduceRTT         bool              `yaml:"reduce-rtt,omitempty"`
	CongestionControl string            `yaml:"congestion-control,omitempty"`
	UDPRelayMode      string            `yaml:"udp-relay-mode,omitempty"`
	ClientFingerprint string            `yaml:"client-fingerprint,omitempty"`
	UDP               bool              `yaml:"udp,omitempty"`
	TFO               bool              `yaml:"tfo,omitempty"`
	TLS               bool              `yaml:"tls,omitempty"` // 统一使用 TLS 字段
	Tls               bool              `yaml:"-"`             // 兼容旧版，解析时忽略
	AlterId           int               `yaml:"alterId,omitempty"`
	Cipher            string            `yaml:"cipher,omitempty"`
	Network           string            `yaml:"network,omitempty"`
	Host              string            `yaml:"host,omitempty"`
	WSPath            string            `yaml:"ws-path,omitempty"`
	WSHeaders         map[string]string `yaml:"ws-headers,omitempty"`
	WSOpts            WSOpts            `yaml:"ws-opts,omitempty"`
	Flow              string            `yaml:"flow,omitempty"`
	ServerName        string            `yaml:"servername,omitempty"` // VLESS 专用 SNI 别名
	RealityOpts       *RealityOpts      `yaml:"reality-opts,omitempty"`
}

func PreprocessYAML(data string) string {
	// 预处理：万一有连续的 }{ 之间没有分隔符，强行插入 --- 分隔符
	s := strings.ReplaceAll(data, "}\n{", "}\n---\n{")
	s = strings.ReplaceAll(s, "}{", "}\n---\n{")
	return s
}

func ParseNodes(path string) ([]Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := PreprocessYAML(string(data))
	var nodes []Node
	decoder := yaml.NewDecoder(strings.NewReader(content))

	for {
		var node Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			// 这里不直接 return error，防止文件中混杂了无用的文本导致整个解析中断
			// 记录一下日志然后跳过当前块即可
			continue
		}

		// 🚀 核心修改：使用 switch 白名单支持多协议扩展
		switch node.Type {
		case "anytls", "trojan", "tuic", "vmess", "ss", "hysteria2", "http", "https", "vless":
			// 如果未来增加了新协议，直接在这个 case 里加名字即可
			nodes = append(nodes, node)
		default:
			// 如果遇到未知协议或者空类型，静默跳过
			if node.Type != "" {
				fmt.Printf("⚠️ 提示: 跳过不支持的协议节点 [%s] %s\n", node.Type, node.Name)
			}
		}
	}
	return nodes, nil
}

func tryGzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func tryBase64Variants(s string) ([]byte, bool) {
	clean := strings.TrimSpace(s)
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	var decoders = []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString, base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if out, err := dec(clean); err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

func LoadInput(input string) ([]byte, error) {
	s := strings.TrimSpace(input)

	// 智能判断：如果是一整行链接且不含 @，则认为是订阅链接去下载
	isSingleLine := !strings.Contains(s, "\n")
	if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) && isSingleLine && !strings.Contains(s, "@") {

		req, err := http.NewRequest("GET", s, nil)
		if err != nil {
			return nil, err
		}
		// ⚠️ 伪装成正常浏览器，防止被机场防火墙拦截导致下载失败
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("订阅下载失败，HTTP 状态码: %d", resp.StatusCode)
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	return []byte(s), nil
}

func NormalizeSubscription(raw []byte) (string, error) {
	b := bytes.TrimSpace(raw)
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	s := string(b)
	if strings.Contains(s, "://") {
		return s, nil
	}
	if dec, err := tryGzip(b); err == nil && len(dec) > 0 {
		s = string(bytes.TrimSpace(dec))
		if strings.Contains(s, "://") {
			return s, nil
		}
		b = dec
	}
	tryList := [][]byte{b}
	decodedOnce := false
	for round := 0; round < 2; round++ {
		var next []byte
		for _, candidate := range tryList {
			if dec, ok := tryBase64Variants(string(candidate)); ok {
				next = dec
				decodedOnce = true
				break
			}
		}
		if len(next) == 0 {
			break
		}
		text := strings.TrimSpace(string(next))
		if strings.Contains(text, "://") {
			return text, nil
		}
		tryList = [][]byte{next}
	}
	if decodedOnce {
		return strings.TrimSpace(string(tryList[0])), nil
	}
	return strings.TrimSpace(string(b)), nil
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int(t)) {
			return strconv.Itoa(int(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
func getPort(v any) (int, error) {
	switch t := v.(type) {
	case string:
		return strconv.Atoi(t)
	case float64:
		return int(t), nil
	case int:
		return t, nil
	default:
		return 0, fmt.Errorf("unsupported port type")
	}
}
