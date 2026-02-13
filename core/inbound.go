package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type NetworkSettingsProxyProtocol struct {
	AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
}

func (v *V2Core) removeInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *V2Core) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

// BuildInbound build Inbound config for different protocol
func buildInbound(nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	switch nodeInfo.Type {
	case "vless":
		err = buildVLess(nodeInfo, in)
	case "vmess":
		err = buildVMess(nodeInfo, in)
	case "trojan":
		err = buildTrojan(nodeInfo, in)
	case "shadowsocks":
		err = buildShadowsocks(nodeInfo, in)
	case "hysteria2":
		err = buildHysteria2(nodeInfo, in)
	case "tuic":
		err = buildTuic(nodeInfo, in)
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	if len(nodeInfo.Common.NetworkSettings) > 0 {
		n := &NetworkSettingsProxyProtocol{}
		err := json.Unmarshal(nodeInfo.Common.NetworkSettings, n)
		if err != nil {
			return nil, fmt.Errorf("unmarshal network settings error: %s", err)
		}
		if n.AcceptProxyProtocol {
			if in.StreamSetting == nil {
				t := coreConf.TransportProtocol(nodeInfo.Common.Network)
				in.StreamSetting = &coreConf.StreamConfig{
					Network: &t,
					SocketSettings: &coreConf.SocketConfig{
						AcceptProxyProtocol: n.AcceptProxyProtocol,
					},
				}
			} else {
				in.StreamSetting.SocketSettings = &coreConf.SocketConfig{
					AcceptProxyProtocol: n.AcceptProxyProtocol,
				}
			}
		}
	}
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Common.ServerPort),
				To:   uint32(nodeInfo.Common.ServerPort),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(nodeInfo.Common.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &coreConf.StringList{"http", "tls", "quic"},
	}
	in.SniffingConfig = sniffingConfig

	// Set TLS or Reality settings
	switch nodeInfo.Security {
	case panel.Tls:
		if nodeInfo.Common.CertInfo == nil {
			return nil, errors.New("the CertInfo is not vail")
		}
		switch nodeInfo.Common.CertInfo.CertMode {
		case "none", "":
			break
		default:
			if in.StreamSetting == nil {
				in.StreamSetting = &coreConf.StreamConfig{}
			}
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     nodeInfo.Common.CertInfo.CertFile,
						KeyFile:      nodeInfo.Common.CertInfo.KeyFile,
						OcspStapling: 3600,
					},
				},
				RejectUnknownSNI: nodeInfo.Common.CertInfo.RejectUnknownSni,
			}
		}
	case panel.Reality:
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Common
		dest := v.TlsSettings.Dest
		if dest == "" {
			dest = v.TlsSettings.ServerName
		}
		xver := v.TlsSettings.Xver
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%s",
			dest,
			v.TlsSettings.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:        d,
			Xver:        xver,
			Show:        false,
			ServerNames: []string{v.TlsSettings.ServerName},
			PrivateKey:  v.TlsSettings.PrivateKey,
			ShortIds:    []string{v.TlsSettings.ShortId},
			Mldsa65Seed: v.TlsSettings.Mldsa65Seed,
		}
	default:
		break
	}
	in.Tag = tag
	return in.Build()
}

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	inbound.Protocol = "vless"
	var err error
	decryption := "none"
	if nodeInfo.Common.Encryption != "" {
		switch nodeInfo.Common.Encryption {
		case "mlkem768x25519plus":
			encSettings := nodeInfo.Common.EncryptionSettings
			parts := []string{
				"mlkem768x25519plus",
				encSettings.Mode,
				encSettings.Ticket,
			}
			if encSettings.ServerPadding != "" {
				parts = append(parts, encSettings.ServerPadding)
			}
			parts = append(parts, encSettings.PrivateKey)
			decryption = strings.Join(parts, ".")
		default:
			return fmt.Errorf("vless decryption method %s is not support", nodeInfo.Common.Encryption)
		}
	}
	inboundConfig := &coreConf.VLessInboundConfig{
		Decryption: decryption,
	}
	if len(v.NetworkSettings) > 0 {
		type fallbackJSON struct {
			Name string          `json:"name"`
			Alpn string          `json:"alpn"`
			Path string          `json:"path"`
			Type string          `json:"type"`
			Dest json.RawMessage `json:"dest"`
			Xver json.RawMessage `json:"xver"`
		}
		var ns struct {
			Fallbacks []fallbackJSON `json:"fallbacks"`
		}
		if err := json.Unmarshal(v.NetworkSettings, &ns); err != nil {
			return fmt.Errorf("unmarshal vless fallback settings error: %s", err)
		}
		if len(ns.Fallbacks) > 0 {
			fallbacks := make([]*coreConf.VLessInboundFallback, 0, len(ns.Fallbacks))
			for _, fb := range ns.Fallbacks {
				var xver uint64
				if len(fb.Xver) != 0 && string(fb.Xver) != "null" {
					if err := json.Unmarshal(fb.Xver, &xver); err != nil {
						var xverStr string
						if err := json.Unmarshal(fb.Xver, &xverStr); err != nil {
							return fmt.Errorf("unmarshal vless fallback xver error: %s", err)
						}
						parsed, err := strconv.ParseUint(strings.TrimSpace(xverStr), 10, 64)
						if err != nil {
							return fmt.Errorf("parse vless fallback xver error: %s", err)
						}
						xver = parsed
					}
				}
				fallbacks = append(fallbacks, &coreConf.VLessInboundFallback{
					Name: fb.Name,
					Alpn: fb.Alpn,
					Path: fb.Path,
					Type: fb.Type,
					Dest: fb.Dest,
					Xver: xver,
				})
			}
			inboundConfig.Fallbacks = fallbacks
		}
	}
	s, err := json.Marshal(inboundConfig)
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildVMess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	v := nodeInfo.Common
	// Set vmess
	inbound.Protocol = "vmess"
	var err error
	s, err := json.Marshal(&coreConf.VMessInboundConfig{})
	if err != nil {
		return fmt.Errorf("marshal vmess settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Common
	s, err := json.Marshal(&coreConf.TrojanServerConfig{})
	if err != nil {
		return fmt.Errorf("marshal trojan settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) == 0 {
		return nil
	}
	switch network {
	case "tcp":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

type ShadowsocksHTTPNetworkSettings struct {
	AcceptProxyProtocol bool   `json:"acceptProxyProtocol"`
	Path                string `json:"path"`
	Host                string `json:"Host"`
}

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Common
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	// Default: support both tcp and udp
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	settings.IVCheck = true
	// Only set StreamSetting when NetworkSettings is configured
	if len(s.NetworkSettings) != 0 {
		shttp := &ShadowsocksHTTPNetworkSettings{}
		err := json.Unmarshal(s.NetworkSettings, shttp)
		if err != nil {
			return fmt.Errorf("unmarshal shadowsocks settings error: %s", err)
		}
		// HTTP obfuscation requires TCP only (PROXY protocol can work with UDP)
		if shttp.Path != "" || shttp.Host != "" {
			// Restrict protocol-level network list to TCP only for HTTP obfuscation
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}

		// Set StreamSetting for TCP features (PROXY protocol and/or HTTP obfuscation)
		if shttp.AcceptProxyProtocol || shttp.Path != "" || shttp.Host != "" {
			t := coreConf.TransportProtocol("tcp")
			inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
			inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
			inbound.StreamSetting.TCPSettings.AcceptProxyProtocol = shttp.AcceptProxyProtocol
			// Set HTTP header settings if path or host is configured
			if shttp.Path != "" || shttp.Host != "" {
				httpHeader := map[string]interface{}{
					"type":    "http",
					"request": map[string]interface{}{},
				}
				request := httpHeader["request"].(map[string]interface{})
				// Use "/" as default path if not specified
				path := shttp.Path
				if path == "" {
					path = "/"
				}
				request["path"] = []string{path}
				if shttp.Host != "" {
					request["headers"] = map[string]interface{}{
						"Host": []string{shttp.Host},
					}
				}
				headerJSON, err := json.Marshal(httpHeader)
				if err == nil {
					inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
				}
			}
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria2"
	s := nodeInfo.Common
	settings := &coreConf.Hysteria2ServerConfig{
		UpMbps:                uint64(s.UpMbps),
		DownMbps:              uint64(s.DownMbps),
		IgnoreClientBandwidth: s.Ignore_Client_Bandwidth,
		Obfs: &coreConf.Hysteria2ObfsConfig{
			Type:     s.Obfs,
			Password: s.ObfsPassword,
		},
	}

	t := coreConf.TransportProtocol("hysteria2")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	s := nodeInfo.Common
	settings := &coreConf.TuicServerConfig{
		CongestionControl: s.CongestionControl,
		ZeroRttHandshake:  s.ZeroRTTHandshake,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	v := nodeInfo.Common
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: v.PaddingScheme,
	}
	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	if len(v.NetworkSettings) != 0 {
		switch v.Network {
		case "tcp":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.TCPSettings)
			if err != nil {
				return fmt.Errorf("unmarshal tcp settings error: %s", err)
			}
		case "ws":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.WSSettings)
			if err != nil {
				return fmt.Errorf("unmarshal ws settings error: %s", err)
			}
		case "grpc":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.GRPCSettings)
			if err != nil {
				return fmt.Errorf("unmarshal grpc settings error: %s", err)
			}
		case "httpupgrade":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.HTTPUPGRADESettings)
			if err != nil {
				return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
			}
		case "splithttp", "xhttp":
			err := json.Unmarshal(v.NetworkSettings, &inbound.StreamSetting.SplitHTTPSettings)
			if err != nil {
				return fmt.Errorf("unmarshal xhttp settings error: %s", err)
			}
		default:
			return errors.New("the network type is not vail")
		}
	}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	return nil
}
