package core

import (
	"encoding/json"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func mergeJSONValues(existing interface{}, incoming interface{}) interface{} {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}
	switch ex := existing.(type) {
	case map[string]interface{}:
		if inc, ok := incoming.(map[string]interface{}); ok {
			return mergeJSONMaps(ex, inc)
		}
	case []interface{}:
		switch inc := incoming.(type) {
		case []interface{}:
			return append(ex, inc...)
		default:
			return append(ex, inc)
		}
	case string:
		if inc, ok := incoming.(string); ok {
			ex = strings.TrimSpace(ex)
			inc = strings.TrimSpace(inc)
			if ex == "" {
				return inc
			}
			if inc == "" {
				return ex
			}
			return ex + "," + inc
		}
	}
	if inc, ok := incoming.([]interface{}); ok {
		return append([]interface{}{existing}, inc...)
	}
	return incoming
}

func mergeJSONMaps(existing map[string]interface{}, incoming map[string]interface{}) map[string]interface{} {
	if existing == nil {
		existing = map[string]interface{}{}
	}
	for k, v := range incoming {
		if cur, ok := existing[k]; ok {
			existing[k] = mergeJSONValues(cur, v)
			continue
		}
		existing[k] = v
	}
	return existing
}

func GetCustomConfig(infos []*panel.NodeInfo) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	//dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
	//outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dns, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dns)

	//route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	for _, info := range infos {
		if len(info.Common.Routes) == 0 {
			continue
		}
		for _, route := range info.Common.Routes {
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					continue
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
					server.FinalQuery = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_user":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"user":        route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_vlessRoute":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"vlessRoute":  strings.Join(route.Match, ","),
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_ip":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_any":
				if route.ActionValue == nil {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
					}).Debug("route_any missing action_value, skipping")
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
						"err":         err,
					}).Warn("route_any outbound unmarshal failed")
					continue
				}
				if len(route.Match) == 0 {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
					}).Debug("route_any match empty, skipping")
					continue
				}
				log.WithFields(log.Fields{
					"inbound_tag": info.Tag,
					"match_lines": len(route.Match),
					"outboundTag": outbound.Tag,
				}).Debug("route_any processing")
				lines := make([]string, 0, len(route.Match))
				for _, line := range route.Match {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					lines = append(lines, line)
				}
				if len(lines) == 0 {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
					}).Debug("route_any match lines empty after trim, skipping")
					continue
				}
				rule := map[string]interface{}{}
				ruleJSON := strings.Join(lines, "\n")
				if strings.HasPrefix(strings.TrimSpace(ruleJSON), "{") {
					err = json.Unmarshal([]byte(ruleJSON), &rule)
					if err != nil {
						log.WithFields(log.Fields{
							"inbound_tag": info.Tag,
							"err":         err,
							"rule_json":   ruleJSON,
						}).Warn("route_any rule json unmarshal failed")
						continue
					}
				} else {
					for _, line := range lines {
						line = strings.TrimSpace(strings.TrimSuffix(line, ","))
						if line == "" {
							continue
						}
						fragment := map[string]interface{}{}
						fragmentJSON := "{\n" + line + "\n}"
						err = json.Unmarshal([]byte(fragmentJSON), &fragment)
						if err != nil {
							log.WithFields(log.Fields{
								"inbound_tag": info.Tag,
								"err":         err,
								"rule_json":   fragmentJSON,
							}).Warn("route_any rule fragment unmarshal failed")
							continue
						}
						rule = mergeJSONMaps(rule, fragment)
					}
				}
				if len(rule) == 0 {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
					}).Debug("route_any rule empty, skipping")
					continue
				}
				rule["inboundTag"] = info.Tag
				hasOutboundTag := false
				if v, ok := rule["outboundTag"]; ok {
					if s, ok := v.(string); ok {
						hasOutboundTag = strings.TrimSpace(s) != ""
					} else {
						hasOutboundTag = true
					}
				}
				hasBalancerTag := false
				if v, ok := rule["balancerTag"]; ok {
					if s, ok := v.(string); ok {
						hasBalancerTag = strings.TrimSpace(s) != ""
					} else {
						hasBalancerTag = true
					}
				}
				if !hasOutboundTag && !hasBalancerTag {
					rule["outboundTag"] = outbound.Tag
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
						"err":         err,
					}).Warn("route_any rule json marshal failed")
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				log.WithFields(log.Fields{
					"inbound_tag": info.Tag,
					"outboundTag": outbound.Tag,
					"rule_json":   string(rawRule),
				}).Debug("route_any appended rule")
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
						"outboundTag": outbound.Tag,
					}).Debug("route_any outbound already exists, skipping build")
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					log.WithFields(log.Fields{
						"inbound_tag": info.Tag,
						"outboundTag": outbound.Tag,
						"err":         err,
					}).Warn("route_any outbound build failed")
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
				log.WithFields(log.Fields{
					"inbound_tag": info.Tag,
					"outboundTag": outbound.Tag,
				}).Debug("route_any outbound appended")
			case "default_out":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			default:
				continue
			}
		}
	}
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}
