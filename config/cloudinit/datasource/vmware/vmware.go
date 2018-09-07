// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vmware

import (
	"fmt"
	"net"
	"strings"

	"github.com/rancher/os/config/cloudinit/config"
	"github.com/rancher/os/config/cloudinit/datasource"
	"github.com/rancher/os/log"
	"github.com/rancher/os/netconf"
)

type readConfigFunction func(key string) (string, error)
type urlDownloadFunction func(url string) ([]byte, error)

type VMWare struct {
	ovfFileName string
	readConfig  readConfigFunction
	urlDownload urlDownloadFunction
	lastError   error
}

type guestInfoParam int

const (
	hostname guestInfoParam = iota
	configData
	configDataEnc
	configUrl
	ifaceName
	ifaceMac
	ifaceDhcp
	ifaceRole
	ifaceAddress
	ifaceRouteGateway
	ifaceRouteDest
	dnsServer
	dnsDomain
)

var staticParams = map[guestInfoParam]string{
	hostname:			"hostname",
	configData:			"cloud-init.config.data",
	configDataEnc:		"cloud-init.data.encoding",
	configUrl:			"cloud-init.config.url",
}

var indexedParams = map[guestInfoParam]string{
	ifaceName:			"interface.%d.name",
	ifaceMac:			"interface.%d.mac",
	ifaceDhcp:			"interface.%d.dhcp",
	ifaceRole:			"interface.%d.role",
	ifaceAddress:		"interface.%d.ip.%d.address",
	ifaceRouteGateway:	"interface.%d.route.%d.gateway",
	ifaceRouteDest:		"interface.%d.route.%d.destination",
	dnsServer:			"dns.server.%d",
	dnsDomain:			"dns.domain.%d",

}

func (v VMWare) RequiresNetwork() bool {
	return false
}

func (v VMWare) Finish() error {
	return nil
}

func (v VMWare) String() string {
	return fmt.Sprintf("%s: %s (lastError: %s)", v.Type(), v.ovfFileName, v.lastError)
}

func (v VMWare) AvailabilityChanges() bool {
	return false
}

func (v VMWare) ConfigRoot() string {
	return "/"
}

func (v VMWare) read(param guestInfoParam, index ...interface{}) (string, error) {
	if key, ok := staticParams[param]; ok {
		return v.readConfig(key)
	}
	if key, ok := indexedParams[param]; ok {
		if len(index) == 0 {
			return "", fmt.Errorf("missing index for key %s", key)
		}
		key = fmt.Sprintf(key, index...)
		return v.readConfig(key)
	}

	return "", fmt.Errorf("invalid parameter")
}

func (v VMWare) FetchMetadata() (metadata datasource.Metadata, err error) {
	metadata.NetworkConfig = netconf.NetworkConfig{}
	metadata.Hostname, _ = v.read(hostname)

	//netconf := map[string]string{}
	//saveConfig := func(key string, args ...interface{}) string {
	//	key = fmt.Sprintf(key, args...)
	//	val, _ := v.readConfig(key)
	//	if val != "" {
	//		netconf[key] = val
	//	}
	//	return val
	//}

	for i := 0; ; i++ {
		val, _ := v.read(dnsServer, i)
		if val == "" {
			break
		}
		metadata.NetworkConfig.DNS.Nameservers = append(metadata.NetworkConfig.DNS.Nameservers, val)
	}

	for i := 0; ; i++ {
		//if domain := saveConfig("dns.domain.%d", i); domain == "" {
		val, _ := v.read(dnsDomain, i)
		if val == "" {
			break
		}
		metadata.NetworkConfig.DNS.Search = append(metadata.NetworkConfig.DNS.Search, val)
	}

	metadata.NetworkConfig.Interfaces = make(map[string]netconf.InterfaceConfig)
	found := true
	for i := 0; found; i++ {
		found = false

		ethName := fmt.Sprintf("eth%d", i)
		netDevice := netconf.InterfaceConfig{
			DHCP:      true,
			Match:     ethName,
			Addresses: []string{},
		}
		//found = (saveConfig("interface.%d.name", i) != "") || found
		if val, _ := v.read(ifaceName, i); val != "" {
			netDevice.Match = val
			found = true
		}
		//found = (saveConfig("interface.%d.mac", i) != "") || found
		if val, _ := v.read(ifaceMac, i); val != "" {
			netDevice.Match = "mac:" + val
			found = true
		}
		//found = (saveConfig("interface.%d.dhcp", i) != "") || found
		if val, _ := v.read(ifaceDhcp, i); val != "" {
			netDevice.DHCP = (strings.ToLower(val) != "no")
			found = true
		}

		role, _ := v.read(ifaceRole, i)
		for a := 0; ; a++ {
			address, _ := v.read(ifaceAddress, i, a)
			if address == "" {
				break
			}
			netDevice.Addresses = append(netDevice.Addresses, address)
			found = true
			netDevice.DHCP = false

			ip, _, err := net.ParseCIDR(address)
			if err != nil {
				log.Error(err)
				//return metadata, err
			}

			switch role {
			case "public":
				if ip.To4() != nil {
					metadata.PublicIPv4 = ip
				} else {
					metadata.PublicIPv6 = ip
				}
			case "private":
				if ip.To4() != nil {
					metadata.PrivateIPv4 = ip
				} else {
					metadata.PrivateIPv6 = ip
				}
			case "":
			default:
				//return metadata, fmt.Errorf("unrecognized role: %q", role)
				log.Error(err)
			}
		}

		for r := 0; ; r++ {
			gateway, _ := v.read(ifaceRouteGateway, i, r)
			// TODO: do we really not do anything but default routing?
			// destination, _ := v.read(ifaceRouteDest, i, r)
			destination := ""

			if gateway == "" && destination == "" {
				break
			} else {
				netDevice.Gateway = gateway
				found = true
			}
		}
		if found {
			metadata.NetworkConfig.Interfaces[ethName] = netDevice
		}
	}

	return
}

func (v VMWare) FetchUserdata() ([]byte, error) {
	encoding, err := v.read(configDataEnc)
	if err != nil {
		return nil, err
	}

	data, err := v.read(configData)
	if err != nil {
		return nil, err
	}

	// Try to fallback to url if no explicit data
	if data == "" {
		url, err := v.read(configUrl)
		if err != nil {
			return nil, err
		}

		if url != "" {
			rawData, err := v.urlDownload(url)
			if err != nil {
				return nil, err
			}
			data = string(rawData)
		}
	}

	if encoding != "" {
		return config.DecodeContent(data, encoding)
	}
	return []byte(data), nil
}

func (v VMWare) Type() string {
	return "VMWare"
}
