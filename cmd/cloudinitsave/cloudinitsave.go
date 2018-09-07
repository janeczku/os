// Copyright 2015 CoreOS, Inc.
// Copyright 2015-2017 Rancher Labs, Inc.
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

package cloudinitsave

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	yaml "github.com/cloudfoundry-incubator/candiedyaml"

	"github.com/rancher/os/cmd/control"
	"github.com/rancher/os/cmd/network"
	rancherConfig "github.com/rancher/os/config"
	"github.com/rancher/os/config/cloudinit/config"
	"github.com/rancher/os/config/cloudinit/datasource"
	"github.com/rancher/os/config/cloudinit/datasource/configdrive"
	"github.com/rancher/os/config/cloudinit/datasource/file"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/aliyun"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/cloudstack"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/digitalocean"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/ec2"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/gce"
	"github.com/rancher/os/config/cloudinit/datasource/metadata/packet"
	"github.com/rancher/os/config/cloudinit/datasource/proccmdline"
	"github.com/rancher/os/config/cloudinit/datasource/url"
	"github.com/rancher/os/config/cloudinit/datasource/vmware"
	"github.com/rancher/os/config/cloudinit/pkg"
	"github.com/rancher/os/log"
	"github.com/rancher/os/netconf"
	"github.com/rancher/os/util"
)

const (
	datasourceInterval    = 100 * time.Millisecond
	datasourceMaxInterval = 30 * time.Second
	datasourceTimeout     = 5 * time.Minute
)

func Main() {
	log.InitLogger()
	log.Info("Running cloud-init-save")

	if err := control.UdevSettle(); err != nil {
		log.Errorf("Failed to run udev settle: %v", err)
	}

	if err := saveCloudConfig(); err != nil {
		log.Errorf("Failed to save cloud-config: %v", err)
	}

	// If an offline datasource or no datasource was used this will be the
	// first time we apply the network config. Otherwise this will update
	// the network with any new configuration from an online datasource.
	cfg := rancherConfig.LoadConfig()
	log.Debugf("Network config (post save-cc): %#v", cfg.Rancher.Network)
	// network.ApplyNetworkConfig(cfg)
}

func saveCloudConfig() error {
	cfg := rancherConfig.LoadConfig()
	log.Debugf("Network config (pre save-cc-offline): %#v", cfg.Rancher.Network)

	if len(cfg.Rancher.CloudInit.Datasources) == 0 {
		log.Info("No datasources configured")
		return nil
	}

	log.Infof("Datasources that will be considered: %#v", cfg.Rancher.CloudInit.Datasources)
	dss := getDatasources(cfg.Rancher.CloudInit.Datasources)
	if len(dss) == 0 {
		return fmt.Errorf("Failed to initialize datasource(s): %#v", cfg.Rancher.CloudInit.Datasources)
	}

	offline, online := containsOfflineOnlineSources(dss)

	if offline {
		log.Debug("Considering offline datasources")
		if foundDs, ok := selectDatasource(dss, false); ok {
			log.Infof("Used offline datasource: %s", foundDs)
			return nil
		}
	}

	if online {
		// Bring up the network
		cfg = rancherConfig.LoadConfig()
		log.Debugf("Network config (pre save-cc-online): %#v", cfg.Rancher.Network)
		network.ApplyNetworkConfig(cfg)

		log.Debug("Considering online datasources")
		if foundDs, ok := selectDatasource(dss, true); ok {
			log.Infof("Used online datasource: %s", foundDs)
			return nil
		}
	}

	return fmt.Errorf("None of the configured datasource available: %#v", cfg.Rancher.CloudInit.Datasources)
}

func saveFiles(cloudConfigBytes, scriptBytes []byte, metadata datasource.Metadata) error {
	os.MkdirAll(rancherConfig.CloudConfigDir, os.ModeDir|0600)

	if len(scriptBytes) > 0 {
		log.Infof("Writing to %s", rancherConfig.CloudConfigScriptFile)
		if err := util.WriteFileAtomic(rancherConfig.CloudConfigScriptFile, scriptBytes, 500); err != nil {
			log.Errorf("Error while writing file %s: %v", rancherConfig.CloudConfigScriptFile, err)
			return err
		}
	}

	if len(cloudConfigBytes) > 0 {
		if err := util.WriteFileAtomic(rancherConfig.CloudConfigBootFile, cloudConfigBytes, 400); err != nil {
			return err
		}
		log.Infof("Wrote to %s", rancherConfig.CloudConfigBootFile)
	}

	metaDataBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return err
	}

	if err = util.WriteFileAtomic(rancherConfig.MetaDataFile, metaDataBytes, 400); err != nil {
		return err
	}
	log.Infof("Wrote to %s", rancherConfig.MetaDataFile)

	// if we write the empty meta yml, the merge fails.
	// TODO: the problem is that a partially filled one will still have merge issues, so that needs fixing - presumably by making merge more clever, and making more fields optional
	emptyMeta, err := yaml.Marshal(datasource.Metadata{})
	if err != nil {
		return err
	}
	if bytes.Compare(metaDataBytes, emptyMeta) == 0 {
		log.Infof("not writing %s: its all defaults.", rancherConfig.CloudConfigNetworkFile)
		return nil
	}

	type nonRancherCfg struct {
		Network netconf.NetworkConfig `yaml:"network,omitempty"`
	}
	type nonCfg struct {
		Rancher nonRancherCfg `yaml:"rancher,omitempty"`
	}
	// write the network.yml file from metadata
	cc := nonCfg{
		Rancher: nonRancherCfg{
			Network: metadata.NetworkConfig,
		},
	}

	if err := os.MkdirAll(path.Dir(rancherConfig.CloudConfigNetworkFile), 0700); err != nil {
		log.Errorf("Failed to create directory for file %s: %v", rancherConfig.CloudConfigNetworkFile, err)
	}

	if err := rancherConfig.WriteToFile(cc, rancherConfig.CloudConfigNetworkFile); err != nil {
		log.Errorf("Failed to save config file %s: %v", rancherConfig.CloudConfigNetworkFile, err)
	}
	log.Infof("Wrote to %s", rancherConfig.CloudConfigNetworkFile)

	return nil
}

func fetchAndSave(ds datasource.Datasource) error {
	var metadata datasource.Metadata

	log.Infof("Fetching user-data from datasource %s", ds)
	userDataBytes, err := ds.FetchUserdata()
	if err != nil {
		log.Errorf("Failed fetching user-data from datasource: %v", err)
		return err
	}
	log.Infof("Fetching meta-data from datasource of type %v", ds.Type())
	metadata, err = ds.FetchMetadata()
	if err != nil {
		log.Errorf("Failed fetching meta-data from datasource: %v", err)
		return err
	}

	userData := string(userDataBytes)
	scriptBytes := []byte{}

	if config.IsScript(userData) {
		scriptBytes = userDataBytes
		userDataBytes = []byte{}
	} else if isCompose(userData) {
		if userDataBytes, err = composeToCloudConfig(userDataBytes); err != nil {
			log.Errorf("Failed to convert compose to cloud-config syntax: %v", err)
			return err
		}
	} else if config.IsCloudConfig(userData) {
		if _, err := rancherConfig.ReadConfig(userDataBytes, false); err != nil {
			log.WithFields(log.Fields{"cloud-config": userData, "err": err}).Warn("Failed to parse cloud-config, not saving.")
			userDataBytes = []byte{}
		}
	} else {
		log.Errorf("Unrecognized user-data\n(%s)", userData)
		userDataBytes = []byte{}
	}

	if _, err := rancherConfig.ReadConfig(userDataBytes, false); err != nil {
		log.WithFields(log.Fields{"cloud-config": userData, "err": err}).Warn("Failed to parse cloud-config")
		return errors.New("Failed to parse cloud-config")
	}

	return saveFiles(userDataBytes, scriptBytes, metadata)
}

// getDatasources creates a slice of possible Datasources for cloudinit based
// on the different source command-line flags.
func getDatasources(datasources []string) []datasource.Datasource {
	dss := make([]datasource.Datasource, 0, 5)

	for _, ds := range datasources {
		parts := strings.SplitN(ds, ":", 2)

		root := ""
		if len(parts) > 1 {
			root = parts[1]
		}

		switch parts[0] {
		case "*":
			dss = append(dss, getDatasources([]string{"configdrive", "vmware", "ec2", "digitalocean", "packet", "gce", "cloudstack"})...)
		case "cloudstack":
			for _, source := range cloudstack.NewDatasource(root) {
				dss = append(dss, source)
			}
		case "ec2":
			dss = append(dss, ec2.NewDatasource(root))
		case "file":
			if root != "" {
				dss = append(dss, file.NewDatasource(root))
			}
		case "url":
			if root != "" {
				dss = append(dss, url.NewDatasource(root))
			}
		case "cmdline":
			if len(parts) == 1 {
				dss = append(dss, proccmdline.NewDatasource())
			}
		case "configdrive":
			if root == "" {
				root = "/media/config-2"
			}
			dss = append(dss, configdrive.NewDatasource(root))
		case "digitalocean":
			// TODO: should we enableDoLinkLocal() - to avoid the need for the other kernel/oem options?
			dss = append(dss, digitalocean.NewDatasource(root))
		case "gce":
			dss = append(dss, gce.NewDatasource(root))
		case "packet":
			dss = append(dss, packet.NewDatasource(root))
		case "vmware":
			// made vmware datasource dependent on detecting vmware independently, as it crashes things otherwise
			v := vmware.NewDatasource(root)
			if v != nil {
				dss = append(dss, v)
			}
		case "aliyun":
			dss = append(dss, aliyun.NewDatasource(root))
		}
	}

	return dss
}

func enableDoLinkLocal() {
	_, err := netconf.ApplyNetworkConfigs(&netconf.NetworkConfig{
		Interfaces: map[string]netconf.InterfaceConfig{
			"eth0": {
				IPV4LL: true,
			},
		},
	}, false, false)
	if err != nil {
		log.Errorf("Failed to apply link local on eth0: %v", err)
	}
}

// selectDatasource attempts to choose a valid Datasource to use based on its
// current availability. The first Datasource to report to be available is
// returned. Datasources will be retried if possible if they are not
// immediately available. If all Datasources are permanently unavailable or
// datasourceTimeout is reached before one becomes available, nil is returned.
func selectDatasource(sources []datasource.Datasource, onlineSource bool) (string, bool) {
	ds := make(chan datasource.Datasource)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for _, s := range sources {
		if s.RequiresNetwork() != onlineSource {
			continue
		}
		wg.Add(1)
		go func(s datasource.Datasource) {
			defer wg.Done()

			duration := datasourceInterval
			for {
				log.Infof("Checking availability of datasource %q", s.Type())
				if s.IsAvailable() {
					log.Infof("Datasource available: %s", s)
					ds <- s
					return
				}
				if !s.AvailabilityChanges() {
					log.Infof("Datasource unavailable, skipping: %s", s)
					return
				}
				log.Errorf("Datasource not ready, will retry: %s", s)
				select {
				case <-stop:
					return
				case <-time.After(duration):
					duration = pkg.ExpBackoff(duration, datasourceMaxInterval)
				}
			}
		}(s)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var s datasource.Datasource
	var name string
	select {
	case s = <-ds:
		name = s.String()
		if err := fetchAndSave(s); err != nil {
			log.Errorf("error fetching cloud-init datasource (%s): %s", s, err)
		}
	case <-done:
	case <-time.After(datasourceTimeout):
	}

	close(stop)
	return name, name != ""
}

func isCompose(content string) bool {
	return strings.HasPrefix(content, "#compose\n")
}

func composeToCloudConfig(bytes []byte) ([]byte, error) {
	compose := make(map[interface{}]interface{})
	err := yaml.Unmarshal(bytes, &compose)
	if err != nil {
		return nil, err
	}

	return yaml.Marshal(map[interface{}]interface{}{
		"rancher": map[interface{}]interface{}{
			"services": compose,
		},
	})
}

func containsOfflineOnlineSources(sources []datasource.Datasource) (offline bool, online bool) {
	for _, s := range sources {
		online = s.RequiresNetwork() == true || online
		offline = s.RequiresNetwork() == false || offline
	}
	return
}
