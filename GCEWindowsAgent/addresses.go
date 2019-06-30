//  Copyright 2017 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/GoogleCloudPlatform/guest-logging-go/logger"
)

var (
	addressDisabled   = false
	addressKey        = regKeyBase + `\ForwardedIps`
	interfacesEnabled = false
	oldWSFCAddresses  string
	oldWSFCEnable     bool
	protoID           = 66
)

type addressMgr struct{}

func (a *addressMgr) parseWSFCAddresses() string {
	wsfcAddresses := config.Section("wsfc").Key("addresses").String()
	if wsfcAddresses != "" {
		return wsfcAddresses
	}
	if newMetadata.Instance.Attributes.WSFCAddresses != "" {
		return newMetadata.Instance.Attributes.WSFCAddresses
	}
	if newMetadata.Project.Attributes.WSFCAddresses != "" {
		return newMetadata.Project.Attributes.WSFCAddresses
	}

	return ""
}

func (a *addressMgr) parseWSFCEnable() bool {
	wsfcEnable, err := config.Section("wsfc").Key("enable").Bool()
	if err == nil {
		return wsfcEnable
	}
	if newMetadata.Instance.Attributes.EnableWSFC != nil {
		return *newMetadata.Instance.Attributes.EnableWSFC
	}
	if newMetadata.Project.Attributes.EnableWSFC != nil {
		return *newMetadata.Project.Attributes.EnableWSFC
	}
	return false
}

func getForwardsFromRegistry(mac string) ([]string, error) {
	regFwdIPs, err := readRegMultiString(addressKey, mac)
	if err == errRegNotExist {
		// The old agent stored MAC addresses without the ':',
		// check for those and clean them up.
		oldName := strings.Replace(mac, ":", "", -1)
		regFwdIPs, err = readRegMultiString(addressKey, oldName)
		if err == nil {
			deleteRegKey(addressKey, oldName)
		}
	} else if err != nil {
		return nil, err
	}
	return regFwdIPs, nil
}

func compareIPs(configuredIPs, desiredIPs []string) (toAdd, toRm []string) {
	for _, desiredIP := range desiredIPs {
		if !containsString(desiredIP, configuredIPs) {
			toAdd = append(toAdd, desiredIP)
		}
	}

	for _, configuredIP := range configuredIPs {
		if !containsString(configuredIP, desiredIPs) {
			toRm = append(toRm, configuredIP)
		}
	}
	return toAdd, toRm
}

var badMAC []string

func getInterfaceByMAC(mac string, ifs []net.Interface) (net.Interface, error) {
	hwaddr, err := net.ParseMAC(mac)
	if err != nil {
		return net.Interface{}, err
	}

	for _, iface := range ifs {
		if iface.HardwareAddr.String() == hwaddr.String() {
			return iface, nil
		}
	}
	return net.Interface{}, fmt.Errorf("no interface found with MAC %s", mac)
}

func getRoutes(ifname string) ([]string, error) {
	args := fmt.Sprintf("route list table local type local scope host dev %s proto %d", ifname, protoID)
	out, err := exec.Command("ip", strings.Split(args, " ")...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("error getting routes: %s", ee.Stderr)
		}
		return nil, err
	}
	var res []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimPrefix(line, "local ")
		line = strings.TrimSpace(line)
		if line != "" {
			res = append(res, line)
		}
	}
	return res, nil
}

func addRoute(ip, ifname string) error {
	if strings.Index(ip, "/") == -1 {
		ip = ip + "/32"
	}
	args := fmt.Sprintf("route add to local %s scope host dev %s proto %d", ip, ifname, protoID)
	err := exec.Command("ip", strings.Split(args, " ")...).Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("error adding route: %s", ee.Stderr)
	}
	return err
}

func removeRoute(ip, ifname string) error {
	if strings.Index(ip, "/") == -1 {
		ip = ip + "/32"
	}
	args := fmt.Sprintf("route delete to local %s scope host dev %s proto %d", ip, ifname, protoID)
	err := exec.Command("ip", strings.Split(args, " ")...).Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("error removing route: %s", ee.Stderr)
	}
	return err
}

// Filter out forwarded ips based on WSFC (Windows Failover Cluster Settings).
// If only EnableWSFC is set, all ips in the ForwardedIps and TargetInstanceIps will be ignored.
// If WSFCAddresses is set (with or without EnableWSFC), only ips in the list will be filtered out.
func (a *addressMgr) applyWSFCFilter() {
	wsfcAddresses := a.parseWSFCAddresses()

	var wsfcAddrs []string
	for _, wsfcAddr := range strings.Split(wsfcAddresses, ",") {
		if wsfcAddr == "" {
			continue
		}

		if net.ParseIP(wsfcAddr) == nil {
			logger.Errorf("Address for WSFC is not in valid form %s", wsfcAddr)
			continue
		}

		wsfcAddrs = append(wsfcAddrs, wsfcAddr)
	}

	if len(wsfcAddrs) != 0 {
		interfaces := newMetadata.Instance.NetworkInterfaces
		for idx := range interfaces {
			var filteredForwardedIps []string
			for _, ip := range interfaces[idx].ForwardedIps {
				if !containsString(ip, wsfcAddrs) {
					filteredForwardedIps = append(filteredForwardedIps, ip)
				}
			}
			interfaces[idx].ForwardedIps = filteredForwardedIps

			var filteredTargetInstanceIps []string
			for _, ip := range interfaces[idx].TargetInstanceIps {
				if !containsString(ip, wsfcAddrs) {
					filteredTargetInstanceIps = append(filteredTargetInstanceIps, ip)
				}
			}
			interfaces[idx].TargetInstanceIps = filteredTargetInstanceIps
		}
	} else {
		wsfcEnable := a.parseWSFCEnable()
		if wsfcEnable {
			for idx := range newMetadata.Instance.NetworkInterfaces {
				newMetadata.Instance.NetworkInterfaces[idx].ForwardedIps = nil
				newMetadata.Instance.NetworkInterfaces[idx].TargetInstanceIps = nil
			}
		}
	}
}

func (a *addressMgr) diff() bool {
	wsfcAddresses := a.parseWSFCAddresses()
	wsfcEnable := a.parseWSFCEnable()

	diff := !reflect.DeepEqual(newMetadata.Instance.NetworkInterfaces, oldMetadata.Instance.NetworkInterfaces) ||
		wsfcEnable != oldWSFCEnable || wsfcAddresses != oldWSFCAddresses

	oldWSFCAddresses = wsfcAddresses
	oldWSFCEnable = wsfcEnable
	return diff
}

func (a *addressMgr) timeout() bool {
	select {
	case <-ticker:
		return true
	default:
		return false
	}
}

func (a *addressMgr) disabled() (disabled bool) {
	var err error

	defer func() {
		if disabled != addressDisabled {
			addressDisabled = disabled
			logStatus("address", disabled)
		}
	}()

	disabled, err = strconv.ParseBool(config.Section("addressManager").Key("disable").String())
	if err == nil {
		return disabled
	}
	if newMetadata.Instance.Attributes.DisableAddressManager != nil {
		disabled = *newMetadata.Instance.Attributes.DisableAddressManager
		return disabled
	}
	if newMetadata.Project.Attributes.DisableAddressManager != nil {
		disabled = *newMetadata.Project.Attributes.DisableAddressManager
		return disabled
	}
	disabled, err = config.Section("Daemons").Key("network_daemon").Bool()
	if err == nil {
		return !disabled
	}
	return addressDisabled
}

func (a *addressMgr) set() error {
	if runtime.GOOS == "windows" {
		a.applyWSFCFilter()
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" && !interfacesEnabled {
		if err := enableNetworkInterfaces(interfaces); err != nil {
			return err
		}
		interfacesEnabled = true
	}

	for _, ni := range newMetadata.Instance.NetworkInterfaces {
		iface, err := getInterfaceByMAC(ni.Mac, interfaces)
		if err != nil {
			if !containsString(ni.Mac, badMAC) {
				logger.Errorf("Error getting interface: %s", err)
				badMAC = append(badMAC, ni.Mac)
			}
			continue
		}
		wantIPs := append(ni.ForwardedIps, ni.TargetInstanceIps...)
		if runtime.GOOS != "windows" {
			// IP Aliases are not supported on windows.
			wantIPs = append(wantIPs, ni.IPAliases...)
		}

		var forwardedIPs []string
		if runtime.GOOS == "windows" {
			forwardedIPs, err = getForwardsFromRegistry(ni.Mac)
			if err != nil {
				logger.Errorf("Error getting forwards from registry: %s", err)
				continue
			}
		} else {
			forwardedIPs, err = getRoutes(iface.Name)
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					logger.Errorf("Error getting routes: %s", ee.Stderr)
				} else {
					logger.Errorf("Error getting routes: %v", err)
				}
				continue
			}
		}

		toAdd, toRm := compareIPs(forwardedIPs, wantIPs)

		if len(toAdd) != 0 || len(toRm) != 0 {
			var msg string
			msg = fmt.Sprintf("Changing forwarded IPs for %s from %q to %q by", ni.Mac, forwardedIPs, wantIPs)
			if len(toAdd) != 0 {
				msg += fmt.Sprintf(" adding %q", toAdd)
			}
			if len(toRm) != 0 {
				if len(toAdd) != 0 {
					msg += " and"
				}
				msg += fmt.Sprintf(" removing %q", toRm)
			}
			logger.Infof(msg)
		}

		addrs, err := iface.Addrs()
		if err != nil {
			logger.Errorf("Error getting addresses for interface %s: %s", iface.Name, err)
		}

		var configuredIPs []string
		for _, addr := range addrs {
			configuredIPs = append(configuredIPs, strings.TrimSuffix(addr.String(), "/32"))
		}

		var registryEntries []string
		for _, ip := range toAdd {
			var err error
			if runtime.GOOS == "windows" {
				if containsString(ip, configuredIPs) {
					continue
				}
				err = addAddressWindows(net.ParseIP(ip), net.ParseIP("255.255.255.255"), uint32(iface.Index))
			} else {
				err = addRoute(ip, iface.Name)
			}
			if err == nil {
				registryEntries = append(registryEntries, ip)
			} else {
				logger.Errorf("error adding route: %v", err)
			}
		}

		for _, ip := range toRm {
			var err error
			if runtime.GOOS == "windows" {
				if !containsString(ip, configuredIPs) {
					continue
				}
				err = removeAddressWindows(net.ParseIP(ip), uint32(iface.Index))
			} else {
				err = removeRoute(ip, iface.Name)
			}
			if err != nil {
				logger.Errorf("error removing route: %v", err)
				// Add IPs we fail to remove to registry to maintain accurate record.
				registryEntries = append(registryEntries, ip)
			}
		}

		if runtime.GOOS == "windows" {
			if err := writeRegMultiString(addressKey, ni.Mac, registryEntries); err != nil {
				logger.Errorf("error writing registry: %s", err)
			}
		}
	}

	return nil
}

var osrelease release

func enableNetworkInterfaces(ifaces []net.Interface) error {
	var interfaces []string
	for _, ni := range newMetadata.Instance.NetworkInterfaces {
		iface, err := getInterfaceByMAC(ni.Mac, ifaces)
		if err != nil {
			if !containsString(ni.Mac, badMAC) {
				logger.Errorf("Error getting interface: %s", err)
				badMAC = append(badMAC, ni.Mac)
			}
			continue
		}
		interfaces = append(interfaces, iface.Name)
	}

	if osrelease.os == "rhel" && *osrelease.version.major == 7 {
		for _, iface := range interfaces {
			ifcfg, err := os.Create("/etc/sysconfig/network-scripts/ifcfg-" + iface)
			if err != nil {
				return err
			}
			defer ifcfg.Close()
			// TODO: if it exists, we only amend the file.
			_, err = ifcfg.WriteString("# Added by Google.\nBOOTPROTO=none\nDEFROUTE=no\nIPV6INIT=no\nNM_CONTROLLED=no\nNOZEROCONF=yes\nDEVICE=" + iface)
			if err != nil {
				return err
			}
		}
	}

	if osrelease.os == "sles" {
		if *osrelease.version.major == 11 {
			for _, iface := range interfaces {
				exec.Command("dhcpcd", "-x", iface).Run()
				if err := exec.Command("dhcpcd", iface).Run(); err != nil {
					return err
				}
			}
			return nil
		}
		if *osrelease.version.major == 12 {
			for _, iface := range interfaces {
				ifcfg, err := os.Create("/etc/sysconfig/network/ifcfg-" + iface)
				if err != nil {
					return err
				}
				defer ifcfg.Close()
				_, err = ifcfg.WriteString("# Added by Google.\nSTARTMODE=hotplug\nBOOTPROTO=dhcp\nDHCLIENT_SET_DEFAULT_ROUTE=yes\nDHCLIENT_ROUTE_PRIORITY=10" + iface + "00")
				if err != nil {
					return err
				}
			}
			args := append([]string{"ifup", "--timeout", "1"}, interfaces...)
			return exec.Command("/usr/sbin/wicked", args...).Run()
		}
	}
	exec.Command("dhclient", "-x").Run()
	return exec.Command("dhclient", interfaces...).Run()
}
