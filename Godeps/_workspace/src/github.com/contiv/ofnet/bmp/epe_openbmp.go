/***
Copyright 2016 Cisco Systems Inc. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bmp

// This file constructs the epe label stack for Traffic Engineering using the BGP updates received by OpenBMP

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"os"

	log "github.com/Sirupsen/logrus"
)

type t_rib_record struct {
	RouterName          string `json:"RouterName"`
	PeerName            string `json:"PeerName"`
	Prefix              string `json:"Prefix"`
	PrefixLen           int    `json:"PrefixLen"`
	Origin              string `json:"Origin"`
	OriginAS            int    `json:"Origin_AS"`
	MED                 int    `json:"MED"`
	LocalPref           int    `json:"LocalPref"`
	NH                  string `json:"NH"`
	ASPath              string `json:"AS_Path"`
	ASPathCount         int    `json:"ASPath_Count"`
	Communities         string `json:"Communities"`
	ExtCommunities      string `json:"ExtCommunities"`
	ClusterList         string `json:"ClusterList"`
	Aggregator          string `json:"Aggregator"`
	PeerAddress         string `json:"PeerAddress"`
	PeerASN             int    `json:"PeerASN"`
	IsIPv4              int    `json:"isIPv4"`
	IsPeerIPv4          int    `json:"isPeerIPv4"`
	IsPeerVPN           int    `json:"isPeerVPN"`
	LastModified        string `json:"LastModified"`
	FirstAddedTimestamp string `json:"FirstAddedTimestamp"`
	PrefixBin           string `json:"prefix_bin"`
	PathID              int    `json:"path_id"`
	Labels              string `json:"labels"`
	RibHashID           string `json:"rib_hash_id"`
	PathHashID          string `json:"path_hash_id"`
	PeerHashID          string `json:"peer_hash_id"`
	RouterHashID        string `json:"router_hash_id"`
	IsWithdrawn         string `json:"isWithdrawn"`
	PrefixBits          string `json:"prefix_bits"`
}

/*
type tbl_rib struct {
	VRoutes struct {
		Cols        int `json:"cols"`
		Data        []t_rib_record
		Size        int `json:"size"`
		QueryTimeMs int `json:"queryTime_ms"`
		FetchTimeMs int `json:"fetchTime_ms"`
	} `json:"v_routes"`
}
*/

type tbl_lookup struct {
	VAllRoutes struct {
		Cols        int `json:"cols"`
		Data        []t_rib_record
		Size        int `json:"size"`
		QueryTimeMs int `json:"queryTime_ms"`
		FetchTimeMs int `json:"fetchTime_ms"`
	} `json:"v_all_routes"`
}

type t_links_epe_record struct {
	LocalBGPID     string `json:"Local_BGPID"`
	LocalASN       int    `json:"Local_ASN"`
	RemoteBGPID    string `json:"Remote_BGPID"`
	RemoteASN      int    `json:"Remote_ASN"`
	LocalIP        string `json:"Local_IP"`
	RemoteIP       string `json:"Remote_IP"`
	PeerNodeSID    string `json:"Peer_Node_SID"`
	State          string `json:"State"`
	PathAttrHashID string `json:"path_attr_hash_id"`
	PeerHashID     string `json:"peer_hash_id"`
}

type tbl_ls_links_epe struct {
	LsLinksEpe struct {
		Cols        int `json:"cols"`
		Data        []t_links_epe_record
		Size        int `json:"size"`
		QueryTimeMs int `json:"queryTime_ms"`
		FetchTimeMs int `json:"fetchTime_ms"`
	} `json:"ls_links_epe"`
}

type tbl_router struct {
	Routers struct {
		Cols int `json:"cols"`
		Data []struct {
			RouterName     string      `json:"RouterName"`
			RouterIP       string      `json:"RouterIP"`
			RouterAS       interface{} `json:"RouterAS"`
			Description    string      `json:"description"`
			IsConnected    int         `json:"isConnected"`
			IsPassive      int         `json:"isPassive"`
			LastTermCode   int         `json:"LastTermCode"`
			LastTermReason string      `json:"LastTermReason"`
			InitData       string      `json:"InitData"`
			LastModified   string      `json:"LastModified"`
		} `json:"data"`
		Size        int `json:"size"`
		QueryTimeMs int `json:"queryTime_ms"`
		FetchTimeMs int `json:"fetchTime_ms"`
	} `json:"routers"`
}

type link_info struct {
	the_label string
	the_bgpid string
}

// This needs to be sourced from a configuration file
//const bmp_agent = "localhost"

// This needs to be sourced from a configuration file
//const bmp_port = "8001"
//const url_rib = "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/rib"
//const url_links = "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/linkstate/epe"
//const url_routers = "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/routers"

func has_the_sla(ext_commt, target_sla string) bool {

	log.Infof("extcom is  %v , target %s", ext_commt , target_sla)
	sla_info := strings.Split(ext_commt, "rt=0:")

	//log.Debugf("Extended communities  %v", sla_info)
	for idx := range sla_info {

		log.Infof("sla is  %s", sla_info[idx])
		if target_sla == strings.TrimSpace(sla_info[idx]) {

			log.Infof("Found sla %v", sla_info[idx])
			return true
		}
	}

	//log.Errorf("Unable to find the sla")
	return false
}

func find_router_name(router_data tbl_router, router_ip, peer_name string) string {

	found := false
	for idx := 0; idx < router_data.Routers.Size; idx++ {

		if router_data.Routers.Data[idx].RouterIP == router_ip {

			found = true
			return router_data.Routers.Data[idx].RouterName

		}
	}
	if found == false {
		// t2-s1-ge0-0-0-0.tombolo.lab
		re := regexp.MustCompile(`\w+\d+-\w+\d+`)
		router_name := re.FindString(peer_name)
		//log.Debugf("......................Peer Name: %v ................................. Extracted Next Hop Name: %v\n",peer_name, router_name)
		return router_name
	}

	return ""
}

func find_next_hop(lookup_data tbl_lookup, router, sla string, shortest_AS int) (string, int, string) {

	peer_addr := ""
	peer_name := ""

	log.Infof( "find_next_hop sla %v" , sla ) 
	//log.Debugf("                 ROUTER **********%v",router)
	//log.Debugf("                 PATH AS **********%d",shortest_AS)
	for idx := 0; idx < lookup_data.VAllRoutes.Size; idx++ {

		/*
			log.Debugf("------------Row:%d ASP:%d RouterName:%s PeerName:%s PeerAddr:%s ExtCommunities:%s Labels:%s State:%s", idx,
				lookup_data.VAllRoutes.Data[idx].ASPathCount,
				lookup_data.VAllRoutes.Data[idx].RouterName,
				lookup_data.VAllRoutes.Data[idx].PeerName,
				lookup_data.VAllRoutes.Data[idx].PeerAddress,
				lookup_data.VAllRoutes.Data[idx].ExtCommunities,
				lookup_data.VAllRoutes.Data[idx].Labels,
				lookup_data.VAllRoutes.Data[idx].IsWithdrawn)
		*/

		if lookup_data.VAllRoutes.Data[idx].RouterName != router ||
			lookup_data.VAllRoutes.Data[idx].IsWithdrawn != "false" ||
			lookup_data.VAllRoutes.Data[idx].RouterName == lookup_data.VAllRoutes.Data[idx].PeerName {
			continue
		}
		// ****** This is a Hack to reach the tenant VM ***** //
		if lookup_data.VAllRoutes.Data[idx].ASPathCount != 2 {
			if has_the_sla(lookup_data.VAllRoutes.Data[idx].ExtCommunities, sla) == false {
				continue
			}
		}

		//log.Debugf(" Prior : find_next_hop:.......Shortest AS: %d\t\tASP Count:%d\t\tNEXT Hop:%s\n", shortest_AS, lookup_data.VAllRoutes.Data[idx].ASPathCount, peer_addr)
		if shortest_AS == -1 {

			shortest_AS = lookup_data.VAllRoutes.Data[idx].ASPathCount
			peer_addr = lookup_data.VAllRoutes.Data[idx].PeerAddress
			peer_name = lookup_data.VAllRoutes.Data[idx].PeerName
			//log.Debugf(" Inside : find_next_hop:.......shortest AS: %d  count:%d  NEXT HOP:%s\n", shortest_AS, lookup_data.VAllRoutes.Data[idx].ASPathCount, peer_addr)
			continue
		}

		if shortest_AS > lookup_data.VAllRoutes.Data[idx].ASPathCount {
			shortest_AS = lookup_data.VAllRoutes.Data[idx].ASPathCount
			peer_addr = lookup_data.VAllRoutes.Data[idx].PeerAddress
			peer_name = lookup_data.VAllRoutes.Data[idx].PeerName
			//log.Debugf(" Second : find_next_hop:.......shortest AS: %d  count:%d  NEXT HOP:%s\n", shortest_AS, lookup_data.VAllRoutes.Data[idx].ASPathCount, peer_addr)
		}
		if lookup_data.VAllRoutes.Data[idx].ASPathCount == 2 {
			shortest_AS = 0
			break
		}
	}

	log.Infof(" ************: find_next_hop: Shortest AS: %d\t\t\tNEXT HOP:%s\n", shortest_AS, peer_addr)
	return peer_addr, shortest_AS, peer_name

}

func find_epe_label(epe_data tbl_ls_links_epe, peer_addr string) link_info {

	var link link_info
	link.the_label = ""
	link.the_bgpid = ""

	for idx := 0; idx < epe_data.LsLinksEpe.Size; idx++ {

		link_state := epe_data.LsLinksEpe.Data[idx].State
		remote_ip := epe_data.LsLinksEpe.Data[idx].RemoteIP

		if (link_state == "Active") && (remote_ip == peer_addr) {

			/*
				log.Debugf("Row:%d BgpId:%s ASN:%d RemBgpId:%s RemASN:%d LocalIp:%s RemIp:%s PeerNodeSid:%s State:%s", idx,
					epe_data.LsLinksEpe.Data[idx].LocalBGPID,
					epe_data.LsLinksEpe.Data[idx].LocalASN,
					epe_data.LsLinksEpe.Data[idx].RemoteBGPID,
					epe_data.LsLinksEpe.Data[idx].RemoteASN,
					epe_data.LsLinksEpe.Data[idx].LocalIP,
					epe_data.LsLinksEpe.Data[idx].RemoteIP,
					epe_data.LsLinksEpe.Data[idx].PeerNodeSID,
					epe_data.LsLinksEpe.Data[idx].State)
			*/
			peer_node_SID := strings.Split(epe_data.LsLinksEpe.Data[idx].PeerNodeSID, " ")
			if len(peer_node_SID) == 0 {

				log.Errorf("Error: The peer node SID label is empty :%s for remoteIP: %s", peer_node_SID, peer_addr)
				return link

			}

			//log.Debugf("Peer Node SID for epe label: %q",peer_node_SID)
			link.the_label = peer_node_SID[len(peer_node_SID)-1]
			link.the_bgpid = epe_data.LsLinksEpe.Data[idx].RemoteBGPID
			break
		}
	}
	return link
}

func Epe_label_SR(source, target, ver_sla string) (bool, []string) {

	var lookup_data tbl_lookup
	var epe_data tbl_ls_links_epe
	var router_data tbl_router
	var next_hop_name = ""
	var label_stack []string

	bmp_agent := os.Getenv("BMP_HOST")
        log.Infof("BMP host %v",bmp_agent)
         bmp_port := "8001"
        url_rib := "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/rib"
        url_links := "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/linkstate/epe"
        url_routers := "http://" + bmp_agent + ":" + bmp_port + "/db_rest/v1/routers"

	te_sla := map[string]string{
		"high-bandwidth": "3",
		"low-latency":    "2",
		"secure-path":    "4",
	}

	sla := te_sla[ver_sla]
	log.Infof( "Epe_label_SR sla %s" , sla) 
	req, err := http.NewRequest("GET", url_routers, nil)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("openbmp", "CiscoRA")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	dec.Decode(&router_data)

	if router_data.Routers.Size <= 0 {

		log.Errorf("Error: No data returned by query: %s", url_routers)
		return false, label_stack
	}

	req, err = http.NewRequest("GET", url_rib+"/lookup/"+source, nil)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("openbmp", "CiscoRA")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	//log.Debugf("The Status Code is:\n %d\n", resp.StatusCode)
	defer resp.Body.Close()
	dec = json.NewDecoder(resp.Body)
	dec.Decode(&lookup_data)

	if lookup_data.VAllRoutes.Size <= 0 {

		log.Errorf("Error: No data returned by query: %s", url_rib+"/lookup/"+source)
		return false, label_stack
	}
	for idx := 0; idx < lookup_data.VAllRoutes.Size; idx++ {
		log.Debugf("Row:%d Prefix:%s PeerName:%s PeerAddr:%s ExtCommunities:%s Labels:%s ASP:%s", idx,
			lookup_data.VAllRoutes.Data[idx].Prefix,
			lookup_data.VAllRoutes.Data[idx].PeerName,
			lookup_data.VAllRoutes.Data[idx].PeerAddress,
			lookup_data.VAllRoutes.Data[idx].ExtCommunities,
			lookup_data.VAllRoutes.Data[idx].Labels,
			lookup_data.VAllRoutes.Data[idx].ASPath)
		//if lookup_data.VAllRoutes.Data[idx].PeerAddress == "0.0.0.0" {
		next_hop_name = lookup_data.VAllRoutes.Data[idx].RouterName
		log.Infof("..............FIRST Hop Name: %s\n", next_hop_name)
		break
		//}
	}
	req, err = http.NewRequest("GET", url_rib+"/lookup/"+target, nil)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("openbmp", "CiscoRA")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	//log.Debugf("The Status Code is:\n %d\n", resp.StatusCode)
	defer resp.Body.Close()
	dec = json.NewDecoder(resp.Body)
	dec.Decode(&lookup_data)

	//log.Debugf("Lookup for Prefix :%s No of Records:%d ", lookup_data.VAllRoutes.Data[0].Prefix, lookup_data.VAllRoutes.Size)
	if lookup_data.VAllRoutes.Size <= 0 {

		log.Errorf("Error: No data returned by query: %s", url_rib+"/lookup/"+target)
		return false, label_stack
	}
	/*
		for idx := 0; idx < lookup_data.VAllRoutes.Size; idx++ {
			log.Debugf("***Row:%d ASP:%d RouterName:%s PeerName:%s PeerAddr:%s ExtCommunities:%s Labels:%s State:%s", idx,
				lookup_data.VAllRoutes.Data[idx].ASPathCount,
				lookup_data.VAllRoutes.Data[idx].RouterName,
				lookup_data.VAllRoutes.Data[idx].PeerName,
				lookup_data.VAllRoutes.Data[idx].PeerAddress,
				lookup_data.VAllRoutes.Data[idx].ExtCommunities,
				lookup_data.VAllRoutes.Data[idx].Labels,
				lookup_data.VAllRoutes.Data[idx].IsWithdrawn)
		}
	*/

	req, err = http.NewRequest("GET", url_links, nil)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("openbmp", "CiscoRA")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		// handle err
		log.Errorf("%s", err.Error())
		return false, label_stack
	}
	defer resp.Body.Close()
	dec = json.NewDecoder(resp.Body)
	dec.Decode(&epe_data)

	if epe_data.LsLinksEpe.Size <= 0 {

		log.Errorf("Error: No data returned by query: %s", url_links)
		return false, label_stack
	}

	var epe_label, peer_addr, next_hop_ip string
	var link link_info
	path_as := -1
	peer_addr = "INVALID-PEER"
	peer_name := ""
	for peer_addr != "" && path_as != 0 {
		peer_addr, path_as, peer_name = find_next_hop(lookup_data, next_hop_name, sla, path_as)
		if peer_addr == "" && path_as != 0 {
			log.Errorf("Error: Could not locate the next hop for: %s for the given sla ", next_hop_name)
			return false, label_stack
		}

		epe_label = ""
		next_hop_ip = ""
		link = find_epe_label(epe_data, peer_addr)
		epe_label = link.the_label
		next_hop_ip = link.the_bgpid
		if epe_label == "" {
			log.Errorf("Error: Could not find label for next hop: %s ", peer_addr)
			return false, label_stack
		}
		if next_hop_ip == "" {
			log.Errorf("Error: Could not find Remote BGP Id for next hop: %s ", peer_addr)
			return false, label_stack
		}
		label_stack = append(label_stack, epe_label)
		next_hop_name = find_router_name(router_data, next_hop_ip, peer_name)
		log.Infof("               Peer Addr    : %s\t\t\tBGP Id: %s\t\tName: %s\t\tEPE Label: %s\n", peer_addr, next_hop_ip, next_hop_name, epe_label)

	}

	return true, label_stack

}

func Get_epe_label_SR(src_ip, dstn_ip, epe_sla string) []string {
	status, label_stack := Epe_label_SR(src_ip, dstn_ip, epe_sla)
	log.Infof("LABEL STACK: %q\n", label_stack)
	if status == false {
		log.Errorf(" Error : Could not create the label stack to the destination:")
	}
	return label_stack
}

