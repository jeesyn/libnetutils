/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

/* Utilities for managing the dhcpcd DHCP client daemon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cutils/properties.h>
#include <android/log.h>
#define LOCAL_TAG "DHCPUTIL"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOCAL_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOCAL_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, LOCAL_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOCAL_TAG, __VA_ARGS__))

static const char DAEMON_NAME[]        = "dhcpcd";
static const char DAEMON_PROP_NAME[]   = "init.svc.dhcpcd";
static const char HOSTNAME_PROP_NAME[] = "net.hostname";
static const char DHCP_PROP_NAME_PREFIX[]  = "dhcp";
static const char DHCP_CONFIG_PATH[]   = "/system/etc/dhcpcd/dhcpcd.conf";
static const int NAP_TIME = 20;   /* wait for 20ms at a time */
                                  /* when polling for property values */
static const char DAEMON_NAME_RENEW[]  = "iprenew";
static char errmsg[100];
/* interface length for dhcpcd daemon start (dhcpcd_<interface> as defined in init.rc file)
 * or for filling up system properties dhcpcd.<interface>.ipaddress, dhcpcd.<interface>.dns1
 * and other properties on a successful bind
 */
#define MAX_INTERFACE_LENGTH 25

/*
 * P2p interface names increase sequentially p2p-p2p0-1, p2p-p2p0-2.. after
 * group formation. This does not work well with system properties which can quickly
 * exhaust or for specifiying a dhcp start target in init which requires
 * interface to be pre-defined in init.rc file.
 *
 * This function returns a common string p2p for all p2p interfaces.
 */
void get_p2p_interface_replacement(const char *interface, char *p2p_interface) {
    /* Use p2p for any interface starting with p2p. */
    if (strncmp(interface, "p2p",3) == 0) {
        strncpy(p2p_interface, "p2p", MAX_INTERFACE_LENGTH);
    } else {
        strncpy(p2p_interface, interface, MAX_INTERFACE_LENGTH);
    }
}

/*
 * vlan interface names increase sequentially ethx.1, ethx.2.. after
 * group formation. This does not work well with system properties which can quickly
 * exhaust or for specifiying a dhcp start target in init which requires
 * interface to be pre-defined in init.rc file.
 *
 * This function returns a common string vlan for all vlan interfaces.
 */
void get_vlan_interface_replacement(const char *interface, char *vlan_interface) {
    /* Use vlan for any interface starting with eth0. */
    if (strncmp(interface, "eth0.",5) == 0) {
        strncpy(vlan_interface, "vlan", MAX_INTERFACE_LENGTH);
    } else {
        strncpy(vlan_interface, interface, MAX_INTERFACE_LENGTH);
    }
}
/*
 * Wait for a system property to be assigned a specified value.
 * If desired_value is NULL, then just wait for the property to
 * be created with any value. maxwait is the maximum amount of
 * time in seconds to wait before giving up.
 */
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = (maxwait * 1000) / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- > 0) {
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL || 
                    strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
        usleep(NAP_TIME * 1000);
    }
    return -1; /* failure */
}

static int fill_ip_info(const char *interface,
                     char *ipaddr,
                     char *gateway,
                     uint32_t *prefixLength,
                     char *dns[],
                     char *server,
                     uint32_t *lease,
                     char *vendorInfo,
                     char *domain,
                     char *mtu)
{
    char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];
    /* Interface name after converting p2p0-p2p0-X to p2p to reuse system properties */
    char p2p_interface[MAX_INTERFACE_LENGTH];
    int x;

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.ipaddress", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, ipaddr, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.gateway", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, gateway, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.server", DHCP_PROP_NAME_PREFIX, p2p_interface);
    property_get(prop_name, server, NULL);

    //TODO: Handle IPv6 when we change system property usage
    if (gateway[0] == '\0' || strncmp(gateway, "0.0.0.0", 7) == 0) {
        //DHCP server is our best bet as gateway
        strncpy(gateway, server, PROPERTY_VALUE_MAX);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, p2p_interface);
    if (property_get(prop_name, prop_value, NULL)) {
        int p;
        // this conversion is v4 only, but this dhcp client is v4 only anyway
        in_addr_t mask = ntohl(inet_addr(prop_value));
        // Check netmask is a valid IP address.  ntohl gives NONE response (all 1's) for
        // non 255.255.255.255 inputs.  if we get that value check if it is legit..
        if (mask == INADDR_NONE && strcmp(prop_value, "255.255.255.255") != 0) {
            snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
            return -1;
        }
        for (p = 0; p < 32; p++) {
            if (mask == 0) break;
            // check for non-contiguous netmask, e.g., 255.254.255.0
            if ((mask & 0x80000000) == 0) {
                snprintf(errmsg, sizeof(errmsg), "DHCP gave invalid net mask %s", prop_value);
                return -1;
            }
            mask = mask << 1;
        }
        *prefixLength = p;
    }

    for (x=0; dns[x] != NULL; x++) {
        snprintf(prop_name, sizeof(prop_name), "%s.%s.dns%d", DHCP_PROP_NAME_PREFIX, p2p_interface, x+1);
        property_get(prop_name, dns[x], NULL);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.leasetime", DHCP_PROP_NAME_PREFIX, p2p_interface);
    if (property_get(prop_name, prop_value, NULL)) {
        *lease = atol(prop_value);
    }

    snprintf(prop_name, sizeof(prop_name), "%s.%s.vendorInfo", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, vendorInfo, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.domain", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, domain, NULL);

    snprintf(prop_name, sizeof(prop_name), "%s.%s.mtu", DHCP_PROP_NAME_PREFIX,
            p2p_interface);
    property_get(prop_name, mtu, NULL);

    return 0;
}

static const char *ipaddr_to_string(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

/*
 * Start the dhcp client daemon, and wait for it to finish
 * configuring the interface.
 *
 * The device init.rc file needs a corresponding entry for this work.
 *
 * Example:
 * service dhcpcd_<interface> /system/bin/dhcpcd -ABKL -f dhcpcd.conf
 */
int dhcp_do_request(const char *interface,
                    char *ipaddr,
                    char *gateway,
                    uint32_t *prefixLength,
                    char *dns[],
                    char *server,
                    uint32_t *lease,
                    char *vendorInfo,
                    char *domain,
                    char *mtu)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2 + sizeof(DHCP_CONFIG_PATH)];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";
    /* Interface name after converting p2p0-p2p0-X to p2p to reuse system properties */
    char p2p_interface[MAX_INTERFACE_LENGTH];
    char vlan_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);
    get_vlan_interface_replacement(p2p_interface,vlan_interface);

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            vlan_interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the daemon and wait until it's ready */
    if (property_get(HOSTNAME_PROP_NAME, prop_value, NULL) && (prop_value[0] != '\0'))
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-f %s -h %s %s", DAEMON_NAME,
                 vlan_interface, DHCP_CONFIG_PATH, prop_value, interface);
    else
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-f %s %s", DAEMON_NAME,
                 vlan_interface, DHCP_CONFIG_PATH, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for dhcpcd to start");
        return -1;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP result property was not set");
        return -1;
    }
    if (strcmp(prop_value, "ok") == 0) {
        char dns_prop_name[PROPERTY_KEY_MAX];
        if (fill_ip_info(interface, ipaddr, gateway, prefixLength, dns,
                server, lease, vendorInfo, domain, mtu) == -1) {
            return -1;
        }
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP result was %s", prop_value);
        return -1;
    }
}

/**
 * Stop the DHCP client daemon.
 */
int dhcp_stop(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    char p2p_interface[MAX_INTERFACE_LENGTH];
    char vlan_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);
    get_vlan_interface_replacement(p2p_interface, vlan_interface);
    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            vlan_interface);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, vlan_interface);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    property_set(result_prop_name, "failed");
    return 0;
}

/**
 * Release the current DHCP client lease.
 */
int dhcp_release_lease(const char *interface)
{
    char value[PROPERTY_VALUE_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char result_prop_name[PROPERTY_KEY_MAX];
    const char *ctrl_start_prop = "ctl.start";
    const char *ctrl_stop_prop = "ctl.stop";
    const char *desired_released_status = "released";
    const char *desired_stopped_status = "stopped";
    char p2p_interface[MAX_INTERFACE_LENGTH];
    char vlan_interface[MAX_INTERFACE_LENGTH];
    
    get_p2p_interface_replacement(interface, p2p_interface);
    get_vlan_interface_replacement(p2p_interface, vlan_interface);
    property_get("net.dhcp.release", value, NULL);
    if(strcmp(value, "true") == 0) {
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_r_%s", DAEMON_NAME, vlan_interface);
        snprintf(result_prop_name, sizeof(result_prop_name), "dhcp.%s.result",p2p_interface);
        memset(value, 0, PROPERTY_VALUE_MAX);
        property_get(result_prop_name, value, "");
        if (strcmp(value, "ok") == 0) {
            property_set(ctrl_start_prop, daemon_cmd);
            if (wait_for_property(result_prop_name, desired_released_status, 1) < 0) {
                return -1;
            }
        }
    } else {
        snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
                DAEMON_PROP_NAME,
                vlan_interface);

        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, vlan_interface);

        /* Stop the daemon and wait until it's reported to be stopped */
        property_set(ctrl_stop_prop, daemon_cmd);
        if (wait_for_property(daemon_prop_name, desired_stopped_status, 5) < 0) {
            return -1;
        }
    }
    return 0;
}

char *dhcp_get_errmsg() {
    return errmsg;
}

/**
 * The device init.rc file needs a corresponding entry.
 *
 * Example:
 * service iprenew_<interface> /system/bin/dhcpcd -n
 *
 */
int dhcp_do_request_renew(const char *interface,
                    char *ipaddr,
                    char *gateway,
                    uint32_t *prefixLength,
                    char *dns[],
                    char *server,
                    uint32_t *lease,
                    char *vendorInfo,
                    char *domain,
                    char *mtu)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";

    char p2p_interface[MAX_INTERFACE_LENGTH];
    char vlan_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);
    get_vlan_interface_replacement(p2p_interface,vlan_interface);
    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            p2p_interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the renew daemon and wait until it's ready */
    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME_RENEW,
            vlan_interface, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP Renew to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP Renew result property was not set");
        return -1;
    }
    if (strcmp(prop_value, "ok") == 0) {
        return fill_ip_info(interface, ipaddr, gateway, prefixLength, dns,
                server, lease, vendorInfo, domain, mtu);
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP Renew result was %s", prop_value);
        return -1;
    }
}


/**
 * The device init.rc file needs a corresponding entry.
 *
 * Example:
 * service arping /system/bin/arping -c 3 -f -D -I
 * return: -1:arping error
 *			0:ip addr conflict
 *			1:ip addr unconfilct
 */
static const char ARPING_PROP_NAME_PREFIX[]  = "arping";
int arping_check_addressconflict(const char *interface,
                    const char *ipaddr)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    char desired_status[PROPERTY_VALUE_MAX]="running";
    char daemon_prop_name[PROPERTY_VALUE_MAX]="init.svc.arping";
    const char *ctrl_prop = "ctl.start";
    int retry_cnt = 3;
    char p2p_interface[MAX_INTERFACE_LENGTH];

    get_p2p_interface_replacement(interface, p2p_interface);

    snprintf(result_prop_name, sizeof(result_prop_name), "net.%s.result",
            ARPING_PROP_NAME_PREFIX);
    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");
    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s:%s %s", "arping",
            p2p_interface,ipaddr );
    LOGD("arping_check_addressconflict:start  %s", daemon_cmd);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);

    /* Start the arping daemon and wait until it's ready */
    while(--retry_cnt){
        property_set(ctrl_prop, daemon_cmd);
        if (wait_for_property(daemon_prop_name, desired_status, 5) < 0){
            LOGD("Time out waiting for arping to start,retrying...");
            if(retry_cnt == 0)
                return -1;
        }else {
            break;
        }
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for arping to finish");
        LOGD("Timed out waiting for arping to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "arping result property was not set");
	    LOGD("arping result property was not set");
        return -1;
    }
    if(strcmp(prop_value,"conflict") == 0){
        LOGD("return arping result property :confict");
        return 0;
    }else{
        LOGD("return arping result property :unconfilct");
        return 1;
    }
}
