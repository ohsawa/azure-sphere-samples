/* Copyright (c) Microsoft Corporation. All rights reserved.
   Licensed under the MIT License. */

// This sample C application shows how to set up services on a private Ethernet network. It
// configures the network with a static IP address, starts the DHCP service allowing dynamically
// assigning IP address and network configuration parameters, enables the SNTP service allowing
// other devices to synchronize time via this device, and sets up a TCP server.
//
// It uses the API for the following Azure Sphere application libraries:
// - log (messages shown in Visual Studio's Device Output window during debugging)
// - networking (sets up private Ethernet configuration)

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

// applibs_versions.h defines the API struct versions to use for applibs APIs.
#include "applibs_versions.h"
#include "epoll_timerfd_utilities.h"

#include <applibs/log.h>
#include <applibs/networking.h>
#include <applibs/wificonfig.h>
#include <applibs/gpio.h>
#include <applibs/storage.h>

// By default, this sample's CMake build targets hardware that follows the MT3620
// Reference Development Board (RDB) specification, such as the MT3620 Dev Kit from
// Seeed Studios.
//
// To target different hardware, you'll need to update the CMake build. The necessary
// steps to do this vary depending on if you are building in Visual Studio, in Visual
// Studio Code or via the command line.
//
// See https://github.com/Azure/azure-sphere-samples/tree/master/Hardware for more details.
//
// This #include imports the sample_hardware abstraction from that hardware definition.
#include "mt3620.h"

#include "echo_tcp_server.h"

#define HW_SW2		MT3620_GPIO12	// not using
#define HW_SW3		MT3620_GPIO14	// not using
#define HW_LED1		MT3620_GPIO8	// "StatusLED" : Controllable with Device Twin
#define HW_LED2		MT3620_GPIO9	// "DebugLED" : Azure IoT Connection status
#define HW_PORT1	MT3620_GPIO0
#define HW_PORT2	MT3620_GPIO1
#define HW_PORT3	MT3620_GPIO2
#define HW_PORT4	MT3620_GPIO4
#define HW_ENC28RST	MT3620_GPIO6

#define NR_PORTS							4

typedef struct InputPort {
	int fd;
	int gpio;
	GPIO_Value_Type currentState;
} InputPort;

#define InputPort_Initializer(GPIO)		\
	.fd = -1,							\
	.gpio = GPIO,						\
	.currentState = GPIO_Value_High

static InputPort port[] = {
	[0] = {
		InputPort_Initializer(HW_PORT1),
	},
	[1] = {
		InputPort_Initializer(HW_PORT2),
	},
	[2] = {
		InputPort_Initializer(HW_PORT3),
	},
	[3] = {
		InputPort_Initializer(HW_PORT4),
	},
};

static int led1GpioFd = -1;
static int led2GpioFd = -1;

// File descriptors - initialized to invalid value
static int epollFd = -1;
static int timerFd = -1;

static int chechStatsFlag = 0;

static void ContactPollTimerEventHandler(EventData* eventData);

static bool isNetworkStackReady = false;
EchoServer_ServerState *serverState = NULL;

// Termination state
static volatile sig_atomic_t terminationRequired = false;

// Ethernet / TCP server settings.
static struct in_addr localServerIpAddress;
static struct in_addr subnetMask;
static struct in_addr gatewayIpAddress;
static const uint16_t LocalTcpServerPort = 11000;
static int serverBacklogSize = 3;
static const char NetworkInterface[] = "eth0";

/// <summary>
///     Signal handler for termination requests. This handler must be async-signal-safe.
/// </summary>
static void TerminationHandler(int signalNumber)
{
    // Don't use Log_Debug here, as it is not guaranteed to be async-signal-safe.
    terminationRequired = true;
}

/// <summary>
///     Called when the TCP server stops processing messages from clients.
/// </summary>
static void ServerStoppedHandler(EchoServer_StopReason reason)
{
    const char *reasonText;
    switch (reason) {
    case EchoServer_StopReason_ClientClosed:
        reasonText = "client closed the connection.";
        break;

    case EchoServer_StopReason_Error:
        reasonText = "an error occurred. See previous log output for more information.";
        break;

    default:
        reasonText = "unknown reason.";
        break;
    }

    Log_Debug("INFO: TCP server stopped: %s\n", reasonText);
    terminationRequired = true;
}

/// <summary>
///     Shut down TCP server and close epoll event handler.
/// </summary>
static void ShutDownServerAndCleanup(void)
{
    EchoServer_ShutDown(serverState);
    CloseFdAndPrintError(epollFd, "Epoll");
    CloseFdAndPrintError(timerFd, "Timer");
}

/// <summary>
///     Check network status and display information about all available network interfaces.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
static int CheckNetworkStatus(void)
{
    // Ensure the necessary network interface is enabled.
    int result = Networking_SetInterfaceState(NetworkInterface, true);
    if (result != 0) {
        if (errno == EAGAIN) {
            Log_Debug("INFO: The networking stack isn't ready yet, will try again later.\n");
            return 0;
        } else {
            Log_Debug(
                "ERROR: Networking_SetInterfaceState for interface '%s' failed: errno=%d (%s)\n",
                NetworkInterface, errno, strerror(errno));
            return -1;
        }
    }
    isNetworkStackReady = true;

    // Display total number of network interfaces.
    ssize_t count = Networking_GetInterfaceCount();
    if (count == -1) {
        Log_Debug("ERROR: Networking_GetInterfaceCount: errno=%d (%s)\n", errno, strerror(errno));
        return -1;
    }
    Log_Debug("INFO: Networking_GetInterfaceCount: count=%zd\n", count);

    // Read current status of all interfaces.
    size_t bytesRequired = ((size_t)count) * sizeof(Networking_NetworkInterface);
    Networking_NetworkInterface *interfaces = malloc(bytesRequired);
    if (!interfaces) {
        abort();
    }

    ssize_t actualCount = Networking_GetInterfaces(interfaces, (size_t)count);
    if (actualCount == -1) {
        Log_Debug("ERROR: Networking_GetInterfaces: errno=%d (%s)\n", errno, strerror(errno));
    }
    Log_Debug("INFO: Networking_GetInterfaces: actualCount=%zd\n", actualCount);

    // Print detailed description of each interface.
    for (ssize_t i = 0; i < actualCount; ++i) {
        Log_Debug("INFO: interface #%zd\n", i);

        // Print the interface's name.
        char printName[IF_NAMESIZE + 1];
        memcpy(printName, interfaces[i].interfaceName, interfaces[i].interfaceNameLength);
        printName[interfaces[i].interfaceNameLength] = '\0';
        Log_Debug("INFO:   interfaceName=\"%s\"\n", interfaces[i].interfaceName);

        // Print whether the interface is enabled.
        Log_Debug("INFO:   isEnabled=\"%d\"\n", interfaces[i].isEnabled);

        // Print the interface's configuration type.
        Networking_IpType ipType = interfaces[i].ipConfigurationType;
        const char *typeText;
        switch (ipType) {
        case Networking_IpType_DhcpNone:
            typeText = "DhcpNone";
            break;
        case Networking_IpType_DhcpClient:
            typeText = "DhcpClient";
            break;
        default:
            typeText = "unknown-configuration-type";
            break;
        }
        Log_Debug("INFO:   ipConfigurationType=%d (%s)\n", ipType, typeText);

        // Print the interface's medium.
        Networking_InterfaceMedium_Type mediumType = interfaces[i].interfaceMediumType;
        const char *mediumText;
        switch (mediumType) {
        case Networking_InterfaceMedium_Unspecified:
            mediumText = "unspecified";
            break;
        case Networking_InterfaceMedium_Wifi:
            mediumText = "Wi-Fi";
            break;
        case Networking_InterfaceMedium_Ethernet:
            mediumText = "Ethernet";
            break;
        default:
            mediumText = "unknown-medium";
            break;
        }
        Log_Debug("INFO:   interfaceMediumType=%d (%s)\n", mediumType, mediumText);

        // Print the interface connection status
        Networking_InterfaceConnectionStatus status;
        int result = Networking_GetInterfaceConnectionStatus(interfaces[i].interfaceName, &status);
        if (result != 0) {
            Log_Debug("ERROR: Networking_GetInterfaceConnectionStatus: errno=%d (%s)\n", errno,
                      strerror(errno));
            return -1;
        }
        Log_Debug("INFO:   interfaceStatus=0x%02x\n", status);
    }

    free(interfaces);

    return 0;
}

/// <summary>
///     Configure the specified network interface with a static IP address.
/// </summary>
/// <param name="interfaceName">
///     The name of the network interface to be configured.
/// </param>
/// <returns>0 on success, or -1 on failure</returns>
static int ConfigureNetworkInterfaceWithStaticIp(const char *interfaceName)
{
    Networking_IpConfig ipConfig;
    Networking_IpConfig_Init(&ipConfig);
    inet_aton("192.168.100.10", &localServerIpAddress);
    inet_aton("255.255.255.0", &subnetMask);
    inet_aton("0.0.0.0", &gatewayIpAddress);
    Networking_IpConfig_EnableStaticIp(&ipConfig, localServerIpAddress, subnetMask,
                                       gatewayIpAddress);

    int result = Networking_IpConfig_Apply(interfaceName, &ipConfig);
    Networking_IpConfig_Destroy(&ipConfig);
    if (result != 0) {
        Log_Debug("ERROR: Networking_IpConfig_Apply: %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    Log_Debug("INFO: Set static IP address on network interface: %s.\n", interfaceName);

    return 0;
}

/// <summary>
///     Start SNTP server on the specified network interface.
/// </summary>
/// <param name="interfaceName">
///     The name of the network interface on which to start the SNTP server.
/// </param>
/// <returns>0 on success, or -1 on failure</returns>
static int StartSntpServer(const char *interfaceName)
{
    Networking_SntpServerConfig sntpServerConfig;
    Networking_SntpServerConfig_Init(&sntpServerConfig);
    int result = Networking_SntpServer_Start(interfaceName, &sntpServerConfig);
    Networking_SntpServerConfig_Destroy(&sntpServerConfig);
    if (result != 0) {
        Log_Debug("ERROR: Networking_SntpServer_Start: %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    Log_Debug("INFO: SNTP server has started on network interface: %s.\n", interfaceName);
    return 0;
}

/// <summary>
///     Configure and start DHCP server on the specified network interface.
/// </summary>
/// <param name="interfaceName">
///     The name of the network interface on which to start the DHCP server.
/// </param>
/// <returns>0 on success, or -1 on failure</returns>
static int ConfigureAndStartDhcpSever(const char *interfaceName)
{
    Networking_DhcpServerConfig dhcpServerConfig;
    Networking_DhcpServerConfig_Init(&dhcpServerConfig);

    struct in_addr dhcpStartIpAddress;
    inet_aton("192.168.100.11", &dhcpStartIpAddress);

    Networking_DhcpServerConfig_SetLease(&dhcpServerConfig, dhcpStartIpAddress, 1, subnetMask,
                                         gatewayIpAddress, 24);
    Networking_DhcpServerConfig_SetNtpServerAddresses(&dhcpServerConfig, &localServerIpAddress, 1);

    int result = Networking_DhcpServer_Start(interfaceName, &dhcpServerConfig);
    Networking_DhcpServerConfig_Destroy(&dhcpServerConfig);
    if (result != 0) {
        Log_Debug("ERROR: Networking_DhcpServer_Start: %d (%s)\n", errno, strerror(errno));
        return -1;
    }
    Log_Debug("INFO: DHCP server has started on network interface: %s.\n", interfaceName);
    return 0;
}

/// <summary>
///     Configure network interface, start SNTP server and TCP server.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
static int CheckNetworkStackStatusAndLaunchServers(void)
{
    // Check the network stack readiness and display available interfaces when it's ready.
    if (CheckNetworkStatus() != 0) {
        return -1;
    }

    // The network stack is ready, so unregister the timer event handler and launch servers.
    if (isNetworkStackReady) {
        // UnregisterEventHandlerFromEpoll(epollFd, timerFd);

        // Use static IP addressing to configure network interface.
        int result = ConfigureNetworkInterfaceWithStaticIp(NetworkInterface);
        if (result != 0) {
            return -1;
        }

        // Start the SNTP server.
        result = StartSntpServer(NetworkInterface);
        if (result != 0) {
            return -1;
        }

        // Configure and start DHCP server.
        result = ConfigureAndStartDhcpSever(NetworkInterface);
        if (result != 0) {
            return -1;
        }

        // Start the TCP server.
        serverState = EchoServer_Start(epollFd, localServerIpAddress.s_addr, LocalTcpServerPort,
                                       serverBacklogSize, ServerStoppedHandler);
        if (serverState == NULL) {
            return -1;
        }
    }

    return 0;
}

/// <summary>
///     The timer event handler.
/// </summary>
static void TimerEventHandler(EventData *eventData)
{
    int i;
    char D_INStr[16] = "D_IN: ";
    GPIO_Value_Type D_INState[4];
    GPIO_Value_Type LED_State;

    if (ConsumeTimerFdEvent(timerFd) != 0) {
        terminationRequired = true;
        return;
    }

    // Check whether the network stack is ready.
    if (!isNetworkStackReady && chechStatsFlag != 1) {
        if (CheckNetworkStackStatusAndLaunchServers() != 0) {
            terminationRequired = true;
        }
    }

    if(serverState->clientFd != -1) {
        if (chechStatsFlag != 1) {
            chechStatsFlag = 1;
        }
        for(i = 0; i < 4; i++) {
            GPIO_GetValue(port[i].fd, &D_INState[i]);
        }
        sprintf(D_INStr, "D_IN: %d %d %d %d", D_INState[0], D_INState[1], D_INState[2], D_INState[3]);
        strcpy(serverState->input, D_INStr);
        LaunchWrite(serverState);
        GPIO_GetValue(led1GpioFd, &LED_State);
        GPIO_SetValue(led1GpioFd, 1 - LED_State);
    }
}

// event handler data structures. Only the event handler field needs to be populated.
static EventData timerEventData = {.eventHandler = &TimerEventHandler};

/// <summary>
///     Set up SIGTERM termination handler, set up epoll event handling, configure network
///     interface, start SNTP server and TCP server.
/// </summary>
/// <returns>0 on success, or -1 on failure</returns>
static int InitializeAndLaunchServers(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = TerminationHandler;
    sigaction(SIGTERM, &action, NULL);

    epollFd = CreateEpollFd();
    if (epollFd < 0) {
        return -1;
    }

    // ENC28J60 Reset
	int deviceENC28rstGpioFd = GPIO_OpenAsOutput(HW_ENC28RST, GPIO_OutputMode_PushPull, GPIO_Value_Low);
	struct timespec req;
	req.tv_sec = 0;
	req.tv_nsec = 1000;
	nanosleep(&req, NULL);
	GPIO_SetValue(deviceENC28rstGpioFd, GPIO_Value_High);

    // Open contact inputs as input
	int i;
	for (i = 0; i < NR_PORTS; i++) {
		Log_Debug("Opening CONTACT_INPUT_%d as input\n", i + 1);
		port[i].fd = GPIO_OpenAsInput(port[i].gpio);
		if (port[i].fd < 0) {
			Log_Debug("ERROR: Could not open contact input %d: %s (%d).\n", i + 1, strerror(errno), errno);
			return -1;
		}
	}

	// LED1
	Log_Debug("Opening HW_LED1 as output\n");
	led1GpioFd =
		GPIO_OpenAsOutput(HW_LED1, GPIO_OutputMode_PushPull, GPIO_Value_High);
	if (led1GpioFd < 0) {
		Log_Debug("ERROR: Could not open LED1: %s (%d).\n", strerror(errno), errno);
		return -1;
	}

	// LED2
	Log_Debug("Opening HW_LED2 as output\n");
	led2GpioFd =
		GPIO_OpenAsOutput(HW_LED2, GPIO_OutputMode_PushPull, GPIO_Value_High);

	if (led2GpioFd < 0) {
		Log_Debug("ERROR: Could not open LED2: %s (%d).\n", strerror(errno), errno);
		return -1;
	}

    // Check network interface status at the specified period until it is ready.
    struct timespec checkInterval = {0, 500*1000*1000};
    timerFd = CreateTimerFdAndAddToEpoll(epollFd, &checkInterval, &timerEventData, EPOLLIN);
    if (timerFd < 0) {
        return -1;
    }

    return 0;
}

/// <summary>
///     Main entry point for this application.
/// </summary>
int main(int argc, char *argv[])
{
    const struct timespec interval = {10, 0};
    int ret;
    Log_Debug("INFO: Private Ethernet TCP server application starting.\n");
    if (InitializeAndLaunchServers() != 0) {
        terminationRequired = true;
    }

    // Use epoll to wait for events and trigger handlers, until an error or SIGTERM happens
    while (!terminationRequired) {
        if (WaitForEventAndCallHandler(epollFd) != 0) {
            terminationRequired = true;
        }
        printf("Wifi scanning...\n");
        ret = WifiConfig_TriggerScanAndGetScannedNetworkCount();
        if (ret <= 0) {
            printf("ERROR: WifiConfig_TriggerScanAndGetScannedNetworkCount failed: %s (%d).\n",
                strerror(errno), errno);
            nanosleep(&interval, NULL);
        } else {
            printf("Detected %d access points.\n", ret);
        }
    }

    ShutDownServerAndCleanup();
    Log_Debug("INFO: Application exiting.\n");
    return 0;
}
