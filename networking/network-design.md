# Network Design

# Overview
This lab uses a VirtualBox NAT Network to provide controlled internal communication between virtual machines while allowing outbound internet access.
All virtual machines are connected to the same NAT Network to simulate a small internal enterprise environment.

## Network Mode Selection
**Network Mode:** NAT Network 
**Network Name:** Null

The NAT Network mode was selected to:
- Allow all lab machines to communicate with each other
- Provide internet access for updates and tooling
- Prevent direct inbound access from external networks

This design balances usability and security for an isolated home lab.

## Virtual Machine Network Configuration
All virtual machines share identical network settings:

- Adapter: 1
- Attached to: NAT Network
- NAT Network Name: Null

## Network Configuration Evidence
The following screenshots document the VirtualBox network configuration for each system:

- Kali Linux NAT Network configuration
- Ubuntu NAT Network configuration
- Windows 10 Enterprise NAT Network configuration

These screenshots confirm that all systems are connected to the same NAT Network (`Null`) using Adapter 1.
![Kali NAT Network](../assets/kali-nat-network.png)
![Ubuntu NAT Network](../assets/ubuntu-nat-network.png)
![Windows 10 NAT Network](../assets/windows10-nat-network.png)

## Connected Systems
- Kali Linux
- Ubuntu 
- Windows 10 Enterprise

## Communication Flow
- VM ↔ VM communication: **Allowed**
- VM → Internet: **Allowed**
- Internet → VM: **Blocked by default**
- Host ↔ VM: **Allowed**

This ensures a controlled environment suitable for troubleshooting and analysis
## Security Considerations
- NAT Network provides basic isolation from external threats
- No services are exposed publicly
