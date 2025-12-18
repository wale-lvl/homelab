# Architecture Overview

## High-Level Design

This homelab is a virtualized cybersecurity environment designed to simulate a small enterprise network. 
It is built using Oracle VirtualBox and consists of three primary systems connected through an isolated NAT Network.

The architecture is intentionally simple to allow focused experimentation with networking, security testing, and system interactions while maintaining safe isolation from the host machine.

## Lab Components and Roles

| System        | Operating System        | Role in Lab                         |
|--------------|-------------------------|--------------------------------------|
| Kali Linux   | Kali Linux               | Attacker / Security Testing Machine |
| Ubuntu       | Ubuntu Linux             | Internal Server / Attacker          |
| Windows 10   | Windows 10 Enterprise    | User Endpoint                       |

---

## System Responsibilities

### Kali Linux
- Acts as the attacker and testing workstation
- Used for reconnaissance, scanning, and exploitation simulations
- Represents an untrusted or external threat actor

### Ubuntu Linux
- Acts as an internal server, can be used as an attacker also
- Hosts services such as SSH and web services
- Represents infrastructure targets within the network

### Windows 10 Enterprise
- Acts as a corporate endpoint
- Represents a user workstation
- Used to study endpoint behavior, security controls, and attack impact

---

## Network Architecture

All virtual machines are connected using a VirtualBox **NAT Network** named `Null`.

This design provides:
- Network communication between all lab systems
- Internet access for updates and package installation
- Isolation from the host’s physical network

---

## Trust Boundaries

The lab enforces logical trust boundaries:

- **Untrusted Zone:** Kali Linux
- **Trusted/Internal Zone:** Ubuntu and Windows 10

These boundaries allow realistic simulation of:
- External attacks against internal systems
- Lateral movement scenarios
- Defensive monitoring and response

---

## Design Philosophy

This architecture prioritizes:
- Simplicity over complexity
- Clear role separation
- Safe experimentation
- Documentation and reproducibility

The design can be expanded in the future to include additional servers, monitoring systems, or segmented networks.
