# Internal Network Configuration

## Overview

All virtual machines in this lab are connected using a VirtualBox NAT Network named `Null`.

This internal network allows:
- Communication between Kali, Ubuntu, and Windows VMs
- Internet access for updates and package installation
- Network isolation from the host’s physical LAN

## Network Design Summary

- Network Type: NAT Network
- Network Name: Null
- Adapter Used: Adapter 1 on all VMs

This configuration simulates a small internal enterprise network while maintaining safety and isolation.
