# Windows 10 Enterprise Setup

## Purpose
Windows 10 Enterprise serves as a **target endpoint** in the lab environment. It is used to emulate a typical corporate user workstation for testing both attack and defense techniques.

## Installation Summary

1. In VirtualBox, create a new VM named `Windows10-Enterprise`(name is optional, can be anything you want).
2. Assign sufficient resources (4 GB RAM, 40 GB disk recommended).
3. Attach the Windows 10 installation ISO.
4. Complete the Windows installer steps:
   - Language and keyboard setup
   - Accept license terms
   - Choose custom installation
   - Create user account
5. Complete initial setup and log in.

## Network Configuration

- Adapter 1 → NAT Network (`Null`)
- Ensures internet access and communication with other VMs

## Role in Lab

- Serves as an **endpoint** and victim OS
- Useful for:
  - Testing Windows service scans
  - Logging and monitoring
  - Baseline defender/endpoint behavior

## Installation Evidence

![Windows 10 Enterprise Installation](../assets/windows10.png)
