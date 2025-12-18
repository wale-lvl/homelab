
Paste this in:

```markdown
# Kali Linux Setup

## Purpose of Kali Linux in the Lab

Kali Linux is the primary **security testing and penetration testing** operating system in this lab. It serves as the attacker/testing machine from which security assessments, scans, and analysis are performed.

## General Installation Steps

1. Start VirtualBox and create a new VM named `Kali Linux`.
2. Set the type to **Linux** and version to Debian 64-bit.
3. Allocate at least 2–4 GB RAM and at least 20 GB storage.
4. Attach the Kali Linux ISO as a virtual optical drive.
5. Boot the VM and follow the standard installer prompts:
   - Select language and keyboard
   - Choose guided disk partitioning
   - Create user account
6. Complete the installation and reboot into the installed system (change default password to something more secure).

## Network Configuration

- Adapter 1 → NAT Network (`Null`)
- Allows internet access for updates and tool installation
- Machines on the same NAT network can communicate with each other

## Role in Lab

Kali Linux is used to:
- Run vulnerability scans
- Test network services
- Perform ethical attack simulations
- Analyze lab traffic and configurations

## Installation Evidence

![Kali Linux Installation](../screenshots/install/kali.png)
