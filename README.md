# My First Minute On A Server;

     _____                            _   _               _            _
    /  ___|                          | | | |             | |          (_)
    \ `--.  ___ _ ____   _____ _ __  | |_| | __ _ _ __ __| | ___ _ __  _ _ __   __ _
     `--. \/ _ \ '__\ \ / / _ \ '__| |  _  |/ _` | '__/ _` |/ _ \ '_ \| | '_ \ / _` |
    /\__/ /  __/ |   \ V /  __/ |    | | | | (_| | | | (_| |  __/ | | | | | | | (_| |
    \____/ \___|_|    \_/ \___|_|    \_| |_/\__,_|_|  \__,_|\___|_| |_|_|_| |_|\__, |
                                                                                __/ |
                                                                               |___/

Hi! My name is [Remi Teeple](https://remi.works) and this guide is aimed to provide a consistent standard for server initialization and rollout for any and all! It is based off an [old article](https://plusbryan.com/my-first-5-minutes-on-a-server-or-essential-security-for-linux-servers) and my hope is keep the information in said article relevant in a modern 2020 eco-system. If you aren't much for reading then please use [the included script]() to automate this entire guide.

Without further ado, let's begin...

[![CC-BY-SA](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)](#license)

# Table of Contents

- [My First Minute On A Server;](#my-first-minute-on-a-server)
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
  - [System Hardening](#system-hardening)
  - [Application Installation & Configuration](#application-installation--configuration)
  - [Guide Automation Script](#guide-automation-script)
- [System Hardening](#system-hardening-1)
  - [Creating a User](#creating-a-user)
  - [Changing Default Passwords](#changing-default-passwords)
  - [Updating and Upgrading](#updating-and-upgrading)
  - [SSH Authentication Keys (TODO https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys-on-ubuntu-20-04)](#ssh-authentication-keys-todo-httpswwwdigitaloceancomcommunitytutorialshow-to-set-up-ssh-keys-on-ubuntu-20-04)
  - [Change the default SSH Port & Disable ROOT login](#change-the-default-ssh-port--disable-root-login)
  - [Firewall Setup (UFW)](#firewall-setup-ufw)
- [Application Installation & Configuration](#application-installation--configuration-1)
  - [Update Automation (unattended-upgrades)](#update-automation-unattended-upgrades)
  - [Checking for Rootkits (chkrootkit & rkhunter)](#checking-for-rootkits-chkrootkit--rkhunter)
  - [iptables Intrusion Detection & Prevention (PSAD)](#iptables-intrusion-detection--prevention-psad)
  - [Application Intrusion Detection & Prevention (Fail2Ban)](#application-intrusion-detection--prevention-fail2ban)
  - [Anti-Virus Scanning (ClamAV)](#anti-virus-scanning-clamav)
  - [System Logging (Logwatch)](#system-logging-logwatch)
- [The Script](#the-script)
- [Conclusion](#conclusion)

# Introduction

This guide is split into **X sections**. Each section can be used independently of one another and will provide explanations as to what each step does. I've catered this guide to Ubuntu architecture but many of the principles and configurations will work on any Linux Distribution.

Feel free to use whatever command line editor you like... For this guide all of the examples will be provided with `nano` usage.

## System Hardening

This section covers hardening a fresh Linux Server with native commands and configurations.

## Application Installation & Configuration

This section covers the installation and configuration of software to assist in the hardening of the Linux server.

## Guide Automation Script

A simple explaination as to what the included script does to your machine.

# System Hardening

**System Hardening** is the process of securing a system's settings and configuration files in attempt to minimize threat vulnerability and the possibility of compromise. **System Hardening** is done by shrinking the attack surface to reduce the amount of attack vectors a bad actor might attempt to exploit.

A commonaility of many default systems is an exposure to various threats. By using this guide we will minimize the attack surface for a brand new Linux server.

## Creating a User

If your system doesn't have a user setup by default, it is important to create one youself.

To create a new user we use the following command:

```bash
adduser <YOUR_USER>
```

We then must grant the new user permission to use sudo by adding them to the **sudo** group.

```bash
usermod -aG sudo <YOUR_USER>
```

## Changing Default Passwords

Change the password for the root user to something long and complicated.

Ensure that you are ROOT before running this:

```bash
passwd
```

## Updating and Upgrading

Once the system is alive and well it's important to ensure that we are up to date. By updating the packages on our system we mitigate the risk of leaving vulnerabilities un-patched.

To update our package lists and upgrade any outdated packages we run the following:

```bash
sudo apt-get update && sudo apt-get upgrade
```

## SSH Authentication Keys (TODO https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys-on-ubuntu-20-04)

SSH Authentication is the new sticky-note password. A largely static identifier that's used to ensure the connection between the key-holder and the server.

To generate a [Ed25519](https://linux-audit.com/using-ed25519-openssh-keys-instead-of-dsa-rsa-ecdsa/) key pair use the following command:

```bash
ssh-keygen -t ed25519
```

After generating the key pair you will be prompted with the following output:

```bash
# Console Output
Generating public/private rsa key pair.
Enter file in which to save the key (/<YOUR_HOME>/.ssh/id_rsa):
```

> Pressing enter _(or "return")_ will save the key pair into the `.ssh` directory in your home. You can also specify a directory to save the key pair to if so desired.

After saving the key pair's location you will see the following prompt:

```bash
# Console Output
Enter passphrase (empty for no passphrase):
```

> **Note:** Though _technically_ optional, a **secure passphrase** is highly reccomended.

Your key pair should now generate and display and output similiar to the following:

```bash
# Console Output
Your identification has been saved in /<YOUR_HOME>/.ssh/id_rsa
Your public key has been saved in /<YOUR_HOME>/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:/hk7MJ5n5aiqdfTVUZr+2Qt+qCiS7BIm5Iv0dxrc3ks user@host
The key's randomart image is:
+---[RSA 3072]----+
|                .|
|               + |
|              +  |
| .           o . |
|o       S   . o  |
| + o. .oo. ..  .o|
|o = oooooEo+ ...o|
|.. o *o+=.*+o....|
|    =+=ooB=o.... |
+----[SHA256]-----+
```

## Change the default SSH Port & Disable ROOT login

The default SSH port (22) is an easy target for most bad actors. To help mitigate the amount of hits you might receive against a public facing SSH port, you can change it to a non-standard port. Ensure that the port that you change SSH to is not already in use, that is typically a port **above 1024**... Here [is a list](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports) of ports to avoid.

Open sshd_config

```bash
sudo nano /etc/ssh/sshd_config
```

Add the following to the bottom of sshd_config

```bash
Port <YOUR_PORT_NUMBER> #Changes the SSH Port
PermitRootLogin no #Disallows Root Login (Login to user instead!)
PasswordAuthentication no #Disables password authentication (SSH Keys used instead!)
AllowUsers <YOUR_USER>@<YOUR_IP> #Limit logins to specific users & IP's
```

After we're done making changes the SSH sevice must be restarted to take said changes!

```bash
sudo service ssh restart
```

## Firewall Setup (UFW)

**UFW** _(Uncomplicated Firewall)_ is a simple but powerful tool to secure a Linux Server.

Before anything else. We must add SSH to the allow list to prevent your connection dropping

# Application Installation & Configuration

The following section will provide insight on the installation and configuration of software to enable intrusion detection, intrusion prevention, malware detection, system logging, automation

## Update Automation (unattended-upgrades)

Automatic security updates are important to ensure un-patched vulernabilities are mitigated on a live server. While automatic upgrades can occassionaly break things, I'd say its better to patch security holes with slightly more up-keep _(the task is automated afterall)_ than it is to stay overtly less secure.

To keep the system up-to-date without admin intervention we will install [**unattended-upgrades**](https://wiki.debian.org/UnattendedUpgrades):

```bash
sudo apt-get install unattended-upgrades
```

Then open the 10periodic conf file:

```bash
sudo nano /etc/apt/apt.conf.d/10periodic
```

And update the file's contents to match the following:

```bash
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

Finally we open the unattended-upgrades conf file:

```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

And add the following to the bottom of the file:

```bash
Unattended-Upgrade::Allowed-Origins {
        "Ubuntu lucid-security";
        "Ubuntu lucid-updates"; #Optionally disable to improve stability
};
```

## Checking for Rootkits (chkrootkit & rkhunter)

> A **rootkit** is a collection of computer software, typically malicious, designed to enable access to a computer or an area of its software that is not otherwise allowed (for example, to an unauthorized user) and often masks its existence or the existence of other software. - [Wikipedia](https://en.wikipedia.org/wiki/Rootkit)

Obviously, rootkits are not something we want. We can use [**rkhunter**](http://rkhunter.sourceforge.net/) & [**chkrootkit**](http://www.chkrootkit.org/) to detect if our system has been compromised.

By using these two tools we can quickly scan for rootkits!

```bash
sudo apt-get install rkhunter chkrootkit
```

First we'll run **chkrootkit**

```bash
sudo chkrootkit
```

Second we'll run **rkhunter**

```bash
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check
```

> **Note:** If anything is detected immediately look up remidiation strategies!

## iptables Intrusion Detection & Prevention (PSAD)

## Application Intrusion Detection & Prevention (Fail2Ban)

## Anti-Virus Scanning (ClamAV)

## System Logging (Logwatch)

System logging is an important part of security auditting and monitoring. Logging allows you to see if any bad actors are hitting the server from a point that you might not have expected. Logging allows you to see what might cause unexpected server outages. Logging allows you to be a better administrator. To log the server's status and have said status sent to your email daily, we will be using [**Logwatch**](https://sourceforge.net/projects/logwatch/files/).

As always, the first stpe is to install the application:

```bash
sudo apt-get install logwatch
```

We then need to open the logwatch cron:

```bash
sudo nano /etc/cron.daily/00logwatch
```

And add this line:

```bash
/usr/sbin/logwatch --output mail --mailto <YOUR>@<EMAIL>.com --detail high
```

> **Note:** This will enable a daily email to generate with high details and send to whatever email is speicfied. For this to work properly SNMP should be allowed through the firewall.

# The Script

This script is intended to act as an automation tool for this guide. As such I highly reccommend you read through the guide before executing the script. This script is not meant to supplement the guide, or meant to be done as a final step. Instead this script IS the guide. Please only modify your system **AFTER RUNNING THE SCRIPT**.

I will not take responsibility for any damage caused by the script.

# Conclusion

Once everything is said and done, it's time to restart the server:

```bash
sudo reboot
```
