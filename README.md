# Your First Minute On A Server

```
     :::   :::    ::::::::::      :::   :::        ::::::::          :::          ::::::::
    :+:   :+:    :+:            :+:+: :+:+:      :+:    :+:       :+: :+:       :+:    :+:
    +:+ +:+     +:+           +:+ +:+:+ +:+     +:+    +:+      +:+   +:+      +:+
    +#++:      :#::+::#      +#+  +:+  +#+     +#+    +:+     +#++:++#++:     +#++:++#++
    +#+       +#+           +#+       +#+     +#+    +#+     +#+     +#+            +#+
   #+#   #+# #+#       #+# #+#       #+# #+# #+#    #+# #+# #+#     #+# #+# #+#    #+#
  ###   ### ###       ### ###       ### ###  ########  ### ###     ### ###  ########
```

**Your First Minute On A Server** _(YFMOAS)_

Hi! :wave: My name is [Remi Teeple](https://remi.works) and this guide is aimed to provide a consistent standard for server initialization and rollout. I wanted to consolidate my ideal server creation for my own reference but I figured I should share my methodology and ideology. Originally inspired by an [old article](https://plusbryan.com/my-first-5-minutes-on-a-server-or-essential-security-for-linux-servers) my hope is to keep the information in said article relevant in a modern 2020 eco-system while adding additional security. :godmode:

If you aren't much for reading then please use [the included script]() to automate this entire guide.

# Table of Contents

- [Your First Minute On A Server](#your-first-minute-on-a-server)
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
    - [System Hardening](#system-hardening)
    - [Application Installation & Configuration](#application-installation--configuration)
    - [Guide Automation Script](#guide-automation-script)
- [System Hardening](#system-hardening-1)
  - [Creating a User](#creating-a-user)
  - [Changing Default Passwords](#changing-default-passwords)
  - [Updating and Upgrading](#updating-and-upgrading)
  - [Creating & Using SSH Authentication Keys](#creating--using-ssh-authentication-keys)
  - [Securing SSH](#securing-ssh)
  - [Firewall Setup (**UFW**)](#firewall-setup-ufw)
  - [Securing Sudo (TODO)](#securing-sudo-todo)
  - [Securing Shared Memory](#securing-shared-memory)
- [Application Installation & Configuration](#application-installation--configuration-1)
  - [Update Automation (**unattended-upgrades**)](#update-automation-unattended-upgrades)
  - [Checking for Rootkits (**chkrootkit** & **rkhunter**)](#checking-for-rootkits-chkrootkit--rkhunter)
  - [Anti-Virus Scanning (**ClamAV**)](#anti-virus-scanning-clamav)
  - [iptables Intrusion Detection & Prevention (**PSAD**)](#iptables-intrusion-detection--prevention-psad)
  - [Application Intrusion Detection & Prevention (**Fail2Ban**)](#application-intrusion-detection--prevention-fail2ban)
  - [System Logging (**Logwatch**)](#system-logging-logwatch)
- [The Script](#the-script)
- [Conclusion](#conclusion)
- [License](#license)

# Introduction

This guide is split into **X sections**. Each section can be used independently of one another and will provide explanations as to what each step does. I've catered this guide to Ubuntu / Debian architecture but many of the principles and configurations will work on any Linux Distribution.

### System Hardening

Covers hardening a fresh Linux Server with native commands and configurations to shrink the default attack surface.

### Application Installation & Configuration

This section covers the installation and configuration of software to assist in the hardening of the Linux server.

### Guide Automation Script

A simple explanation as to what the included script does to your machine and how to use it.

Feel free to use whatever command line editor you like... For this guide all of the examples will be provided with `nano` usage.

# System Hardening

**System Hardening** is the process of securing a system's settings and configuration files in attempt to minimize threat vulnerability and the possibility of compromise. **System Hardening** is done by shrinking the attack surface to reduce the amount of attack vectors a bad actor might attempt to exploit.

A commonality of many default systems is an exposure to various threats. By using this guide we will minimize the attack surface for a brand new Linux server.

## Creating a User

If your system doesn't have a user setup by default, it is important to create one yourself.

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

## Creating & Using SSH Authentication Keys

SSH Authentication is the new sticky-note password. A largely static identifier that's used to ensure the connection between the key-holder and the server.

To generate a [Ed25519](https://linux-audit.com/using-ed25519-openssh-keys-instead-of-dsa-rsa-ecdsa/) key pair use the following command:

```bash
ssh-keygen -t ed25519
```

After generating the key pair you will be prompted with the following output:

```bash
# Console Output
Generating public/private ed25519 key pair.
Enter file in which to save the key (/<YOUR_HOME>/<YOUR_USER/.ssh/id_ed25519):
```

> Pressing enter _(or "return")_ will save the key pair into the `.ssh` directory in your home. You can also specify a directory to save the key pair to if so desired.

After saving the key pair's location you will see the following prompt:

```bash
# Console Output
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
```

> **Note:** Though _technically_ optional, a **secure passphrase** is highly recommended.

Your key pair should now generate and display and output similar to the following:

```bash
# Console Output
Your identification has been saved in /<YOUR_HOME>/<YOUR_USER>/.ssh/id_ed25519
Your public key has been saved in /<YOUR_HOME>/<YOUR_USER>/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:Xn8oX0Bp17+6B7lZ2vG6bB6vUar0ZW9ty/tQKRAWRcY <USER>@<HOST>
The key's randomart image is:
+--[ED25519 256]--+
|           +=+   |
|          . oE . |
|           .+ . .|
|           o..  o|
|        S . ....+|
|       . . . =.*.|
|        . . + #.*|
|           + X+X*|
|            o=XXB|
+----[SHA256]-----+
```

Once you have generated the key pair, you must now copy the public key to whatever hosts will connect to the server.

You can view the public key with the following command:

```bash
cat ~/.ssh/id_ed25519.pub
```

You can copy the public key to a password-based SSH enabled account with the following command:

```bash
cat ~/.ssh/id_ed25519.pub | ssh <USER>@<REMOTE_HOST> "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod -R go= ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

**ENSURE THAT YOU FOLLOW THE SECURING SSH STEP TO ENABLE SSH KEY AUTHENTICATION**

If you do not wish to read the [Securing SSH](#securing-ssh) section the information is reiterated here...

To enable the use of SSH key authentication exclusively (no password authentication) ensure that `sshd_config` disallows password authentication via the following...

Open `sshd_config`:

```bash
sudo nano /etc/ssh/sshd_config
```

Add the following line to the bottom of the file:

```bash
PasswordAuthentication no # Disables password authentication (this enables SSH key auth)
```

> **Note**: Do not loose your SSH public key as it will be your only way to login to the server remotely. Physical logins will still be available.

## Securing SSH

The default SSH port _(22)_ is an easy target for most bad actors. To help mitigate the amount of hits you might receive against a public facing SSH port, you can change it to a non-standard port. Ensure that the port that you change SSH to is not already in use, that is typically a port **above 1024**... Here [is a list](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports) of ports to avoid.

Open `sshd_config`:

```bash
sudo nano /etc/ssh/sshd_config
```

The following are highly recommended additions to your `sshd_config` file, however they are each optional. As such a comment explaining their action has been added next to each.
Add the following to the bottom of `sshd_config`:

```bash
Port <YOUR_PORT_NUMBER>             # Changes the SSH Port
PermitRootLogin no                  # Disallows Root Login (Login to user instead!)
PermitEmptyPasswords no             # Ensures no user logon without password
PasswordAuthentication no           # Disables password auth (enables SSH key auth)
AllowUsers <YOUR_USER>@<YOUR_IP>    # Limit logins to specific users & IP's
```

After we're done making changes the SSH service must be restarted to take said changes!

```bash
sudo service ssh restart
```

## Firewall Setup (**UFW**)

**UFW** _(Uncomplicated Firewall)_ is a simple but powerful tool to secure a Linux Server.

Before anything else. We must add SSH to the allow list to prevent your connection dropping

## Securing Sudo (TODO)

## Securing Shared Memory

Shared memory is a performant mehtod of passing data between running programs. Shared memory allows multiple processes to share the same space in memory, because of this bad actors could poteintially snoop process information from running services via the default read / write `/run/shm` space. To mitigate this we make the `/run/shm` space read-only.

In short, shared memory opens an attack vector against running services, securing shared memory prevents this from happening.

To secure shared memory, first open your `fstab` file:

```bash
sudo nano /etc/fstab
```

Add the following line to the bottom of the open `fstab` file:

```bash
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0
```

Once you save the changes exit and reboot your system:

```bash
sudo reboot
```

> **Note**: If you're following along with the guide then you can wait until the end to preform this action.

# Application Installation & Configuration

The following section will provide insight on the installation and configuration of software to enable intrusion detection, intrusion prevention, malware detection, system logging, automation

## Update Automation (**unattended-upgrades**)

Automatic security updates are important to ensure un-patched vulnerabilities are mitigated on a live server. While automatic upgrades can occasionally break things, I'd say its better to patch security holes with slightly more up-keep \_(the task is automated after all) then it is to stay overtly less secure.

To keep the system up-to-date without admin intervention we will install [**unattended-upgrades**](https://wiki.debian.org/UnattendedUpgrades):

```bash
sudo apt-get install unattended-upgrades
```

Then open the `10periodic` apt.conf file:

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

Now we need to configure unattended-upgrades to work properly. unattended-upgrades has many different configuration settings that I suggest you explore. For the purpose of this guide however, we will set up unattended-upgrades quite basically.

Open the `50unattended-upgrades` apt.conf file:

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

## Checking for Rootkits (**chkrootkit** & **rkhunter**)

> A **rootkit** is a collection of computer software, typically malicious, designed to enable access to a computer or an area of its software that is not otherwise allowed (for example, to an unauthorized user) and often masks its existence or the existence of other software. - [Wikipedia](https://en.wikipedia.org/wiki/Rootkit)

Obviously, rootkits are not something we want. We can use [**rkhunter**](http://rkhunter.sourceforge.net/) & [**chkrootkit**](http://www.chkrootkit.org/) to detect if our system has been compromised.

By using these two tools we can quickly scan for rootkits!

```bash
sudo apt-get install rkhunter chkrootkit
```

First we'll run `chkrootkit`

```bash
sudo chkrootkit
```

Second we'll run `rkhunter`

```bash
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check
```

> **Note:** If anything is detected immediately look up remediation strategies!

## Anti-Virus Scanning (**ClamAV**)

A necessity for any computer in the modern internet age is a competent anti-virus (while it's only ever as effective as the user's safe browsing practices). **ClamAV** provides just that.
**ClamAV** is an anti-virus scanner for Linux systems. It uses **ClamAV-Freshclam** to update virus definitions and **ClamAV-Daemon** keeps the `clamd` process running to speed up scanning.

```bash
sudo apt-get install clamav clamav-freshclam clamav-daemon
```

Start the `clamav-freshclam` service:

```bash
sudo service clamav-freshclam start
```

Ensure `clamav-freshclam` is running:

```bash
sudo service clamav-freshclam status
```

To initiate a full system scan and automatically remove found files enter the following command:

```bash
sudo clamscan -r --remove /
```

## iptables Intrusion Detection & Prevention (**PSAD**)

[PSAD](https://cipherdyne.org/psad/) is an intrusion prevention tool similiar to **Fail2ban** however, while Fail2ban detects and blocks on a application level, **PSAD** blocks on an iptables level via log messages.

> "Fail2BAN scans log files of various applications such as apache, ssh or ftp and automatically bans IPs that show the malicious signs such as automated login attempts. PSAD on the other hand scans iptables and ip6tables log messages (typically /var/log/messages) to detect and optionally block scans and other types of suspect traffic such as DDoS or OS fingerprinting attempts. It's ok to use both programs at the same time because they operate on different level." - [FINESEC](https://serverfault.com/a/447604/289829)

As always, the first step is to install the application:

```bash
sudo apt-get install psad
```

Ensure that `ENABLE_AUTO_IDS` & `EXPECT_TCP_OPTIONS` are set to `Y` in `psad.conf`:

```bash
# ENABLE_AUTO_IDS & EXPECT_TCP_OPTIONS should = Y
sudo nano /etc/psad/psad.conf
```

Open and edit `/etc/ufw/before.rules` & `/etc/ufw/before6.rules`:

```bash
sudo nano /etc/ufw/before.rules
sudo nano /etc/ufw/before6.rules
```

Add the following to the end of each file **BEFORE THE COMMIT LINE**:

```bash
# Log all traffic so PSAD can analyze it.
-A INPUT -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES] "
```

Reload UFW and psad

```bash
sudo ufw reload

sudo psad -R # (case sensitive)
sudo psad --sig-update
sudo psad -H # (case sensitive)
```

## Application Intrusion Detection & Prevention (**Fail2Ban**)

[Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) scans log files and bans IPs that show the malicious signs such as too many password failures, port scanning, searching for exploits, etc.

> **Note**: Fail2ban comes well configured out of the box so the additional configuration steps are optional but recommended.

Install `fail2ban` with the following command:

```bash
sudo apt-get install fail2ban
```

Create the file `jail.local` (not `jail.conf` as it may be overwritten by updates):

```bash
sudo nano /etc/fail2ban/jail.conf
```

Add or replace the following in the `jail.local` file:

```bash
[sshd]
enabled = true
banaction = ufw
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
```

Finally you must restart the fail2ban service for changes to take effect:

```bash
sudo service fail2ban restart
```

## System Logging (**Logwatch**)

System logging is an important part of security auditing and monitoring. Logging allows you to see if any bad actors are hitting the server from a point that you might not have expected. Logging allows you to see what might cause unexpected server outages. Logging allows you to be a better administrator. To log the server's status and have said status sent to your email daily, we will be using [**Logwatch**](https://sourceforge.net/projects/logwatch/files/).

As always, the first step is to install the application:

```bash
sudo apt-get install logwatch
```

We then need to open the `00logwatch` cron file:

```bash
sudo nano /etc/cron.daily/00logwatch
```

And add this line:

```bash
/usr/sbin/logwatch --output mail --mailto <YOUR>@<EMAIL>.com --detail high
```

> **Note:** This will enable a daily email to generate with high details and send to whatever email is specified. For this to work properly SNMP should be allowed through the firewall.

# The Script

This script is intended to act as an automation tool for this guide. As such I highly recommended you read through the guide before executing the script. This script is not meant to supplement the guide, or meant to be done as a final step. Instead this script IS the guide. Please only modify your system **AFTER RUNNING THE SCRIPT**.

I will not take responsibility for any damage caused by the script.

# Conclusion

Once everything is said and done, it's time to restart the server:

```bash
sudo reboot
```

After the dust settles you should have a significantly more secure Linux server box. I hope this guide has helped you and please feel free to reach out to me if you encounter issues.

Written by [Remi Teeple](https://remi.works)

# License

[![CC-BY-SA](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)](#license)
