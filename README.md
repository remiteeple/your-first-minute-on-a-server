# Your First Minute On A Server

```
                      `YMM'   `MM' `7MM"""YMM  `7MMM.     ,MMF'  .g8""8q.       db        .M"""bgd
                        VMA   ,V     MM    `7    MMMb    dPMM  .dP'    `YM.    ;MM:      ,MI    "Y
                         VMA ,V      MM   d      M YM   ,M MM  dM'      `MM   ,V^MM.     `MMb.
                          VMMP       MM""MM      M  Mb  M' MM  MM        MM  ,M  `MM       `YMMNq.
                           MM        MM   Y      M  YM.P'  MM  MM.      ,MP  AbmmmqMA    .     `MM
                           MM        MM          M  `YM'   MM  `Mb.    ,dP' A'     VML   Mb     dM
                         .JMML.    .JMML.      .JML. `'  .JMML.  `"bmmd"' .AMA.   .AMMA .P"Ybmmd"

                      """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
```

**Your First Minute On A Server** ( YFMOAS )

_An Essential Security guide for Linux Servers_

Hi! :wave: My name is [Remi Teeple](https://remi.works) and this guide is aimed to provide a consistent standard for server initialization and rollout. This guide was created from the perspective of a layman as security and hosting is not necessarily my forte. As such I wanted to consolidate my ideal server creation for my own reference but I figured I should share my methodology and ideology via GitHub for anyone to use. Originally inspired by the legendary ["My First 5 Minutes On A Server; Or, Essential Security for Linux Servers"](https://plusbryan.com/my-first-5-minutes-on-a-server-or-essential-security-for-linux-servers) my hope is to keep the information in said article relevant in a modern 2020 eco-system while adding additional security.

This guide was tested on Ubuntu `Ubuntu 20.04.1 LTS` (&ARM)

If you aren't much for reading then please use [the included script]() to automate this entire guide.

# Table of Contents :book:

- [Your First Minute On A Server](#your-first-minute-on-a-server)
- [Table of Contents :book:](#table-of-contents-book)
- [Introduction :handshake:](#introduction-handshake)
- [System Hardening :lock:](#system-hardening-lock)
  - [Creating a User](#creating-a-user)
  - [Changing Default Passwords](#changing-default-passwords)
  - [Updating and Upgrading](#updating-and-upgrading)
  - [Creating & Using SSH Authentication Keys](#creating--using-ssh-authentication-keys)
  - [Securing SSH](#securing-ssh)
  - [Firewall Setup (**UFW**)](#firewall-setup-ufw)
  - [Setting Timezone](#setting-timezone)
  - [Securing Sudo (TODO)](#securing-sudo-todo)
  - [Setting Security Limits](#setting-security-limits)
  - [Securing Shared Memory](#securing-shared-memory)
  - [Disabling Root User](#disabling-root-user)
  - [Securing SYSCTL](#securing-sysctl)
  - [Disabling IPv6](#disabling-ipv6)
- [Application Installation & Configuration :wrench:](#application-installation--configuration-wrench)
  - [Update Automation (**unattended-upgrades**)](#update-automation-unattended-upgrades)
  - [Checking for Rootkits (**chkrootkit** & **rkhunter**)](#checking-for-rootkits-chkrootkit--rkhunter)
  - [Anti-Virus Scanning (**ClamAV**)](#anti-virus-scanning-clamav)
  - [iptables Intrusion Detection & Prevention (**PSAD**)](#iptables-intrusion-detection--prevention-psad)
  - [Application Intrusion Detection & Prevention (**Fail2Ban**)](#application-intrusion-detection--prevention-fail2ban)
  - [System Logging (**Logwatch**)](#system-logging-logwatch)
- [System Stability :triangular_ruler:](#system-stability-triangular_ruler)
  - [Cleaning Installed Packages](#cleaning-installed-packages)
- [Guide Automation Script :scroll:](#guide-automation-script-scroll)
- [Conclusion :wave:](#conclusion-wave)
- [Q&A :grey_question:](#qa-grey_question)
- [License :exclamation:](#license-exclamation)

# Introduction :handshake:

This guide is split into **4 sections**. Each section can be used independently of one another and will provide explanations as to what each step does. I've catered this guide to Ubuntu / Debian architecture but many of the principles and configurations will work on any Linux Distribution. If you plan to have your server be internet facing then this guide is a good baseline for security.

**System Hardening**

- Covers hardening a fresh Linux Server with native commands and configurations to shrink the default attack surface.

**Application Installation & Configuration**

- This section covers the installation and configuration of software to assist in the hardening of the Linux server.

**Server Stability**

- Advice for maintaining server stability with regular up-keep tasks and some minor automation.

**Guide Automation Script**

- A simple explanation as to what the included script does to your machine and how to use it.

Feel free to use whatever command line editor you like... For this guide all of the examples will be provided with `nano` usage.

# System Hardening :lock:

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
sudo apt-get update && sudo apt-get full-upgrade -y
```

Optionally we can clean up after we update:

```bash
sudo apt-get autoremove -y && sudo apt-get autoclean -y
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

> **NOTE:** Though _technically_ optional, a **secure passphrase** is highly recommended.

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

Open `/etc/ssh/sshd_config`:

```bash
sudo nano /etc/ssh/sshd_config
```

Add the following line to the bottom of the file:

```bash
PasswordAuthentication no # Disables password authentication (this enables SSH key auth)
```

> **NOTE**: Do not lose your SSH public key as it will be your only way to login to the server remotely. Physical logins will still be available.

## Securing SSH

The default SSH port _(22)_ is an easy target for most bad actors. To help mitigate the amount of hits you might receive against a public facing SSH port, you can change it to a non-standard port. Ensure that the port that you change SSH to is not already in use, that is typically a port **above 1024**... Here [is a list](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports) of ports to avoid. Ultimately, changing your SSH port will stop only a few scanners from hitting the port so it is an optional but recommended step.

Open `/etc/ssh/sshd_config`:

```bash
sudo nano /etc/ssh/sshd_config
```

The following are highly recommended additions to your `sshd_config` file, however they are each optional. As such a comment explaining their action has been added next to each.
Add the following to the bottom of `sshd_config`:

```bash
# SSH Protocol 1 has vulnerabilities
Protocol 2

# Changes the SSH Port
Port <YOUR_PORT_NUMBER>

# Enforce strict home directory and key file permissions
StrictModes yes

# Disallows Root Login (Login to user instead!)
PermitRootLogin no

# Ensures no user logon without password
PermitEmptyPasswords no

# Disables password auth (enables SSH key auth)
PasswordAuthentication no

# Disables SSH environment variables
PermitUserEnvironment no

# Display last login
PrintLastLog no

# Reduce latency
UseDNS no

# Sets the max number of unauthenticated connections to the SSH daemon
MaxStartups 2

# Disables host based authentication
HostbasedAuthentication no

# Disables .rhosts authentication
IgnoreRhosts yes
RhostsAuthentication no
RhostsRSAAuthentication no
RSAAuthentication yes

# Prevent SSH tunnelling other ports
AllowTcpForwarding no
X11Forwarding no

# Limit logins to specific users and/or IP's
AllowUsers <USER>@<IP>
```

After we're done making changes the SSH service must be restarted to take said changes!

```bash
sudo service ssh restart
```

> **NOTE**: If you changed the default SSH port then any mention of the alias "ssh" will need to be replaced with the specific port you set. i.e. `sudo ufw limit in ssh` should now be `sudo ufw limit in <YOUR_PORT>`.

## Firewall Setup (**UFW**)

**UFW** _(Uncomplicated Firewall)_ is a simple but powerful tool to secure a Linux Server. The firewall configuration is largely dependant on the purpose of your server. This guide will cover some essential policies to ensure a good baseline for security, but additional tweaking will likely be required in production environments to ensure security.

A solid default starting point for `UFW` blocking comes from the "default" policy set, which can be activated via:

```bash
sudo ufw default allow outgoing # Alternatively "deny" depending on server prerequisites
```

```bash
sudo ufw default deny incoming
```

The first policy to set is to allow SSH access, otherwise you may inadvertently lock yourself out of the system. (Physical logins would still work.)

```bash
sudo ufw limit in ssh # Ideally setup more script policies to limit who can connect via SSH
```

> **NOTE**: "limit in" limits the amount of inbound connections that are allowed. Alternatively "allow" can be used if lots of SSH connections are expected.

Once the initial policies have been put in place, you can start `UFW`

```bash
sudo ufw enable
```

Verify the status of `UFW` and all the active policies:

```bash
sudo ufw status
```

## Setting Timezone

For accuracy in your logs please ensure that your timezone is properly set. To properly set your timezone use the following commands...

```bash
sudo locale-gen en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8
sudo dpkg-reconfigure tzdata
```

Alternatively, you can use the `timedatectl`:

```bash
timedatectl set-timezone EST # Eastern Standard Time
```

## Securing Sudo (TODO)

## Setting Security Limits

While rudimentary, [Fork Bomb](https://en.wikipedia.org/wiki/Fork_bomb) attacks are incredibly effective at causing system outages through means of a denial-of-service via resource starvation. To prevent such an attack from occurring on your Linux server the following **Security Limits** can be set...

Open `/etc/security/limits.conf`:

```bash
sudo nano /etc/security/limits.conf
```

The file explains how to setup specific user and group limits. If you want a simple solution to limit the amount of all user and group processes use the following.

Add this to the bottom of `/etc/security/limits.conf`:

```bash
* hard nproc 500
```

- "\*" represents the users, in this case all.
- "hard" sets a hard limit to the number of processes.
- "nproc" defines that we are limiting the number of processes.
- "500" is the maximum number of processes that a user can have.

## Securing Shared Memory

Shared memory is a performant method of passing data between running programs. Shared memory allows multiple processes to share the same space in memory, because of this bad actors could potentially snoop process information from running services via the default read / write `/run/shm` space. To mitigate this we make the `/run/shm` space read-only.

In short, shared memory opens an attack vector against running services, securing shared memory prevents this from happening.

To secure shared memory, first open your `/etc/fstab` file:

```bash
sudo nano /etc/fstab
```

Add the following line to the bottom of the open `/etc/fstab` file:

```bash
tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0
```

Once you save the changes exit and reboot your system:

```bash
sudo shutdown -r now
```

> **NOTE**: If you're following along with the guide you can wait until the end to preform this action.

## Disabling Root User

Disabling the root account is a safe action that removes the poteintial risk of a bad actor gaining access to it. We disable the account instead of removing it as that may cause issues if for whatever reason the root user is later needed.

To disable the root user use the following command:

```bash
# "-l" indicates that we are locking the user account
sudo passwd -l root
```

To enable the root user use the following command:

```bash
# "-u" indicates that we are unlocking the user account
sudo passwd -u root
```

## Securing SYSCTL

The `/etc/sysctl.conf` file is used to configure kernel parameters at runtime. By modifying specific parameters in the `/etc/sysctl.conf` file we can establish higher kernel level security in a Linux environment. Each parameter included in this example `/etc/sysctl.conf` is my personal recommendation, I implore that you to seek out each setting to get a better understanding of the possible values they can each be set to so you can create a customized configuration tailored to your server requirements. _These settings are catered to Ubuntu 20.08 LTS ARM with Docker._

The settings in `/etc/sysctl.conf` can:

- Limit network-transmitted configuration for IPv4.
- Limit network-transmitted configuration for IPv6.
- Prevent against 'syn flood` attacks
- Enable source IP verification.
- Prevent spoofing attacks against the IP address of the server.
- Log several types of suspicious packets. _(spoofed packets, source-routed packets, redirects, etc)_
- Automatically reboot on OOM (Out Of Memory) Kernel Panic.

To enable these settings enable the following in your `/etc/sysctl.conf`:

```bash
# Inspired by: https://www.kmotoko.com/articles/linux-hardening-kernel-parameters-with-sysctl/
# Docker support: https://bugs.launchpad.net/ubuntu/+source/procps/+bug/1676540

########################
### SYSTEM STABILITY ###
########################

# Reboot on Out Of Memory
# Kernel will wait 10 seconds before PANIC
vm.panic_on_oom = 1
kernel.panic = 10

#######################
### SYSTEM SECURITY ###
#######################

# Enable address space randomization
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0

# Hide kernel pointers
kernel.kptr_restrict = 1

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict ptrace scope
kernel.yama.ptrace_scope = 1

########################
### NETWORK SECURITY ###
########################

# Harden BPF JIT compiler
net.core.bpf_jit_harden = 1

# Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disable packet forwarding
# This disables mc_forwarding as well; writing to mc_forwarding causes an error net.
#net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
#net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Enable IP spoofing protection
# Turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Do not accept ICMP redirects (prevent MITM attacks)
# This removes the secure_redirects sysctlnet.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
#net.ipv4.conf.all.secure_redirects = 0
#net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
#net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.default.send_redirects = 0

# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Don't relay bootp
net.ipv4.conf.all.bootp_relay = 0

# Disable proxy ARP
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# Mitigate time-wait assassination hazards in TCP
net.ipv4.tcp_rfc1337 = 1

# Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ensure that subsequent connections use the new values
# ENSURE THIS IS AT THE END
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1
```

> **NOTE**: Some of the settings above are commented out because they interfere with Docker Engine. For increased security at the sacrifice of some usability uncomment the extra kernel instructions.

## Disabling IPv6

IPv6 currently poses a huge attack surface to most existing machines that are internet connected. As such disabling IPv6 entirely is a suitable option in some cases. While entirely dependant on the purpose of the server, it is recommended to disable IPv6 communications unless they are vital to hosting.

To disable IPv6 we first open the `/etc/sysctl.conf` file:

```bash
sudo nano /etc/sysctl.conf
```

Then add the following at the bottom of the `/etc/sysctl.conf` file:

```bash
# Disable all IPv6 communications
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Finally, reload the configuration:

```bash
sudo sysctl -p
```

# Application Installation & Configuration :wrench:

The following section will provide insight on the installation and configuration of software to enable intrusion detection, intrusion prevention, malware detection, system logging, automation

## Update Automation (**unattended-upgrades**)

Automatic security updates are important to ensure un-patched vulnerabilities are mitigated on a live server. While automatic upgrades can occasionally break things, I'd say its better to patch security holes with slightly more up-keep \_(the task is automated after all) then it is to stay overtly less secure.

To keep the system up-to-date without admin intervention we will install [**unattended-upgrades**](https://wiki.debian.org/UnattendedUpgrades):

```bash
sudo apt-get install unattended-upgrades
```

Open `/etc/apt/apt.conf.d/10periodic`:

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

Open `/etc/apt/apt.conf.d/50unattended-upgrades`:

```bash
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

Add the following to the bottom of the file:

```bash
Unattended-Upgrade::Allowed-Origins {
        "Ubuntu lucid-security";
        "Ubuntu lucid-updates"; # Optionally disable to improve stability
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

> **NOTE:** If anything is detected immediately look up remediation strategies!

## Anti-Virus Scanning (**ClamAV**)

[ClamAV](https://www.clamav.net/) is an anti-virus scanner for Linux systems. It uses **ClamAV-Freshclam** to update virus definitions and **ClamAV-Daemon** keeps the `clamd` process running to speed up scanning.
A necessity for any computer in the modern internet age is a competent anti-virus (while it's only ever as effective as the user's safe browsing practices). **ClamAV** provides just that.

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

[PSAD](https://cipherdyne.org/psad/) is an intrusion prevention tool similar to **Fail2ban** however, while Fail2ban detects and blocks on a application level, **PSAD** blocks on an iptables level via log messages.

> "Fail2BAN scans log files of various applications such as apache, ssh or ftp and automatically bans IPs that show the malicious signs such as automated login attempts. PSAD on the other hand scans iptables and ip6tables log messages (typically /var/log/messages) to detect and optionally block scans and other types of suspect traffic such as DDoS or OS fingerprinting attempts. It's ok to use both programs at the same time because they operate on different level." - [FINESEC](https://serverfault.com/a/447604/289829)

The first step is to install `psad`:

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
-A FORWARD -j LOG --log-tcp-options --log-prefix "[IPTABLES]"
```

Reload `UFW` and `psad`

```bash
sudo ufw reload

sudo psad -R # (case sensitive)
sudo psad --sig-update
sudo psad -H # (case sensitive)
```

## Application Intrusion Detection & Prevention (**Fail2Ban**)

[Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) scans log files and bans IPs that show the malicious signs such as too many password failures, port scanning, searching for exploits, etc.

> **NOTE**: Fail2ban comes well configured out of the box so the additional configuration steps are optional but recommended.

Install `fail2ban` with the following command:

```bash
sudo apt-get install fail2ban
```

Create the file `/etc/fail2ban/jail.local` (not `jail.conf` as it may be overwritten by updates):

```bash
sudo nano /etc/fail2ban/jail.local
```

Add or replace the following in the `/etc/fail2ban/jail.local` file:

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

We then need to open the `/etc/cron.daily/00logwatch` cron file:

```bash
sudo nano /etc/cron.daily/00logwatch
```

Add this line to `/etc/cron.daily/00logwatch`:

```bash
/usr/sbin/logwatch --output mail --mailto <YOUR>@<EMAIL>.com --detail high
```

> **NOTE:** This will enable a daily email to generate with high details and send to whatever email is specified. For this to work properly SNMP should be allowed through the firewall.

# System Stability :triangular_ruler:

Ensuring stability and longevity is the focus here. Ideally with email notifications setup on your server you will know of specific outages, intrusions, or any other major issues that might require an administrator's intervention. If you plan to regularly maintain the server manually then this section will include some relevant commands and information on how to do that.

## Cleaning Installed Packages

If unattended-upgrades is installed the following commands should run automatically given the configuration in this guide was used. Otherwise, these commands should be run from time to time to clean and unused packages from the server.

Execute the following command to automatically remove and clean unused packages:

```bash
sudo apt-get autoremove && sudo apt-get autoclean
```

> **NOTE**: "vm.panic_on_oom=1" line enables panic on OOM; the "kernel.panic=10" line tells the kernel to reboot ten seconds after panicking.

# Guide Automation Script :scroll:

**THIS SECTION AND THE SCRIPT ARE CURRENTLY W.I.P**

This script is intended to act as an automation tool for this guide. As such I highly recommended you read through the guide before executing the script. This script is not meant to supplement the guide, or meant to be done as a final step. Instead this script IS the guide. Please only modify your system **AFTER RUNNING THE SCRIPT**.

The script cannot safely be 100% automated so prompts may appear to request user verification and outputs may display sensitive information for safe-keeping on other systems.

I will not take responsibility for any damage caused by the script.

# Conclusion :wave:

Once everything is said and done, it's time to restart the server:

```bash
sudo shutdown -r now
```

After the dust settles you should have a significantly more secure Linux server box. I hope this guide has helped you and please feel free to reach out to me if you encounter issues.

# Q&A :grey_question:

> Why use this when there's "X"?

You have freewill, I just provide the guide. If there is a better, more up to date, or more concise guide then feel free to link it for other users benefit. I created this guide to help collate my information and learn a little more about various security procedures.

> Who are you?

I'm [Remi Teeple](https://remi.works), a game and software developer from Ottawa Ontario Canada. I like servers and security too.

> Why the name "Your First Minute On A Server"?

YFMOAS was named such because I wanted to compete directly with the much popularized server setup phrase of "My First X On A Server". This is largely done as homage to other guides.

> Do you have any additional resources?

These are the resources that I would normally frequent to get a system secure. Please note that some of the articles are quite dated now. Don't blindly follow any of these as it may result in system instability.

- http://bookofzeus.com/
- https://gist.github.com/lokhman/cc716d2e2d373dd696b2d9264c0287a3
- https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
- https://www.thefanclub.co.za/how-to/how-secure-ubuntu-1604-lts-server-part-1-basics
- https://www.nuharborsecurity.com/ubuntu-server-hardening-guide-2/
- https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys-on-ubuntu-20-04
- https://www.digitalocean.com/community/tutorials/initial-server-setup-with-ubuntu-20-04
- https://plusbryan.com/my-first-5-minutes-on-a-server-or-essential-security-for-linux-servers
- https://www.kmotoko.com/articles/linux-hardening-kernel-parameters-with-sysctl/

> I would like to contribute.
> | |
> I found an issue with the guide.

Please contact me immediately via [remi@teeple.xyz](mailto:remi@teeple.xyz). I am currently in the process of getting a better understanding of GitHub's core systems so I will likely allow contributors in the near future.

> Something broke and I need help!

Please create an issue and describe your problem. I am one man and this is not my day job, nor is it something I deal with frequently but I will attempt to answer any questions.

> Why did you make this?

I made this as a reference for myself to quickly setup servers whenever I need one for a specific project.

> Would this work on a Raspberry Pi?

Yes! In fact majority of this guide was specifically created to cater to my needs when creating Raspberry Pi servers. I'd recommend using this [nifty little tool](https://github.com/Hexxeh/rpi-update) to ensure that you RPI stays up to date firmware wise! Alternatively (and arguable a much safer method for updating firmware) is to use the same tool pre-install from a Raspberry PI OS image. I suggest you keep a Micro SD card kicking around loaded with Raspberry PI OS for this specific reason.

Have more questions? Feel free to ask!

# License :exclamation:

[![CC-BY-SA](https://i.creativecommons.org/l/by-sa/4.0/88x31.png)](#license)
