# Metasploit

The custom Metasploit Framework modules.

* [Requirements](#requirements)
* [Package](#package)
* [Vulnerabilities](#vulnerabilities)
* [Modules](#modules)

## Requirements

Some modules need packages not installed in the metasploit:

* [zero_length_headers_leak](modules/auxiliary/dos/http/zero_length_headers_leak.rb)
  * [net-http2](https://rubygems.org/gems/net-http2/versions/0.18.2)

[How to add and update gems in metasploit framework](https://github.com/rapid7/metasploit-framework/wiki/How-to-add-and-update-gems-in-metasploit-framework)

## Packages

### Metasploit

Apply changings and install Metasploit Framework only [ArchLinux](https://www.archlinux.org/) distribution.

```sh
cd packages/metasploit
makepkg -rsi
```

### Armitage

Apply changings and install Armitage only [ArchLinux](https://www.archlinux.org/) distribution.

```sh
cd packages/armitager
makepkg -rsi
```

> Note: Armitage requires Metasploit service running, and database configuration

```sh
cp /usr/share/metasploit/database.yml.sample $HOME/.msf4/database.yml

msfconsole
> db_status

sudo systemctl start docker.service
sudo systemctl start metasploit.service
```

## Vulnerabilities

Reproduces vulnerabilities to test locally.

## Modules

Custom modules for Metasploit Framework

```sh
rm -r $HOME/.msf4/modules
ln -s /your/path/to/this/repository/modules $HOME/.msf4/modules
```
