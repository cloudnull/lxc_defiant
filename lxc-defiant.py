#!/usr/bin/env python
# =============================================================================
# Copyright [2013] [Kevin Carter]
# License Information :
# This software has no warranty, it is provided 'as is'. It is your
# responsibility to validate the behavior of the routines and its accuracy
# using the code provided. Consult the GNU General Public license for further
# details (see GNU General Public License).
# http://www.gnu.org/licenses/gpl.html
# =============================================================================

import argparse
import errno
import grp
import logging
from logging import handlers
import os
import platform
import pwd
import random
import shutil
import spwd
import subprocess


LOG = logging.getLogger('lxc_defiant')


DEFAULT_POLICY_D = """
#!/bin/sh
exit 101
"""


DEFAULT_FSTAB = """
proc   proc  proc    nodev,noexec,nosuid  0 0
sysfs  sys   sysfs   defaults             0 0
"""


DEFAULT_LXC_CONFIG = """
lxc.utsname = %(name)s

lxc.devttydir = %(ttydir)s
lxc.tty = 4
lxc.pts = 1024
lxc.rootfs = %(rootfs)s
lxc.mount  = %(path)s/fstab
lxc.arch = %(arch)s
lxc.cap.drop = sys_module mac_admin
lxc.pivotdir = lxc_putold

# Max ram
lxc.cgroup.memory.limit_in_bytes = %(ram)s
lxc.cgroup.devices.deny = a
# Allow any mknod (but not using the node)
lxc.cgroup.devices.allow = c *:* m
lxc.cgroup.devices.allow = b *:* m
# /dev/null and zero
lxc.cgroup.devices.allow = c 1:3 rwm
lxc.cgroup.devices.allow = c 1:5 rwm
# consoles
lxc.cgroup.devices.allow = c 5:1 rwm
lxc.cgroup.devices.allow = c 5:0 rwm
#lxc.cgroup.devices.allow = c 4:0 rwm
#lxc.cgroup.devices.allow = c 4:1 rwm
# /dev/{,u}random
lxc.cgroup.devices.allow = c 1:9 rwm
lxc.cgroup.devices.allow = c 1:8 rwm
lxc.cgroup.devices.allow = c 136:* rwm
lxc.cgroup.devices.allow = c 5:2 rwm
# rtc
lxc.cgroup.devices.allow = c 254:0 rwm
#fuse
lxc.cgroup.devices.allow = c 10:229 rwm
#tun
lxc.cgroup.devices.allow = c 10:200 rwm
#full
lxc.cgroup.devices.allow = c 1:7 rwm
#hpet
lxc.cgroup.devices.allow = c 10:228 rwm
#kvm
lxc.cgroup.devices.allow = c 10:232 rwm
"""


DEFAULT_SSH_CONFIG = """
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
UseDNS no
"""


DEFAULT_HOSTS = """
127.0.0.1   localhost localhost.localdomain
127.0.1.1   %(hostname)s

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
"""


UBUNTU_INTERFACE_TEMPLATE = """
# User Interface
auto %(interface)s
iface %(interface)s inet static
    address %(address)s
    netmask %(netmask)s
    gateway %(gateway)s
"""


UBUNTU_NETWORK_INTERFACES = """
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

#THIS IS ALWAYS GOING TO BE THE LXC BRIDGE
auto eth0
iface eth0 inet dhcp
"""


UBUNTU_SOURCES = """
deb %(main)s %(release)s universe
deb %(main)s %(release)s-updates universe
deb %(main)s %(release)s-backports main universe

deb %(main)s %(release)s multiverse
deb %(main)s %(release)s-updates multiverse

deb %(main)s %(release)s main restricted
deb %(main)s %(release)s-updates main restricted

deb %(main)s %(release)s-security main restricted
deb %(main)s %(release)s-security universe
deb %(main)s %(release)s-security multiverse
"""


DISTRO_DATA = {
    'ubuntu': {
        'mirrors': {
            'main': 'http://us.archive.ubuntu.com/ubuntu'
        },
        'interface_template': UBUNTU_INTERFACE_TEMPLATE,
        'default_interface': UBUNTU_NETWORK_INTERFACES,
        'interface_file': 'etc/network/interfaces',
        'pkg_source_file': 'etc/apt/sources.list',
        'pkg_sources': UBUNTU_SOURCES,
        'components': 'main,universe,backports',
        'install': "apt-get"
                   " -o Dpkg::Options:='--force-confold'"
                   " -o Dpkg::Options:='--force-confdef'"
                   " install -y",
        'deprecated_releases': [
            'Natty',
            'Oneiric'
        ],
        'lxc_packages': [
            'lxcguest'
        ],
        'groups': [
            'sudo',
            'admin'
        ],
        'upgrade': 'apt-get dist-upgrade -y',
        'update': 'apt-get update',
        'hostname_file': 'etc/hostname',
        'hosts_file': 'etc/hosts',
        'hosts': DEFAULT_HOSTS,
        'ssh_config_file': 'etc/ssh/sshd_config',
        'ssh_config': DEFAULT_SSH_CONFIG,
        'policy_file': 'usr/sbin/policy-rc.d',
        'policy_rcd': DEFAULT_POLICY_D,
        'packages': [
            'ssh',
            'vim'
        ]
    }
}

SUPPORTED_ARCH = ['i386', 'amd64']

ARGS = {
    'debug': {
        'args': [
            '-d',
            '--debug',
        ],
        'required': False,
        'action': 'store_true',
        'help': 'Enable Debug Mode',
    },
    'packages': {
        'args': [
            '-o',
            '--optional-packages',
        ],
        'required': False,
        'type': str,
        'metavar': '',
        'help': 'Install optional Packages on to the system before booting.'
                ' This is a comma seperated list. Simply place one package'
                ' name after another with no spaces.'
                ' Example, apache2,mysql-server,python-dev',
    },
    'max_ram': {
        'args': [
            '-M',
            '--max-ram',
        ],
        'required': False,
        'type': int,
        'metavar': '',
        'default': 512,
        'help': 'Max Ram that the container is allowed to consume. written'
                ' in Megabytes, default is %(default)s',
    },
    'path': {
        'args': [
            '-p',
            '--path',
        ],
        'required': False,
        'type': str,
        'metavar': '',
        'help': 'Installation Path',
    },
    'name': {
        'args': [
            '-n',
            '--name',
        ],
        'required': True,
        'type': str,
        'metavar': '',
        'help': 'Name of Container',
    },
    'flush_cache': {
        'args': [
            '-F',
            '--flush-cache',
        ],
        'action': 'store_true',
        'default': False,
        'help': 'Flush the image Cache',
    },
    'release': {
        'args': [
            '-r',
            '--release',
        ],
        'required': False,
        'default': 'precise',
        'type': str,
        'metavar': '',
        'help': 'Change the Container Distribution Release',
    },
    'binddir': {
        'args': [
            '-L',
            '--bind-dir',
        ],
        'required': False,
        'type': str,
        'metavar': '',
        'action': 'append',
        'help': 'bind a local directory to the container. Every entry should'
                ' be the FULL path to the directory that you want to bind'
                ' within the container. This can be used multiple times.',
    },
    'bindhome': {
        'args': [
            '-b',
            '--bindhome',
        ],
        'required': False,
        'type': str,
        'metavar': '',
        'help': 'bind <user>\'s home into the container.',
    },
    'arch': {
        'args': [
            '-a',
            '--arch',
        ],
        'required': False,
        'choices': SUPPORTED_ARCH,
        'metavar': '',
        'default': 'amd64',
        'help': '%s,' % SUPPORTED_ARCH + ' default %(default)s',
    },
    'auth_key': {
        'args': [
            '-S',
            '--auth-key',
        ],
        'required': False,
        'type': str,
        'metavar': '',
        'help': 'Set the path to authentication key which will be injected'
                ' into the new Container.',
    },
    'username': {
        'args': [
            '-U',
            '--username',
        ],
        'required': False,
        'default': 'defiant',
        'type': str,
        'metavar': '',
        'help': 'Username to create, default is "%(default)s"',

    },
    'password': {
        'args': [
            '-P',
            '--password',
        ],
        'required': False,
        'default': 'defiant',
        'type': str,
        'metavar': '',
        'help': 'Password for new Default user, default is %(default)s',

    },
    'ip_address': {
        'args': [
            '-I',
            '--ip-address',
        ],
        'required': False,
        'metavar': '',
        'type': str,
        'action': 'append',
        'help': 'Add additional IP addresses to the Container, default will'
                ' only use the built in LXC Bridge. This can be used multiple'
                ' times for multiple IP addresses. Format is '
                ' interface=ip=netmask=gateway. NOTE that gateway is optional.'
                ' Example eth0=10.0.0.2=255.255.255.0=10.0.0.1',

    }
}


def logger_setup(name='genastack', debug_logging=False, handler=False):
    """Setup logging for your application

    :param name: ``str``
    :param debug_logging: ``bol``
    :param handler: ``bol``
    :return: ``object``
    """

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s:%(levelname)s => %(message)s"
    )

    log = logging.getLogger(name)

    filehandler = handlers.RotatingFileHandler(
        filename=return_logfile(filename='%s.log' % name),
        maxBytes=51200000,
        backupCount=5
    )

    streamhandler = logging.StreamHandler()
    if debug_logging is True:
        log.setLevel(logging.DEBUG)
        filehandler.setLevel(logging.DEBUG)
        streamhandler.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
        filehandler.setLevel(logging.INFO)
        streamhandler.setLevel(logging.INFO)

    streamhandler.setFormatter(formatter)
    filehandler.setFormatter(formatter)

    log.addHandler(streamhandler)
    log.addHandler(filehandler)

    if handler is True:
        return filehandler
    else:
        return log


def return_logfile(filename):
    """Return a path for logging file.

    IF "/var/log/" does not exist, or you don't have write permissions to
    "/var/log/" the log file will be in your working directory
    Check for ROOT user if not log to working directory.

    :param filename: ``str``
    :return: ``str``
    """

    if os.path.isfile(filename):
        return filename
    else:
        user = os.getuid()
        log_loc = os.path.join('/var', 'log')
        if not user == 0:
            logfile = filename
        else:
            try:
                logfile = os.path.join(log_loc, filename)
            except Exception:
                logfile = '%s' % filename
        return logfile


def mkdir_p(path):
    """'mkdir -p' in Python

    :param path: ``str``
    """
    LOG.info('Looking to see if "%s" needs to be created', path)
    try:
        if not os.path.isdir(path):
            os.makedirs(path)
            LOG.info('Created Directory [ %s ]', path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise OSError(
                'The provided path can not be turned into a directory.'
            )


def cleanup(error, cache, arch):
    """Cleanup system mess on an exception.

    :param error: ``str``
    :param cache: ``str``
    :param arch: ``str``
    """
    dirs = [
        os.path.join(cache, 'partial-%s' % arch),
        os.path.join(cache, 'rootfs-%s' % arch)
    ]
    LOG.exception('An error occurred %s, removing "%s" dirs' % (error, dirs))
    for _dir in dirs:
        if os.path.exists(_dir):
            shutil.rmtree(_dir)


def write_sources(rootfs_path, release, distro):
    """Write teh sources file for the container.

    :param rootfs_path: ``str``
    :param release: ``str``
    :param distro: ``str``
    """

    distro = DISTRO_DATA[distro]
    sources_file = distro.get('pkg_source_file')
    sources = distro.get('pkg_sources')

    if sources is not None:
        sources_vars = distro.pop('mirrors')
        sources_vars['release'] = release
        formatted_sources = str(sources) % sources_vars

        sources_container_file = os.path.join(rootfs_path, sources_file)
        LOG.info('Writing sources file "%s"' % sources_container_file)
        LOG.debug(formatted_sources)
        with open(sources_container_file, 'wb') as sources_file:
            sources_file.write(formatted_sources)


def copy_system(cache, arch, rootfs):
    """Copy the base system into a working directory.

    :param cache: ``str``
    :param arch: ``str``
    :param rootfs: ``str``
    """
    LOG.info('Copying rootfs to %s...' % rootfs)
    mkdir_p(rootfs)
    _rootfs = os.path.join(cache, 'rootfs-%s' % arch)
    commands = [
        'rsync -a %s/ %s/' % (_rootfs, rootfs)
    ]
    _execute_command(commands=commands)


def download_system(cache, arch, release, distro):
    """Download the base system

    :param cache: ``str``
    :param arch: ``str``
    :param release: ``str``
    :param distro: ``str``
    """
    _distro = DISTRO_DATA[distro]
    _packages = _distro.get('packages')
    packages = ','.join(_packages)
    mirrors = _distro.get('mirrors')
    main_mirror = mirrors.get('main')
    LOG.info('installing packages %s' % packages)
    try:
        partial = os.path.join(cache, 'partial-%s' % arch)
        LOG.info('Creating %s', partial)
        mkdir_p(partial)

        LOG.info('Looking to download %s minimal...' % release)

        base_path = os.path.join('/usr', 'sbin')
        q_deboot = os.path.join(base_path, 'qemu-debootstrap')
        if os.path.exists(q_deboot):
            boostrap = q_deboot
        else:
            boostrap = os.path.join(base_path, 'debootstrap')

        components = _distro.get('components')
        commands = [
            '%s --verbose'
            ' --components=%s'
            ' --arch=%s'
            ' --include=%s'
            ' %s %s %s'
            % (boostrap,
               components,
               arch,
               packages,
               release,
               partial,
               main_mirror)
        ]
        _execute_command(commands=commands)

        LOG.info('Installing Updates')
        write_sources(partial, release, distro)

        policy_d = os.path.join(partial, _distro.get('policy_file'))
        update = _distro.get('update')
        upgrade = _distro.get('upgrade')

        LOG.info('Creating temporary policy for container at %s' % policy_d)
        with open(policy_d, 'wb') as f:
            f.write(str(_distro.get('policy_rcd')))

        commands = [
            'chroot %s %s' % (partial, update),
            'chmod +x %s' % policy_d,
            'lxc-unshare -s MOUNT -- chroot "%s"'
            ' %s || { suggest_flush; false; }' % (partial, upgrade),
        ]
        _execute_command(commands=commands, ignore_strerr=True)

        LOG.info('Removing temporary policy for container at %s' % policy_d)
        os.remove(policy_d)

        LOG.info('moving base container configuration in place')
        shutil.move(partial, os.path.join(cache, 'rootfs-%s' % arch))
    except Exception as exp:
        cleanup(exp, cache, arch)


def install_system(rootfs, arch, release, flushcache, distro='ubuntu'):
    """Install the Base Image.

    :param rootfs: ``str``
    :param arch: ``str``
    :param release: ``str``
    :param flushcache: ``bol``
    """
    lock_dir = os.path.join('/var', 'lock' 'subsys')
    mkdir_p(lock_dir)
    lock_file = os.path.join(lock_dir, 'lxc')

    if os.path.exists(lock_file):
        raise SystemExit(
            'Lock File "%s" found, this process can not continue' % lock_file
        )

    with open(lock_file, 'wb') as f:
        f.write('locked')

    try:
        cache = os.path.join('/var', 'cache', 'lxc', release)
        cache_paths = [
            os.path.join(cache, 'partial-%s' % arch),
            os.path.join(cache, 'rootfs-%s' % arch),
        ]
        if flushcache is True:
            LOG.info('Flushing Cache...')
            for path in cache_paths:
                if os.path.exists(path):
                    shutil.rmtree(path)

        LOG.info('Checking cache downloaded in "%s"' % cache_paths[1])
        if not os.path.exists(cache_paths[1]):
            download_system(cache, arch, release, distro)

        LOG.info('Copy %s to %s' % (cache_paths[0], rootfs))
        copy_system(cache, arch, rootfs)
        LOG.info('success')
    finally:
        os.remove(lock_file)


def do_bindhome(rootfs, path, username, distro):
    """If bindhome arg is set, bind local home to the container.

    :param rootfs: ``str``
    :param username: ``str``
    :param distro: ``str``
    """

    def read_file(file_name):
        """Return list from opened file.

        :param file_name: ``str``
        """
        with open(file_name, 'rb') as _f:
            return _f.readlines()

    def check_existing_user(user, file_name):
        """Check for user id conflicts.

        :param user: ``str``
        :param file_name: ``str``
        """
        if not os.path.exists(file_name):
            raise SystemExit(
                'when checking for an existing user the file %s did was not'
                ' found.' % file_name
            )

        for line in read_file(file_name):
            break_out = line.split(':')
            user_name = break_out[0]
            if user == user_name:
                LOG.error(
                    'The user, [ %s ], already exists within the container and'
                    ' you are attempting to bind the home folder of an'
                    ' external user by the same name. this will not work,'
                    ' please select another username.' % user
                )
                raise SystemExit('FAILED to created container.')

    def check_new_id(file_name, id_entry, field):
        """Check for conflicting user id or group id.

        :param file_name: ``str``
        :param id_entry: ``str``
        :param field: ``int``
        """
        if not os.path.exists(file_name):
            raise SystemExit(
                'when checking for duplicate IDs the file %s did was not'
                ' found.' % file_name
            )

        for line in read_file(file_name):
            break_out = line.split(':')
            check_id = int(break_out[field])
            if id_entry == check_id:
                LOG.info(
                    'ID [ %s ] is in use, incrementing and trying again',
                    check_id
                )
                purposed_id = id_entry + 1
                check_new_id(file_name, purposed_id, field)
        else:
            return id_entry

    LOG.info('Binding Local user "%s" to the container', username)

    # Pull known information about the user from passwd
    passwd = os.path.join(rootfs, 'etc', 'passwd')

    # Check to see if the Bind user already exists in the container.
    check_existing_user(username, passwd)
    passwd_data = pwd.getpwnam(username)

    # convert passwd_data to a list
    passwd_list = [i for i in passwd_data.__mul__(1)]

    LOG.info('checking for ID conflicts with user [ %s ]', username)
    user_id = check_new_id(passwd, passwd_data.pw_uid, 2)
    passwd_list[2] = user_id

    LOG.info('checking for ID conflicts with user group [ %s ]', username)
    group_id = check_new_id(passwd, passwd_data.pw_gid, 3)
    passwd_list[3] = group_id

    # Write the new passwd file for the container
    new_passwd = ':'.join([str(i) for i in passwd_list])
    LOG.info('Appending to %s file', passwd)
    LOG.debug(new_passwd)
    with open(passwd, 'ab') as f:
        f.write(new_passwd)

    # Pull known information about the user from shadow
    shadow = os.path.join(rootfs, 'etc', 'shadow')
    shadow_data = spwd.getspnam(username)

    # Write the new shadow_data file for the container
    new_shadow = ':'.join([str(i) for i in shadow_data.__mul__(1)])
    LOG.info('Appending to %s file', shadow)
    LOG.debug(new_shadow)
    with open(shadow, 'ab') as f:
        f.write(new_shadow)

    # Pull known information about the group
    group = os.path.join(rootfs, 'etc', 'group')
    group_data = grp.getgrnam(username)

    # convert group to a list
    group_list = [i for i in group_data.__mul__(1)]
    membership = ','.join(group_list[-1])
    group_list[-1] = membership
    group_list[2] = group_id

    # Write the new group file for the container
    new_group = ':'.join([str(i) for i in group_list])
    LOG.info('Appending to %s file.', group)
    LOG.debug(new_group)
    with open(group, 'ab') as f:
        f.write(new_group)

    user_shell = passwd_data.pw_shell
    if os.path.exists(os.path.join(rootfs, user_shell.lstrip(os.sep))):
        user_bin = user_shell.split(os.sep)
        pkg = user_bin[-1]
        LOG.info('Attempting to install missing shell package [ %s ]', pkg)
        _distro = DISTRO_DATA[distro]
        commands = [
            'chroot %s %s %s' % (rootfs, _distro.get('install'), pkg)
        ]
        _execute_command(commands)

    bind_mount(rootfs, path, passwd_data.pw_dir)


def bind_mount(rootfs, path, local_path):
    """Bind a local path to to the container.

    :param path: ``str``
    :param rootfs: ``str``
    :param local_path: ``str``
    """
    # Extract the relitive path from the provided local path
    relative_path = local_path.strip(os.sep)
    lxc_home = os.path.join(rootfs, relative_path)

    # Create the directory within the container if needed.
    mkdir_p(lxc_home)

    # append to the fstab for the container for the new bind point.
    bind_points = (local_path.rstrip(os.sep), relative_path)
    bind_point = '%s %s none bind 0 0\n' % bind_points
    fstab = os.path.join(path, 'fstab')
    LOG.info('Writing bind point in container [ %s ]', fstab)
    LOG.debug(bind_point)
    with open(fstab, 'ab') as f:
        f.write(bind_point)


def configure_system(distro, rootfs, hostname, username, password,
                     ipaddresses):
    """Perform system configuration.

    :param distro: ``str``
    :param rootfs: ``str``
    :param hostname: ``str``
    :param username: ``str``
    :param password: ``str``
    :param ipaddresses: ``list``
    """

    def _interface_adder(device, address, netmask, gw=None):
        """Add interface entry to interface file."""
        interface_vars = {
            'interface': device,
            'address': address,
            'netmask': netmask,
            'gateway': gw
        }

        template = _distro['interface_template']
        interface = template % interface_vars

        if gw is None:
            interface = interface.replace('gateway', '# gateway')

        LOG.debug(interface)
        return interface

    _distro = DISTRO_DATA[distro]
    interfaces = _distro.get('default_interface')
    if ipaddresses:
        for ip in ipaddresses:
            LOG.info('adding additional IP address %s', ip)
            ip_addr = ip.split('=')
            if len(ip_addr) < 4:
                ip_addr.append(None)
            interfaces += '\n%s' % _interface_adder(*ip_addr)

    interface_file = os.path.join(rootfs, _distro.get('interface_file'))
    LOG.info('writting interface file %s', interface_file)
    with open(interface_file, 'wb') as f:
        f.write(interfaces)

    ssh_file = os.path.join(rootfs, _distro.get('ssh_config_file'))
    LOG.info('writting sshd_config file %s', ssh_file)
    with open(ssh_file, 'wb') as f:
        f.write(str(_distro.get('ssh_config')))

    hostname_file = os.path.join(rootfs, _distro.get('hostname_file'))
    LOG.info('writting hostname file %s', hostname_file)
    with open(hostname_file, 'wb') as f:
        f.write(hostname)

    hosts_file = os.path.join(rootfs, _distro.get('hosts_file'))
    LOG.info('writting hosts file %s', hosts_file)
    with open(hosts_file, 'wb') as f:
        f.write(str(_distro.get('hosts')) % {'hostname': hostname})

    detect = os.path.join(rootfs, 'etc', 'init', 'container-detect.conf')
    if os.path.exists(detect):
        LOG.info('ensuring that our UDEV rules are correct')
        udev_path = os.path.join(rootfs, 'etc', 'udev', 'udev.conf')
        with open(udev_path, 'rb') as f:
            udev_content = f.read()

        with open(udev_path, 'wb') as f:
            changed_udev_content = udev_content.replace('="err"', '=0')
            LOG.debug(changed_udev_content)
            f.write(changed_udev_content)

        tty_template = os.path.join('etc', 'init', 'tty%s.conf')
        for tty in range(5, 6):
            tty_file = os.path.join(rootfs, tty_template % tty)
            if os.path.exists(tty_file):
                LOG.info('removed extra TTY %s', tty_file)
                os.remove(tty_file)

    LOG.info('Creating User %s', username)
    commands = [
        'chroot %s useradd --create-home -s /bin/bash %s'
        % (rootfs, username),
        'echo "%s:%s" | chroot %s chpasswd'
        % (username, password, rootfs)
    ]
    _execute_command(commands)


def copy_configuration(path, rootfs, name, arch, ram, ipaddresses):
    """Move system configuration files in place.

    :param path: ``str``
    :param rootfs: ``str``
    :param name: ``str``
    :param arch: ``str``
    :param ram: ``int``
    :param ipaddresses: ``list``
    """
    lxc_conf = {
        'ttydir': '',
        'arch': arch,
        'path': path,
        'rootfs': rootfs,
        'name': name,
        'ram': (ram * 1024000)
    }

    config_file = os.path.join(path, 'config')
    detect = os.path.join(rootfs, 'etc', 'init', 'container-detect.conf')
    if os.path.exists(detect):
        lxc_conf['ttydir'] = 'lxc'

    # Make sure we have not additional IP addresses to add in
    if not ipaddresses:
        with open(config_file, 'rb') as f:
            open_config = f.read()

        # IF we have EXACTLY one veth network, provide an associated HW addr.
        veth_count = open_config.replace(' ', '').count('network.type=veth')
        if not 'lxc.network.hwaddr' in open_config and veth_count == 1:
            with open(config_file, 'ab') as f:
                mac = (
                    random.randint(0x00, 0x7f),
                    random.randint(0x00, 0xff),
                    random.randint(0x00, 0xff)
                )
                f.write('lxc.network.hwaddr = 00:16:3e:%s:%s:%s' % mac)

    with open(config_file, 'ab') as f:
        f.write(DEFAULT_LXC_CONFIG % lxc_conf)

    fstab_file = os.path.join(path, 'fstab')
    with open(fstab_file, 'wb') as f:
        f.write(DEFAULT_FSTAB)


def post_process(rootfs, release, distro, install_packages, bindhome, path,
                 binddir):
    """Finalize the new container.

    :param rootfs: ``str``
    :param release: ``str``
    :param distro: ``str``
    :param install_packages: ``list``
    """

    detect = os.path.join(rootfs, 'etc', 'init', 'container-detect.conf')
    if os.path.exists(detect):
        resolve_conf_bak = os.path.join(rootfs, 'etc', 'resolv.conf')
        shutil.copyfile(resolve_conf_bak, '%s.lxcbak' % resolve_conf_bak)

        _distro = DISTRO_DATA[distro]
        update = _distro.get('update')
        install = _distro.get('install')
        _lxc_packages = _distro.get('lxc_packages')
        commands = [
            'chroot %s %s' % (rootfs, update)
        ]

        d_list = _distro.get('deprecated_releases')
        if d_list is None:
            d_list = []

        if _lxc_packages and release in d_list:
            lxc_packages = ' '.join(_lxc_packages)
            LOG.info('Installing Some Base packages, %s', lxc_packages)
            commands.append(
                'chroot %s %s %s' % (rootfs, install, lxc_packages)
            )

        base_packages = _distro.get('base_packages')
        if base_packages is None:
            base_packages = []

        if install_packages is not None:
            for pkg in install_packages.split(','):
                base_packages.append(pkg)

        if base_packages:
            _base_packages = ' '.join(base_packages)
            commands.append(
                'chroot %s %s %s' % (rootfs, install, _base_packages)
            )

        _execute_command(commands)

    # if /run/shm remove /dev/shm
    link_shm = os.path.join(rootfs, 'dev', 'shm')
    checks = [
        os.path.islink(link_shm) is False,
        os.path.isdir(link_shm) is True,
        os.path.exists(link_shm) is True
    ]

    if all(checks):
        shutil.move(link_shm, '%s.lxcbak' % link_shm)
        real_shm_path = os.path.join('/run', 'shm')
        os.symlink(real_shm_path, link_shm)

    if bindhome is not None:
        do_bindhome(rootfs, path, bindhome, distro)

    if binddir is not None:
        for local_path in binddir:
            if not os.path.exists(local_path):
                LOG.error(
                    'Local bind path does not exist "%s". Please confirm the'
                    ' local path and try again.', local_path
                )
                raise SystemExit('ERROR')
            bind_mount(rootfs, path, local_path)


def finallize_user(rootfs, username, authkey, distro):
    """Finallize the new system user for the container.

    :param rootfs: ``str``
    :param username: ``str``
    :param authkey: ``str``
    :param distro: ``str``
    """

    _distro = DISTRO_DATA[distro]

    # Create our base groups and users
    commands = []
    for group in _distro.get('groups'):
        commands.append(
            'chroot %s groupadd --system %s >/dev/null 2>&1 || true'
            % (rootfs, group)
        )
        commands.append(
            'chroot %s adduser %s %s >/dev/null 2>&1 || true'
            % (rootfs, username, group)
        )
    else:
        _execute_command(commands)

    # Inject an authkey if provided.
    if authkey is not None and os.path.exists(authkey):
        user_home = os.path.join('home', username, '.ssh')
        root_user_path = os.path.join(rootfs, user_home)

        mkdir_p(root_user_path)

        LOG.info('Reading SSH Key %s', authkey)
        with open(authkey, 'rb') as f:
            key = f.read()

        authorized_keys = os.path.join(root_user_path, 'authorized_keys')
        LOG.info('Injecting Key into Container at %s', authorized_keys)
        LOG.debug(key)
        with open(authorized_keys, 'ab') as f:
            f.write(key)

        key_kwargs = {
            'rootfs': rootfs,
            'username': username,
            'user_home': user_home
        }
        commands = [
            'chroot %(rootfs)s chown -R %(username)s "/%(user_home)s"'
            % key_kwargs
        ]
        _execute_command(commands)


def arg_parser():
    """Setup argument Parsing."""
    parser = argparse.ArgumentParser(
        usage='%(prog)s',
        description='defiant Infra LXC Containers',
        epilog='Licensed "GPLv3+"')

    for service in sorted(ARGS.keys()):
        parser.add_argument(
            *ARGS[service].pop('args'),
            **ARGS[service]
        )

    return parser


def _execute_command(commands, env=None, execute='/bin/bash', debug=False,
                     ignore_strerr=False):
    """Execute a list of commands.

    All commands executed will check for a return code of non-Zero.
    If a non-Zero return code is found an exception will be raised.

    :param commands: ``list``
    :param env: ``dict``
    :param execute: ``str``
    :param debug: ``bol``
    """

    if debug is True:
        output = None
    else:
        output = open(os.devnull, 'wb')

    if ignore_strerr is True:
        error_output = open(os.devnull, 'wb')
    else:
        error_output = None

    for command in commands:
        LOG.info('COMMAND: [ %s ]' % command)
        subprocess.check_call(
            command,
            shell=True,
            env=env,
            stderr=error_output,
            stdout=output,
            executable=execute
        )


def _distro_check():
    """Return the name of the distro based on what we can find."""
    distro = platform.linux_distribution()
    distro = [d.lower() for d in distro]

    if 'ubuntu' in distro:
        return 'ubuntu'
    elif 'debian' in distro:
        return 'debian'
    elif 'redhat' in distro:
        return 'redhat'
    elif 'centos' in distro:
        return 'centos'
    elif 'suse' in distro:
        return 'suse'
    else:
        raise SystemExit('Distro [ %s ] is unsupported.' % distro)


def main():
    """Run the main container Template."""
    args = arg_parser().parse_args()
    logger_setup(name='lxc_defiant', debug_logging=args.debug)

    if os.getuid() is not 0:
        raise SystemExit('To use this template you must be ROOT')

    rootfs = os.path.join(args.path, 'rootfs')
    distro = _distro_check()

    # Install the system
    LOG.info('begining container installation')
    install_system(
        rootfs, args.arch, args.release, args.flush_cache, distro
    )

    # Configure the system
    LOG.info('configuring container')
    configure_system(
        distro, rootfs, args.name, args.username,
        args.password, args.ip_address
    )

    # Copy the configuration to the container
    LOG.info('copying configuring for the new container')
    copy_configuration(
        args.path, rootfs, args.name, args.arch, args.max_ram, args.ip_address
    )

    # Set post process
    LOG.info('post Processing new container')
    post_process(
        rootfs, args.release, distro, args.optional_packages, args.bindhome,
        args.path, args.bind_dir
    )

    LOG.info('finalizing new container default user')
    finallize_user(rootfs, args.username, args.auth_key, distro)

    message = """
    ####  THIS INFORMATION IS ONLY AVAILABLE THIS ONE TIME!  ####

      The default user is '%s' with password '%s'
      Use the 'sudo' command to run tasks as root in the container.

    ####  THIS INFORMATION IS ONLY AVAILABLE THIS ONE TIME!  ####
    """ % (args.username, args.password)
    print(message)

if __name__ == '__main__':
    main()
