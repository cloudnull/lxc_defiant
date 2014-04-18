Defiant, LXC Container Template
###############################
:date: 2014-03-20
:tags: lxc, containers, template, defiant
:category: \*nix
:description: An extensible LXC container Template


This template was created to allow you to create a better LXC container.  The
container template has many options which enhance standard container creation.
This template was built using the ``lxc-ubuntu`` template as a model for
container creation therefore some of the decisions I have made regarding the
implementation and layout may make additional operating system deployment
impossible.

This template is new and while it's working very well the API may be refactored
to add additional features and or compatibility.


Installing the Template
~~~~~~~~~~~~~~~~~~~~~~~

To use this container template move it into the global templates directory


On LXC > 1.0.0

.. code-block:: bash

  cp lxc-defiant.py /usr/share/lxc/templates/lxc-defiant
  chmod +x /usr/share/lxc/templates/lxc-defiant

  cp defiant.common.conf /usr/share/lxc/config/defiant.common.conf


Usage
~~~~~

Here is an example LXC create command using the new template. Note that if
you are using LXC < 1.0.0 the file ``/etc/lxc/default.conf`` may be named
``/etc/lxc/lxc.conf``.

.. code-block:: bash

    lxc-create -n capt_container \
               -t defiant \
               -f /etc/lxc/default.conf \
               --fstype ext4 \
               --fssize 5G \
               -- \
               --username capt_user \
               --password capt_password \
               --bindhome "checkov" \
               --bind-dir /path/to/bind/dir \
               --optional-packages python-dev,curl,wget


Overview
~~~~~~~~

Here is a synopsis on what we're doing:

- New LXC container is being created with a name "capt_container"

- The template being used is "defiant"

- The container configuration file is "/etc/lxc/lxc.conf"

- The container will have an EXT4 file system

- The container will have 5GB of storage

- A user will be created with the name "capt_user"

- The new user "capt_user" will have a password "capt_password"

- The local user "checkov" will be created with the home folder bound within
  the container.

- optional packages python-dev, curl, and wget will be installed into the
  container before it is started.


Once the container is built the password and username will be flashed
on the screen. Write this down!  If you loose it it will not be retrievable 
without messing with the container itself. When read start your new container.


Command Line options
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    optional arguments:
      -h, --help            show this help message and exit
      -a , --arch           ['i386', 'amd64'], default amd64
      -S , --auth-key       Set the path to authentication key which will be
                            injected into the new Container.
      -L , --bind-dir       bind a local directory to the container. Every entry
                            should be the FULL path to the directory that you want
                            to bind within the container. This can be used
                            multiple times. If you provide a target path in your
                            command the specified directory will be bound to the
                            provided path. Example usage: -L /tmp -L
                            /var/log/container_logs=/var/log
      -b , --bindhome       bind <user>'s home into the container.
      -d, --debug           Enable Debug Mode
      -F, --flush-cache     Flush the image Cache
      -I , --ip-address     Add additional IP addresses to the Container, default
                            will only use the built in LXC Bridge. This can be
                            used multiple times for multiple IP addresses. Format
                            is interface=ip=netmask=gateway. NOTE that gateway is
                            optional. Example eth0=10.0.0.2=255.255.255.0=10.0.0.1
      -M , --max-ram        Max Ram that the container is allowed to consume.
                            written in Megabytes, default is 512
      -n , --name           Name of Container
      -o , --optional-packages
                            Install optional Packages on to the system before
                            booting. This is a comma seperated list. Simply place
                            one package name after another with no spaces.
                            Example, apache2,mysql-server,python-dev
      -P , --password       Password for new Default user, default is defiant
      -p , --path           Installation Path
      -r , --release        Change the Container Distribution Release
      --rootfs              Define the rootfs
      -U , --username       Username to create, default is "defiant"

    Licensed "GPLv3+"


NOTICE
~~~~~~

This template presently only supports the Ubuntu minimal image. While the
template has been designed to work with multiple distributions I have not
gotten around to adding them as of yet.

This template has only been tested on a host running Ubuntu 12.04 - 13.10
with LXC 0.7.5 - 1.0.1


License
-------

License:
  Copyright [2014] [Kevin Carter]

  License Information :
  This software has no warranty, it is provided 'as is'. It is your
  responsibility to validate the behavior of the routines and its accuracy
  using the code provided. Consult the GNU General Public license for further
  details (see GNU General Public License).
  http://www.gnu.org/licenses/gpl.html



