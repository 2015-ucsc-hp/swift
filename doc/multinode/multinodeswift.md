# Multinode Swift on Amazon EC2

This guide goes through setting up a multi-node Swift installation on an
Amazon Web Services Elastic Cloud (EC2) Cluster. A basic understanding
of AWS EC2 is assumed (setting up and connecting to nodes).

## Preliminary AWS Setup

To begin, we need at least 2 EC2 nodes, one proxy node and one storage
node (more proxy and storage nodes can be added, but this is the minimum
for a multi-node setup) To ensure the success of the installation,
several preliminary steps have to be taken.

#### EC2 Cluster Security Group

To allow Swift traffic to flow freely between the storage nodes and the
proxy nodes (crucial to the operation of Swift), create a new AWS
Security Group and attach it to all of the nodes. Security Groups are a
set of Firewall rules for an AWS node.

1. Create a new security group with no rules called `openstack`

2. Add a rule to the security group allowing all TCP traffic from the
security group `openstack`.

3. Add a rule to the security group allowing all UDP traffic from the
security group `openstack`.

4. Be sure to allow SSH and any other connection ports you may need to
access the server.

AWS allows you to assign networking rules to and from specific security
groups. This helps you allow traffic between each of your nodes.

#### EC2 Nodes

Create your 2 or more AWS EC2 nodes. Ensure that they are all in the
same subnet, in the same region, and be sure to assign the previous
`openstack` security group to each node. Write down the public and
private IPs for each node. Verify that you can connect to each node and
verify that each node can "talk" to the other nodes via their private
IPs.  If this doesn't work, you need to modify the Security group.

## Setup the Storage Nodes

At this point you should have some number of EC2 nodes with their public
and private IPs. Assign one node to be the proxy node, and the rest to
be the storage nodes. For the remainder of this guide we will use the
following variables to refer to the nodes and their private IP
addresses:

	PROXY_IP 		//Private IP of Proxy Node
	STORAGE_1_IP 	//Private IP of First Storage Node
	STORAGE_2_IP 	//Private IP of Second Storage Node
	STORAGE_N_IP	//Private IP of Nth Storage Node

The following steps should be performed on each of the storage nodes in
your cluster.

### Storage Device

In order to setup a swift cluster each storage node requires a separate
storage device. On AWS it is fairly simple to create a new Elastic Block
Store (EBS) device and attach it to an existing EC2 node. The only thing
to consider is that the EBS device must exist in the same region as the
EC2 node. However, for non-performant purposes, it may be sufficient to
create a small loopback device in place an actual cloud block storage
device.

#### Block Storage Device

After attaching an EBS device verify that it is connected:

```shell
	# lsblk
	xvda    202:0    0   8G  0 disk
	└─xvda1 202:1    0   8G  0 part /
	xvdf    202:80   0   1G  0 disk
```
In this case, the root storage device is `xvda`, and the EBS storage
device used for Swift is `xvdf`. Keep track of the device name for each
of your storage nodes. We will use the following variable to denote the
name of the block device:

	BLOCK_DEVICE \\Block device name (ie xvdf)

```shell
    # ## Sets a label of dN, where N is the number
    # mkfs.xfs -f -i size=512 -LBLOCK_DEVICE /dev/BLOCK_DEVICE

    # ## Add label-based fstab entry
    # echo "LABEL=BLOCK_DEVICE  /srv/node/BLOCK_DEVICE  xfs  noatime,nodiratime,logbufs=8,inode64  0  2" >> /etc/fstab

    # ## Create mount point and mount it (all by label)
    # mkdir -p /srv/node/BLOCK_DEVICE
    # mount /srv/node/BLOCK_DEVICE
    # chown -R swift.swift /srv/node/BLOCK_DEVICE
```

#### Loopback Storage Device

To create a loopback storage device for use with Openstack Swift do this.

#### Install and Update Software

```shell
	# apt-get update
	# apt-get dist-upgrade
	# apt-get install \
	    openssh-server gdisk xfsprogs git \
	    build-essential libffi-dev libxml2-dev libxslt1-dev python-dev \
	    python-swiftclient python-pip python-mysqldb
	# apt-get autoremove
```

#### Create Swift User, Directories and set Permissions

```shell
	# useradd -s /usr/sbin/nologin swift
	# mkdir -p /etc/swift /var/cache/swift /srv/node
	# chown -R swift:swift /etc/swift /var/cache/swift
```

#### Install Swift

When installing Swift from Github there are a few things you can choose,
first you can change which repository you clone from, and then you can
decide which version you want to install. The following variables will
determine the repository and the version.

	SWIFT_REPO 		\\repository ie git://github.com/openstack/swift
	SWIFT_VERSION	\\swift version ie 1.12.0
The Swift version can also be the name of a branch in the repository, ie `master`.

```shell
	# git clone SWIFT_REPO
	# cd swift
	# git checkout SWIFT_VERSION
	# python setup.py install
```
Note that installing different repositories and versions of Swift may
require different setup instructions, please refer to repository/version
specific documentation for additional instructions.

## Setup the Proxy Node

## Run Tests

