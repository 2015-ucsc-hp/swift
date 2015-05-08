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

```bash
	# lsblk
	xvda    202:0    0   8G  0 disk
	└─xvda1 202:1    0   8G  0 part /
	xvdf    202:80   0   1G  0 disk
```
In this case

#### Loopback Storage Device

To create a loopback storage device for use with Openstack Swift.


## Setup the Proxy Node

## Run Tests

