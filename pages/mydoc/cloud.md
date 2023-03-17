---
title: Cloud
sidebar: mydoc_sidebar
permalink: cloud.html
folder: mydoc
---


## recon


Cloud DNS Enumeration

```
python cloudflair.py -d example.com
```

Cloud Service Enumeration

```
cloudmapper collect --account example_account
```


Cloud Storage Bucket Enumeration

```
python GCPBucketBrute.py -d example.com -p projects.txt -n
```

Cloud Application Enumeration

```
nmap -p 80,443,8080 example.com
```

Cloud Metadata Enumeration

```
python inspy.py -d example.com
```

Cloud Provider Enumration

```
python3 cloudenum.py -u example.com
```


## AWS

List all instances in a region:

```
aws ec2 describe-instances
```

Create a new EC2 instance:

```
aws ec2 run-instances --image-id ami-0c55b159cbfafe1f0 --count 1 --instance-type t2.micro --key-name my-key-pair --security-group-ids sg-903004f8 --subnet-id subnet-6e7f829e --associate-public-ip-address
```

Create a new S3 bucket:

```
aws s3 mb s3://my-bucket-name
```

## Google Cloud SDK

List all instances in a project:

```
gcloud compute instances list
```

Create a new VM instance:

```
gcloud compute instances create example-instance --machine-type=n1-standard-1 --image-project=debian-cloud --image-family=debian-10 --zone us-central1-a
```

Create a new Cloud Storage bucket:

```
gsutil mb -p my-project-id gs://my-bucket-name
```

## Microsoft Azure CLI 


List all virtual machines in a resource group:


```
az vm list -g my-resource-group
```

Create a new virtual machine:


```
az vm create --resource-group my-resource-group --name my-vm --image UbuntuLTS --admin-username azureuser --generate-ssh-keys
```

Create a new storage account:

```
az storage account create --name mystorageaccount --resource-group myresourcegroup --location eastus --sku Standard_LRS
```


## S3 bucket misconfigurations


Check if a bucket is publicly accessible:

```
aws s3api get-bucket-acl --bucket [bucket-name]
```

Check if bucket logging is enabled:

```
aws s3api get-bucket-logging --bucket [bucket-name]
```

Check if server-side encryption is enabled

```
aws s3api get-bucket-encryption --bucket [bucket-name]
```

## IAM misconfigurations

Check for unused IAM users and roles:

```
aws iam list-users and aws iam list-roles
```

Check for unused IAM access keys: 

```
aws iam list-access-keys --user-name [user-name]
```

Check for unused IAM permissions:

```
aws iam get-policy --policy-arn [policy-arn]
```


## Security Group misconfigurations


Check for open ports in a security group:

```
aws ec2 describe-security-groups --group-id [security-group-id]
```

Check for unrestricted outbound traffic:

```
aws ec2 describe-security-groups --filters Name=ip-permission.protocol,Values=all Name=ip-permission.cidr,Values=0.0.0.0/0
```

Check for unrestricted inbound traffic from specific IP ranges:

```
aws ec2 describe-security-groups --filters Name=ip-permission.protocol,Values=tcp Name=ip-permission.cidr,Values=[ip-range]/32
```


## VPC misconfigurations

Check for unused VPCs:

```
aws ec2 describe-vpcs
```

Check for unrestricted peering:

```
aws ec2 describe-vpc-peering-connections --filters Name=status-code,Values=active Name=requester-vpc-info.vpc-id,Values=[vpc-id]
```




{% include links.html %}
