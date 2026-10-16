"""Provision and manage an inspect_ranges remote development box on EC2.

Run with `inspect-ranges devbox <command>`. See `devbox/README.md` for the security model and prerequisites.
"""

import base64
import getpass
import gzip
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from functools import cached_property
from pathlib import Path
from typing import Any

import boto3
import click
from botocore.exceptions import ClientError

PROJECT = "inspect-ranges-devbox"
REPO = "meridianlabs-ai/inspect_ranges"
REPO_URL = f"https://github.com/{REPO}.git"
VPC_CIDR = "10.42.0.0/16"
UBUNTU_AMI_PARAM = (
    "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
)
SSM_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
# nested virtualization is only offered on 8th-generation Intel types and their flex variants
NESTED_VIRT_TYPES = re.compile(r"^(c8i|m8i|r8i)(-flex)?\.")
# metal instances run KVM natively, no launch-time CPU option needed (x86 only: the AMI is amd64)
METAL_TYPES = re.compile(r"\.metal(-\d+xl)?$")

HERE = Path(__file__).resolve().parent
SSH_DIR = Path.home() / ".ssh"
SSH_KEY = SSH_DIR / "inspect_ranges_devbox"
SSH_CONFIG_D = SSH_DIR / "config.d"
SSH_KNOWN_HOSTS_D = SSH_DIR / "known_hosts.d"


def log(message: str) -> None:
    # stderr throughout: `proxy` owns stdout as the SSH transport
    click.echo(message, err=True)


class Devbox:
    """AWS resources for one named devbox, plus the infrastructure all devboxes in the account share."""

    def __init__(self, name: str, profile: str | None, region: str | None) -> None:
        self.name = name
        self.profile = profile
        self._region = region

    # created on first use, so `<command> --help` works without AWS configuration

    @cached_property
    def session(self) -> boto3.Session:
        session = boto3.Session(profile_name=self.profile, region_name=self._region)
        if not session.region_name:
            raise click.UsageError(
                "No AWS region configured; pass --region or set one in your AWS profile."
            )
        return session

    @property
    def region(self) -> str:
        region = self.session.region_name
        assert region is not None  # enforced when the session is created
        return region

    @cached_property
    def ec2(self) -> Any:
        return self.session.client("ec2")

    @cached_property
    def iam(self) -> Any:
        return self.session.client("iam")

    @cached_property
    def ssm(self) -> Any:
        return self.session.client("ssm")

    @cached_property
    def cloudwatch(self) -> Any:
        return self.session.client("cloudwatch")

    # --- naming ---------------------------------------------------------------

    @property
    def host_alias(self) -> str:
        return PROJECT if self.name == default_name() else f"{PROJECT}-{self.name}"

    @property
    def cli_options(self) -> str:
        """Global options that re-address this devbox, for commands we tell the user to run."""
        options = f" --region {self.region}"
        if self.profile:
            options += f" --profile {self.profile}"
        if self.name != default_name():
            options += f" --name {self.name}"
        return options

    @property
    def alarm_name(self) -> str:
        return f"{PROJECT}-{self.name}-idle-backstop"

    def tags(self, name: str, **extra: str) -> list[dict[str, str]]:
        return [
            {"Key": "Project", "Value": PROJECT},
            {"Key": "Name", "Value": name},
        ] + [{"Key": k, "Value": v} for k, v in extra.items()]

    def tag_spec(
        self, resource_type: str, name: str, **extra: str
    ) -> list[dict[str, Any]]:
        return [{"ResourceType": resource_type, "Tags": self.tags(name, **extra)}]

    # --- instance lookup ------------------------------------------------------

    def instance(self) -> dict[str, Any] | None:
        instances = self._instances([{"Name": "tag:DevboxName", "Values": [self.name]}])
        if len(instances) > 1:
            ids = ", ".join(i["InstanceId"] for i in instances)
            raise click.ClickException(
                f"Multiple devbox instances named '{self.name}': {ids}"
            )
        return instances[0] if instances else None

    def all_instances(self) -> list[dict[str, Any]]:
        return self._instances([])

    def _instances(self, filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        live = ["pending", "running", "stopping", "stopped"]
        pages = self.ec2.get_paginator("describe_instances").paginate(
            Filters=[
                {"Name": "tag:Project", "Values": [PROJECT]},
                {"Name": "instance-state-name", "Values": live},
                *filters,
            ]
        )
        return [
            i for page in pages for r in page["Reservations"] for i in r["Instances"]
        ]

    def require_instance(self) -> dict[str, Any]:
        instance = self.instance()
        if instance is None:
            raise click.ClickException(
                f"No devbox named '{self.name}' in {self.region}; run `up` first."
            )
        return instance

    # --- shared infrastructure ------------------------------------------------

    def _find_one(
        self, describe: str, key: str, filters: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        items = getattr(self.ec2, describe)(
            Filters=[{"Name": "tag:Project", "Values": [PROJECT]}, *filters]
        )[key]
        return items[0] if items else None

    def ensure_vpc(self) -> str:
        vpc = self._find_one("describe_vpcs", "Vpcs", [])
        if vpc:
            return vpc["VpcId"]
        log(f"Creating VPC {VPC_CIDR}")
        vpc_id = self.ec2.create_vpc(
            CidrBlock=VPC_CIDR, TagSpecifications=self.tag_spec("vpc", PROJECT)
        )["Vpc"]["VpcId"]
        self.ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
        self.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        self.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        return vpc_id

    def ensure_internet_route(self, vpc_id: str) -> None:
        igw = self._find_one("describe_internet_gateways", "InternetGateways", [])
        if igw is None:
            log("Creating internet gateway")
            igw = self.ec2.create_internet_gateway(
                TagSpecifications=self.tag_spec("internet-gateway", PROJECT)
            )["InternetGateway"]
        if not igw.get("Attachments"):
            self.ec2.attach_internet_gateway(
                InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id
            )
        main_table = self.ec2.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]
        if not any(
            r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in main_table["Routes"]
        ):
            self.ec2.create_route(
                RouteTableId=main_table["RouteTableId"],
                DestinationCidrBlock="0.0.0.0/0",
                GatewayId=igw["InternetGatewayId"],
            )

    def candidate_zones(self, vpc_id: str, instance_type: str) -> list[str]:
        """Zones offering `instance_type`, those where we already have a subnet first."""
        offered = sorted(
            o["Location"]
            for o in self.ec2.describe_instance_type_offerings(
                LocationType="availability-zone",
                Filters=[{"Name": "instance-type", "Values": [instance_type]}],
            )["InstanceTypeOfferings"]
        )
        if not offered:
            raise click.ClickException(
                f"{instance_type} is not offered in any availability zone in {self.region}."
            )
        existing = {s["AvailabilityZone"] for s in self._subnets(vpc_id)}
        return sorted(offered, key=lambda az: az not in existing)

    def ensure_subnet(self, vpc_id: str, az: str) -> str:
        for subnet in self._subnets(vpc_id):
            if subnet["AvailabilityZone"] == az:
                return subnet["SubnetId"]
        # one /24 per zone, numbered by the zone's letter
        cidr = f"10.42.{ord(az[-1]) - ord('a')}.0/24"
        log(f"Creating subnet {cidr} in {az}")
        return self.ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az,
            TagSpecifications=self.tag_spec("subnet", f"{PROJECT}-{az}"),
        )["Subnet"]["SubnetId"]

    def _subnets(self, vpc_id: str) -> list[dict[str, Any]]:
        return self.ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]

    def ensure_security_group(self, vpc_id: str) -> str:
        sg = self._find_one(
            "describe_security_groups",
            "SecurityGroups",
            [{"Name": "vpc-id", "Values": [vpc_id]}],
        )
        if sg:
            return sg["GroupId"]
        log("Creating security group (no inbound; egress 80/443 only)")
        sg_id = self.ec2.create_security_group(
            GroupName=PROJECT,
            Description="inspect_ranges devbox: no inbound (access via SSM); egress HTTP/HTTPS only",
            VpcId=vpc_id,
            TagSpecifications=self.tag_spec("security-group", PROJECT),
        )["GroupId"]
        # replace the default allow-all egress. DNS (VPC resolver) and time sync
        # (169.254.169.123) are link-local services security groups don't filter
        self.ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        self.ec2.authorize_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
                for port in (80, 443)
            ],
        )
        return sg_id

    def ensure_instance_profile(self) -> str:
        try:
            self.iam.get_role(RoleName=PROJECT)
        except self.iam.exceptions.NoSuchEntityException:
            log("Creating IAM role (AmazonSSMManagedInstanceCore only)")
            trust = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            self.iam.create_role(
                RoleName=PROJECT,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description="inspect_ranges devbox: SSM access only",
                Tags=self.tags(PROJECT),
            )
            self.iam.attach_role_policy(RoleName=PROJECT, PolicyArn=SSM_POLICY_ARN)
        try:
            profile = self.iam.get_instance_profile(InstanceProfileName=PROJECT)[
                "InstanceProfile"
            ]
        except self.iam.exceptions.NoSuchEntityException:
            profile = self.iam.create_instance_profile(
                InstanceProfileName=PROJECT, Tags=self.tags(PROJECT)
            )["InstanceProfile"]
        if not profile["Roles"]:
            self.iam.add_role_to_instance_profile(
                InstanceProfileName=PROJECT, RoleName=PROJECT
            )
        return PROJECT

    # --- instance lifecycle ---------------------------------------------------

    def launch(
        self,
        instance_type: str,
        volume_size: int,
        iops: int,
        throughput: int,
        idle_minutes: int,
    ) -> dict[str, Any]:
        vpc_id = self.ensure_vpc()
        self.ensure_internet_route(vpc_id)
        zones = self.candidate_zones(vpc_id, instance_type)
        sg_id = self.ensure_security_group(vpc_id)
        profile_name = self.ensure_instance_profile()

        ami_id = self.ssm.get_parameter(Name=UBUNTU_AMI_PARAM)["Parameter"]["Value"]
        root_device = self.ec2.describe_images(ImageIds=[ami_id])["Images"][0][
            "RootDeviceName"
        ]
        log(f"Launching {instance_type} from {ami_id}")

        params: dict[str, Any] = dict(
            ImageId=ami_id,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            # IMDSv2 only, and a hop limit of 1 so containers and VMs on the box can't reach it
            MetadataOptions={
                "HttpEndpoint": "enabled",
                "HttpTokens": "required",
                "HttpPutResponseHopLimit": 1,
                "InstanceMetadataTags": "disabled",
            },
            BlockDeviceMappings=[
                {
                    "DeviceName": root_device,
                    "Ebs": {
                        "VolumeSize": volume_size,
                        "VolumeType": "gp3",
                        "Iops": iops,
                        "Throughput": throughput,
                        "Encrypted": True,
                        "DeleteOnTermination": True,
                    },
                }
            ],
            IamInstanceProfile={"Name": profile_name},
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "Groups": [sg_id],
                    # outbound only: the security group admits nothing inbound
                    "AssociatePublicIpAddress": True,
                    "DeleteOnTermination": True,
                }
            ],
            # in-guest `shutdown` stops rather than terminates, which is how idle auto-stop works
            InstanceInitiatedShutdownBehavior="stop",
            DisableApiTermination=True,
            UserData=user_data(ssh_public_key(), idle_minutes),
            TagSpecifications=[
                *self.tag_spec(
                    "instance", f"{PROJECT}-{self.name}", DevboxName=self.name
                ),
                *self.tag_spec(
                    "volume", f"{PROJECT}-{self.name}", DevboxName=self.name
                ),
            ],
        )
        # metal instances have KVM natively; CpuOptions is invalid for them
        if not METAL_TYPES.search(instance_type):
            params["CpuOptions"] = {"NestedVirtualization": "enabled"}
        # capacity for large 8i types varies by zone, so fall through the zones that offer it
        for az in zones:
            params["NetworkInterfaces"][0]["SubnetId"] = self.ensure_subnet(vpc_id, az)
            try:
                return self._run_instance(params)
            except ClientError as ex:
                if (
                    ex.response.get("Error", {}).get("Code")
                    != "InsufficientInstanceCapacity"
                ):
                    raise
                log(f"No {instance_type} capacity in {az}; trying the next zone")
        raise click.ClickException(
            f"No {instance_type} capacity in any zone in {self.region}; try again later or another type."
        )

    def _run_instance(self, params: dict[str, Any]) -> dict[str, Any]:
        # a just-created instance profile takes a few seconds to become usable by EC2
        for attempt in range(12):
            try:
                return self.ec2.run_instances(**params)["Instances"][0]
            except ClientError as ex:
                if "Invalid IAM Instance Profile" not in str(ex) or attempt == 11:
                    raise
                time.sleep(5)
        raise AssertionError("unreachable")

    def start(self, instance: dict[str, Any] | None = None) -> dict[str, Any]:
        # `up` passes the instance it just launched: tag-filtered lookups lag a new instance
        instance = instance or self.require_instance()
        instance_id = instance["InstanceId"]
        self.ec2.get_waiter("instance_exists").wait(InstanceIds=[instance_id])
        state = instance["State"]["Name"]
        if state == "stopping":
            log("Waiting for the instance to finish stopping")
            self.ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
            state = "stopped"
        if state == "stopped":
            log(f"Starting {instance_id}")
            self.ec2.start_instances(InstanceIds=[instance_id])
        self.ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
        self.wait_for_ssm(instance_id)
        return instance

    def wait_for_ssm(self, instance_id: str, timeout: int = 600) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            info = self.ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )["InstanceInformationList"]
            if info and info[0]["PingStatus"] == "Online":
                return
            time.sleep(5)
        raise click.ClickException(
            f"{instance_id} did not come online in SSM within {timeout}s."
        )

    def put_backstop_alarm(self, instance_id: str, hours: int) -> None:
        if hours <= 0:
            self.cloudwatch.delete_alarms(AlarmNames=[self.alarm_name])
            return
        # independent of the on-box idle check, so a broken or disabled check can't leave the box running
        self.cloudwatch.put_metric_alarm(
            AlarmName=self.alarm_name,
            AlarmDescription=f"Stop devbox '{self.name}' after {hours}h of near-zero CPU",
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            Statistic="Average",
            Period=3600,
            EvaluationPeriods=hours,
            Threshold=2.0,
            ComparisonOperator="LessThanThreshold",
            TreatMissingData="notBreaching",
            AlarmActions=[f"arn:aws:automate:{self.region}:ec2:stop"],
            Tags=self.tags(self.alarm_name),
        )

    def destroy_shared(self) -> None:
        vpc = self._find_one("describe_vpcs", "Vpcs", [])
        if vpc:
            vpc_id = vpc["VpcId"]
            for sg in self.ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )["SecurityGroups"]:
                if sg["GroupName"] != "default":
                    self.ec2.delete_security_group(GroupId=sg["GroupId"])
            for subnet in self.ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )["Subnets"]:
                self.ec2.delete_subnet(SubnetId=subnet["SubnetId"])
            for igw in self.ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )["InternetGateways"]:
                self.ec2.detach_internet_gateway(
                    InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id
                )
                self.ec2.delete_internet_gateway(
                    InternetGatewayId=igw["InternetGatewayId"]
                )
            self.ec2.delete_vpc(VpcId=vpc_id)
            log(f"Deleted VPC {vpc_id}")
        try:
            profile = self.iam.get_instance_profile(InstanceProfileName=PROJECT)[
                "InstanceProfile"
            ]
            for role in profile["Roles"]:
                self.iam.remove_role_from_instance_profile(
                    InstanceProfileName=PROJECT, RoleName=role["RoleName"]
                )
            self.iam.delete_instance_profile(InstanceProfileName=PROJECT)
        except self.iam.exceptions.NoSuchEntityException:
            pass
        try:
            self.iam.detach_role_policy(RoleName=PROJECT, PolicyArn=SSM_POLICY_ARN)
            self.iam.delete_role(RoleName=PROJECT)
            log("Deleted IAM role and instance profile")
        except self.iam.exceptions.NoSuchEntityException:
            pass

    # --- ssh ------------------------------------------------------------------

    def write_ssh_config(self, instance_id: str) -> None:
        proxy = [
            sys.executable,
            "-m",
            "inspect_ranges",
            "devbox",
            "--name",
            self.name,
            "--region",
            self.region,
        ]
        if self.profile:
            proxy += ["--profile", self.profile]
        proxy += ["proxy", "%p"]

        SSH_CONFIG_D.mkdir(mode=0o700, parents=True, exist_ok=True)
        SSH_KNOWN_HOSTS_D.mkdir(mode=0o700, parents=True, exist_ok=True)
        (SSH_CONFIG_D / self.host_alias).write_text(
            f"""# written by `inspect-ranges devbox`
Host {self.host_alias}
  HostName {instance_id}
  User ubuntu
  IdentityFile {SSH_KEY}
  IdentitiesOnly yes
  ForwardAgent no
  StrictHostKeyChecking accept-new
  UserKnownHostsFile {self.known_hosts_file}
  ServerAliveInterval 60
  ServerAliveCountMax 5
  ProxyCommand {shlex.join(proxy)}
"""
        )
        ensure_ssh_include()

    @property
    def known_hosts_file(self) -> Path:
        return SSH_KNOWN_HOSTS_D / self.host_alias

    def ssh(
        self, command: str, check: bool = True, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", self.host_alias, command],
            text=True,
            capture_output=True,
            input=input,
        )
        if check and result.returncode != 0:
            raise click.ClickException(
                f"Command on devbox failed ({result.returncode}): {command}\n{result.stderr.strip()}"
            )
        return result


# --- helpers ------------------------------------------------------------------


def default_name() -> str:
    return re.sub(r"[^a-z0-9-]", "-", getpass.getuser().lower())


def ssh_public_key() -> str:
    if not SSH_KEY.exists():
        log(f"Generating SSH key {SSH_KEY}")
        SSH_DIR.mkdir(mode=0o700, exist_ok=True)
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                PROJECT,
                "-f",
                str(SSH_KEY),
            ],
            check=True,
        )
    return SSH_KEY.with_suffix(".pub").read_text().strip()


def user_data(public_key: str, idle_minutes: int) -> bytes:
    idle_check = base64.b64encode((HERE / "idle-check.sh").read_bytes()).decode()
    script = (
        (HERE / "bootstrap.sh")
        .read_text()
        .replace("__DEVBOX_SSH_PUBKEY__", public_key)
        .replace("__DEVBOX_IDLE_MINUTES__", str(idle_minutes))
        .replace("__DEVBOX_IDLE_CHECK_B64__", idle_check)
    )
    # cloud-init accepts gzipped user-data, which keeps us well under the 16 KB limit
    return gzip.compress(script.encode())


def ensure_ssh_include() -> None:
    config = SSH_DIR / "config"
    include = "Include config.d/*"
    text = config.read_text() if config.exists() else ""
    if include not in text.splitlines():
        # Include must precede any Host block to apply globally
        config.write_text(f"{include}\n\n{text}")
        config.chmod(0o600)


def github_authenticated(devbox: Devbox) -> bool:
    return (
        devbox.ssh("gh auth status --hostname github.com", check=False).returncode == 0
    )


def sync_repo(devbox: Devbox) -> None:
    for key in ("user.name", "user.email"):
        value = local_git_config(key)
        if value:
            devbox.ssh(f"git config --global {key} {shlex.quote(value)}")
    log("Syncing ~/inspect_ranges")
    devbox.ssh(
        f"test -d ~/inspect_ranges || git clone -q {REPO_URL} ~/inspect_ranges; "
        "cd ~/inspect_ranges && ~/.local/bin/uv sync --quiet --group dev"
    )


def local_git_config(key: str) -> str | None:
    result = subprocess.run(
        ["git", "config", "--global", key], text=True, capture_output=True
    )
    return result.stdout.strip() or None


def check_prerequisites() -> None:
    missing = [
        tool
        for tool in ("aws", "session-manager-plugin", "ssh", "uv")
        if shutil.which(tool) is None
    ]
    if missing:
        raise click.ClickException(
            f"Missing required tools: {', '.join(missing)} (see devbox/README.md)."
        )


# --- cli ----------------------------------------------------------------------


@click.group(name="devbox")
@click.option(
    "--name",
    default=default_name,
    show_default="local username",
    help="Devbox name (one per developer).",
)
@click.option("--profile", envvar="AWS_PROFILE", help="AWS profile.")
@click.option(
    "--region", envvar="AWS_REGION", help="AWS region (defaults to the profile's)."
)
@click.pass_context
def devbox_group(
    ctx: click.Context, name: str, profile: str | None, region: str | None
) -> None:
    """Provision and manage an inspect_ranges development box on EC2."""
    ctx.obj = Devbox(name, profile, region)


@devbox_group.command()
@click.option(
    "--instance-type",
    default="m8i.8xlarge",
    show_default=True,
    help="c8i/m8i/r8i family (nested virt) or an x86 metal instance.",
)
@click.option(
    "--volume-size", default=500, show_default=True, help="Root volume size (GiB)."
)
@click.option("--iops", default=6000, show_default=True, help="gp3 IOPS.")
@click.option(
    "--throughput", default=500, show_default=True, help="gp3 throughput (MiB/s)."
)
@click.option(
    "--idle-minutes",
    default=60,
    show_default=True,
    help="Stop after this many idle minutes.",
)
@click.option(
    "--backstop-hours",
    default=6,
    type=click.IntRange(0, 24),
    show_default=True,
    help="CloudWatch stop after N hours <2% CPU (0 = off).",
)
@click.pass_obj
def up(
    devbox: Devbox,
    instance_type: str,
    volume_size: int,
    iops: int,
    throughput: int,
    idle_minutes: int,
    backstop_hours: int,
) -> None:
    """Create (or start) the devbox and bring it fully up to date."""
    check_prerequisites()
    if not (
        NESTED_VIRT_TYPES.match(instance_type) or METAL_TYPES.search(instance_type)
    ):
        raise click.UsageError(
            f"{instance_type} cannot run KVM (use a metal instance, or c8i/m8i/r8i for nested virtualization)."
        )

    instance = devbox.instance()
    if instance is None:
        instance = devbox.launch(
            instance_type, volume_size, iops, throughput, idle_minutes
        )
        # a new instance has a new host key
        devbox.known_hosts_file.unlink(missing_ok=True)
    elif instance["InstanceType"] != instance_type:
        log(
            f"Note: existing devbox is {instance['InstanceType']}; --instance-type applies only at creation."
        )
    instance_id = instance["InstanceId"]
    devbox.write_ssh_config(instance_id)
    devbox.start(instance)

    log("Waiting for host provisioning (first boot takes several minutes)")
    status = devbox.ssh("cloud-init status --wait", check=False)
    if status.returncode != 0:
        raise click.ClickException(
            f"Provisioning failed:\n{status.stdout}{status.stderr}\n"
            f"See /var/log/devbox-bootstrap.log (`ssh {devbox.host_alias} sudo tail -100 /var/log/devbox-bootstrap.log`)."
        )
    if devbox.ssh("test -e /var/lib/devbox/kvm-missing", check=False).returncode == 0:
        raise click.ClickException(
            "/dev/kvm is missing on the devbox: not a metal instance and nested virtualization is not enabled."
        )
    log(
        f"Host provisioned ({instance_id}); SSH config: {SSH_CONFIG_D / devbox.host_alias}"
    )

    devbox.ssh(
        f"echo IDLE_MINUTES={idle_minutes} | sudo tee /etc/devbox.conf >/dev/null"
    )
    devbox.put_backstop_alarm(instance_id, backstop_hours)

    if not github_authenticated(devbox):
        raise click.ClickException(
            "The devbox has no GitHub token yet. Create a fine-grained token limited to "
            f"{REPO} (see devbox/README.md), copy it, then run:\n"
            f"  pbpaste | uv run inspect-ranges devbox{devbox.cli_options} github-token"
        )
    sync_repo(devbox)

    log(f"\nDevbox '{devbox.name}' is ready ({instance_id}).")
    log(f"  ssh {devbox.host_alias}")
    log(
        f"  VS Code: Remote-SSH: Connect to Host... -> {devbox.host_alias}, open ~/inspect_ranges"
    )
    log(
        f"  Auto-stop after {idle_minutes} idle minutes; `devbox-keepalive 4h` on the box to hold it."
    )


@devbox_group.command("github-token")
@click.pass_obj
def github_token(devbox: Devbox) -> None:
    """Store a GitHub token on the devbox (read from stdin), then clone the repo.

    Use a fine-grained token limited to meridianlabs-ai/inspect_ranges. Reading it from stdin keeps it out of your shell history, the terminal, and process listings.
    """
    token = sys.stdin.read().strip()
    # empty first: the prefix check otherwise shadows the more helpful message
    if not token:
        raise click.UsageError("No token on stdin; e.g. `pbpaste | ... github-token`.")
    # fine-grained tokens are github_pat_..., classic ones ghp_...; catch a wrong clipboard before sending it anywhere
    if not token.startswith(("github_pat_", "ghp_")) or any(c.isspace() for c in token):
        raise click.UsageError(
            "stdin doesn't look like a GitHub token (expected github_pat_...)."
        )
    devbox.require_instance()
    # gh stores the token (0600, ~/.config/gh/hosts.yml) and serves it to git as a credential helper
    devbox.ssh(
        "gh auth login --hostname github.com --git-protocol https --with-token",
        input=token,
    )
    devbox.ssh("gh auth setup-git --hostname github.com")
    if not github_authenticated(devbox):
        raise click.ClickException("GitHub rejected the token.")
    sync_repo(devbox)
    log(f"GitHub access configured; ~/inspect_ranges is ready on {devbox.host_alias}.")


@devbox_group.command()
@click.pass_obj
def start(devbox: Devbox) -> None:
    """Start the devbox and wait until it accepts connections."""
    devbox.start()
    log(f"Devbox '{devbox.name}' is running: ssh {devbox.host_alias}")


@devbox_group.command()
@click.pass_obj
def stop(devbox: Devbox) -> None:
    """Stop the devbox (the disk is kept)."""
    instance = devbox.require_instance()
    devbox.ec2.stop_instances(InstanceIds=[instance["InstanceId"]])
    log(f"Stopping {instance['InstanceId']}")


@devbox_group.command()
@click.pass_obj
def status(devbox: Devbox) -> None:
    """Show the devbox's state."""
    instance = devbox.instance()
    if instance is None:
        log(f"No devbox named '{devbox.name}' in {devbox.region}.")
        return
    log(f"name:      {devbox.name}")
    log(
        f"instance:  {instance['InstanceId']} ({instance['InstanceType']}, {devbox.region})"
    )
    log(f"state:     {instance['State']['Name']}")
    log(f"launched:  {instance['LaunchTime']:%Y-%m-%d %H:%M %Z}")
    log(f"ssh:       ssh {devbox.host_alias}")
    if instance["State"]["Name"] == "running":
        conf = devbox.ssh("cat /etc/devbox.conf", check=False).stdout.strip()
        if conf:
            log(f"auto-stop: {conf}")


@devbox_group.command("ssh-config")
@click.pass_obj
def ssh_config(devbox: Devbox) -> None:
    """(Re)write the local SSH config entry for the devbox."""
    instance = devbox.require_instance()
    devbox.write_ssh_config(instance["InstanceId"])
    log(f"Wrote {SSH_CONFIG_D / devbox.host_alias}")


@devbox_group.command(hidden=True)
@click.argument("port")
@click.pass_obj
def proxy(devbox: Devbox, port: str) -> None:
    """SSH ProxyCommand: start the devbox if needed, then tunnel to sshd over SSM."""
    instance = devbox.start()
    command = [
        "aws",
        "ssm",
        "start-session",
        "--target",
        instance["InstanceId"],
        "--region",
        devbox.region,
    ]
    command += [
        "--document-name",
        "AWS-StartSSHSession",
        "--parameters",
        f"portNumber={port}",
    ]
    if devbox.profile:
        command += ["--profile", devbox.profile]
    sys.stdout.flush()
    os.execvp(command[0], command)


@devbox_group.command()
@click.option(
    "--all",
    "destroy_all",
    is_flag=True,
    help="Also delete the shared VPC and IAM role if unused.",
)
@click.option("--yes", is_flag=True, help="Don't ask for confirmation.")
@click.pass_obj
def destroy(devbox: Devbox, destroy_all: bool, yes: bool) -> None:
    """Terminate the devbox (its disk, including its GitHub token, is deleted)."""
    instance = devbox.instance()
    if instance is not None:
        instance_id = instance["InstanceId"]
        if not yes:
            click.confirm(
                f"Terminate devbox '{devbox.name}' ({instance_id}) and delete its disk?",
                abort=True,
            )
        devbox.ec2.modify_instance_attribute(
            InstanceId=instance_id, DisableApiTermination={"Value": False}
        )
        devbox.ec2.terminate_instances(InstanceIds=[instance_id])
        log(f"Terminating {instance_id}")
        devbox.ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id])
        devbox.cloudwatch.delete_alarms(AlarmNames=[devbox.alarm_name])
        (SSH_CONFIG_D / devbox.host_alias).unlink(missing_ok=True)
        devbox.known_hosts_file.unlink(missing_ok=True)
    else:
        log(f"No devbox named '{devbox.name}' in {devbox.region}.")

    if destroy_all:
        others = devbox.all_instances()
        if others:
            names = ", ".join(
                next((t["Value"] for t in i["Tags"] if t["Key"] == "DevboxName"), "?")
                for i in others
            )
            raise click.ClickException(
                f"Shared infrastructure is still in use by: {names}"
            )
        devbox.destroy_shared()
