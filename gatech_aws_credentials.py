from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime
from getpass import getpass
from importlib.metadata import version
from json import dumps
from logging import Logger
from os import path, mkdir
from re import search
from typing import Optional
from urllib.parse import urlparse, parse_qs, quote
import base64
import logging
import sys
import xml.etree.ElementTree as ElementTree

from bs4 import BeautifulSoup
from keyring import get_password, set_password
from requests import Session
import boto3

# Defaults
DEFAULT_CAS_HOST = "cas-test.gatech.edu"
DEFAULT_SAML_URL = "https://cas-test.gatech.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices"

# Errors handled in several places
ERROR_INVALID_CREDENTIALS_IN_KEYRING = (
    "Invalid credentials in keyring. Run `gatech-aws-credentials configure` to update."
)
ERROR_INVALID_USERNAME = "The username {source} does not match the expected format. If this is a real account that has access to AWS, please contact the developers to update the validation logic."
ERROR_RETRIEVING_SAML_RESPONSE = (
    "Failed to retrieve a SAML response - try running again with `--debug` to troubleshoot."
)
ERROR_UNEXPECTED_RESPONSE_CODE = "Unexpected response code {code} while {action}"
ERROR_WRONG_PATH_TYPE = "{path} is not a {type}, please remove it so this tool can write to that location"

# Other assorted constants
AWS_DIR = "~/.aws"
CAS_HOST = "cas_host"
CONFIGURE = "configure"
GATECH = "gatech"
GET_TGT_URL = "https://{hostname}/cas/v1/tickets"
HTML_PARSER = "html.parser"
KEYRING_SERVICE_NAME = "gatech-aws-credentials"
KEYRING_TGT_SUFFIX = "_tgt_url"
PASSWORD = "password"
RETRIEVE = "retrieve"
ROLE_ARN = "arn:aws:iam::{account}:role/{role_name}"
SAML_URL = "saml_url"
USERNAME = "username"


def read_config_file(logger: Logger, filename: str, config: ConfigParser) -> None:
    if path.exists(filename):
        if path.isfile(filename):
            config.read(filename)
        else:
            logger.error(ERROR_WRONG_PATH_TYPE.format(path=filename, type="file"))
            exit(1)


def is_valid_gatech_username(username: str) -> bool:
    if not username.isalnum():
        return False
    if not username[0].isalpha():
        return False
    if not username[-1].isnumeric():
        return False
    return True


def get_ticket_granting_ticket_url(hostname: str, session: Session, username: str, password: str) -> Optional[str]:
    response = session.post(GET_TGT_URL.format(hostname=hostname), data={USERNAME: username, PASSWORD: password},)

    if response.status_code == 401:
        return None

    return BeautifulSoup(response.text, HTML_PARSER).form["action"]


def get_saml_response(logger: Logger, session: Session, saml_url: str, tgt_url: str) -> Optional[str]:
    start_request = session.get(saml_url, allow_redirects=False)

    if start_request.status_code != 302:
        logger.error(ERROR_UNEXPECTED_RESPONSE_CODE.format(code=start_request.status_code, action="starting SAML flow"))

    service = parse_qs(urlparse(start_request.headers["Location"]).query)["service"][0]

    service_ticket_request = session.post(tgt_url, data={"service": service})

    if service_ticket_request.status_code != 200:
        logger.debug(
            ERROR_UNEXPECTED_RESPONSE_CODE.format(
                code=service_ticket_request.status_code, action="retrieving service ticket",
            )
        )
        logger.debug(service_ticket_request.text)
        return None

    saml_request = session.get(service + "&ticket=" + quote(service_ticket_request.text))

    if saml_request.status_code != 200:
        logger.error(
            ERROR_UNEXPECTED_RESPONSE_CODE.format(code=saml_request.status_code, action="retrieving SAML response")
        )
        logger.debug(saml_request.text)
        exit(1)

    return BeautifulSoup(saml_request.text, HTML_PARSER).form.input["value"]


def parse_saml_response_to_roles(saml_response: str) -> list:
    roles = []
    root = ElementTree.fromstring(base64.b64decode(saml_response))

    for saml2attribute in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        if saml2attribute.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            for saml2attributevalue in saml2attribute.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"):
                roles.append(saml2attributevalue.text)

    for role in roles:
        chunks = role.split(",")
        if "saml-provider" in chunks[0]:
            new_role = chunks[1] + "," + chunks[0]
            index = roles.index(role)
            roles.insert(index, new_role)
            roles.remove(role)

    return roles


def parse_role_arn_to_account_name_pair(role: str) -> (str, str):
    matches = search(r"arn:aws:iam::(\d{12}):role/([a-zA-Z-_]+)", role)
    return matches.group(1), matches.group(2)


def build_profile_name(account: str, role: str) -> str:
    return "gatech_" + account + "_" + role


def build_credential_process_string(account: str, role: str) -> str:
    return "gatech-aws-credentials retrieve --account " + account + " --role " + role


def add_profile_to_config(aws_config: ConfigParser, section_name: str, account: str, role: str) -> None:
    if not aws_config.has_section(section_name):
        aws_config.add_section(section_name)

    aws_config.set(section_name, "region", "us-east-1")
    aws_config.set(section_name, "output", "json")
    aws_config.set(
        section_name, "credential_process", build_credential_process_string(account, role),
    )


def get_aws_credentials_from_saml_response(saml_response: str, account: int, role_name: str) -> Optional[dict]:
    roles = parse_saml_response_to_roles(saml_response)

    client = boto3.client("sts", aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None,)

    for role in roles:
        chunks = role.split(",")
        role_arn = chunks[0]
        principal_arn = chunks[1]
        if role_arn == ROLE_ARN.format(account=account, role_name=role_name):
            return client.assume_role_with_saml(
                RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml_response,
            )["Credentials"]

    return None


def datetime_to_iso_8601(obj: datetime):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"{type(obj)} is not serializable")


def configure(
    logger: Logger,
    gatech_config: ConfigParser,
    gatech_config_file: str,
    aws_config: ConfigParser,
    aws_config_file: str,
    saml_url: str,
    cas_host: str,
) -> None:
    logger.debug("Looking for username in config file")

    if gatech_config.has_section(GATECH):
        username = gatech_config.get(GATECH, USERNAME).lower()
    else:
        username = None

    if username is None or not is_valid_gatech_username(username):
        username = input("Username: ").lower()

        if not is_valid_gatech_username(username):
            logger.error(ERROR_INVALID_USERNAME.format(source="you entered"))
            exit(1)

    # Check for credentials in keychain
    logger.debug("Looking for password in keyring")
    password = get_password(KEYRING_SERVICE_NAME, username)
    password_from_keyring = password is not None

    if password is None:
        password = getpass()
        print("")

    print(
        "Checking credentials" + (" found in keyring" if password_from_keyring else "") + ", please wait...",
        flush=True,
    )

    session = Session()

    tgt_url = get_ticket_granting_ticket_url(cas_host, session, username, password)

    if tgt_url is None and password_from_keyring:
        print(
            f"The credentials found the in keyring were not valid. Please enter the correct password for {username}. To use a different username, please update {gatech_config_file}."
        )
        password = getpass()
        print("")

        print("Checking credentials, please wait...", flush=True)

        tgt_url = get_ticket_granting_ticket_url(cas_host, session, username, password)

    if tgt_url is None:
        logger.error("Invalid credentials provided.")
        exit(1)

    saml_response = get_saml_response(logger, session, saml_url, tgt_url)

    if saml_response is None:
        logger.error(ERROR_RETRIEVING_SAML_RESPONSE)
        exit(1)

    roles = parse_saml_response_to_roles(saml_response)

    if len(roles) == 0:
        logger.error("You do not have access to any roles.")
        exit(1)

    if len(roles) > 0:
        for role in roles:
            account, name = parse_role_arn_to_account_name_pair(role.split(",")[0])
            add_profile_to_config(
                aws_config, "profile " + build_profile_name(account, name), account, name,
            )

    awsdir = path.expanduser(AWS_DIR)

    if path.exists(awsdir):
        if not path.isdir(awsdir):
            logger.error(ERROR_WRONG_PATH_TYPE.format(path=awsdir, type="directory"))
            exit(1)
    else:
        mkdir(awsdir)

    with open(aws_config_file, "w") as file:
        aws_config.write(file)

    set_password(KEYRING_SERVICE_NAME, username + KEYRING_TGT_SUFFIX, tgt_url)
    set_password(KEYRING_SERVICE_NAME, username, password)

    if not gatech_config.has_section(GATECH):
        gatech_config.add_section(GATECH)

    gatech_config.set(GATECH, USERNAME, username)

    if saml_url != DEFAULT_SAML_URL:
        gatech_config.set(GATECH, SAML_URL, saml_url)

    if cas_host != DEFAULT_CAS_HOST:
        gatech_config.set(GATECH, CAS_HOST, cas_host)

    with open(gatech_config_file, "w") as file:
        gatech_config.write(file)

    print(f"All done! You may want to review {aws_config_file} to see what this did.")


def retrieve(logger: Logger, username: str, saml_url: str, cas_host: str, account: int, role: str) -> None:
    if not is_valid_gatech_username(username):
        logger.error(ERROR_INVALID_USERNAME.format(source="in the configuration file"))
        exit(1)

    session = Session()

    password = get_password(KEYRING_SERVICE_NAME, username)
    if password is None:
        logger.error("Could not find password in keychain. Run `gatech-aws-credentials configure` to set it.")
        exit(1)

    tgt = get_password(KEYRING_SERVICE_NAME, username + KEYRING_TGT_SUFFIX)
    if tgt is None:
        tgt = get_ticket_granting_ticket_url(cas_host, session, username, password)
        if tgt is None:
            logger.error(ERROR_INVALID_CREDENTIALS_IN_KEYRING)
            exit(1)

    saml_response = get_saml_response(logger, session, saml_url, tgt)
    if saml_response is None:
        tgt = get_ticket_granting_ticket_url(cas_host, session, username, password)
        if tgt is None:
            logger.error(ERROR_INVALID_CREDENTIALS_IN_KEYRING)
            exit(1)

        saml_response = get_saml_response(logger, session, saml_url, tgt)
        if saml_response is None:
            logger.error(ERROR_RETRIEVING_SAML_RESPONSE)
            exit(1)

    set_password(KEYRING_SERVICE_NAME, username + KEYRING_TGT_SUFFIX, tgt)

    credentials = get_aws_credentials_from_saml_response(saml_response, account, role)
    credentials["Version"] = 1
    if credentials is None:
        logger.error("The requested role was not found in the SAML response. Make sure you still have access.")
    print(dumps(credentials, indent=2, default=datetime_to_iso_8601))


def main() -> None:
    parser = ArgumentParser(
        description="Interacts with Georgia Tech CAS and the AWS Security Token Service to retrieve temporary AWS credentials.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "action", choices=[CONFIGURE, RETRIEVE], help="whether to write configuration files or retrieve credentials",
    )
    parser.add_argument(
        "--account", help="the numeric account ID, required for retrieve", type=int, required=RETRIEVE in sys.argv,
    )
    parser.add_argument(
        "--role", help="the role name, required for retrieve", required=RETRIEVE in sys.argv,
    )
    parser.add_argument(
        "--saml-url", help="the URL to use to retrieve a SAML response, can optionally be used with configure",
    )
    parser.add_argument(
        "--cas-host", help="the CAS host to use to retrieve a service ticket, can optionally be used with configure",
    )
    parser.add_argument("--debug", help="print debug information", action="store_true")
    parser.add_argument(
        "--version", action="version", version="gatech-aws-credentials v" + version("gatech-aws-credentials"),
    )
    args = parser.parse_args()

    formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.addHandler(handler)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    home = path.expanduser(AWS_DIR)
    gatech_config_file = home + GATECH
    aws_config_file = home + "config"
    gatech_config = ConfigParser()
    aws_config = ConfigParser()

    read_config_file(logger, gatech_config_file, gatech_config)
    read_config_file(logger, aws_config_file, aws_config)

    if args.saml_url is not None:
        saml_url = args.saml_url
    else:
        if gatech_config.has_section(GATECH):
            saml_url = gatech_config.get(GATECH, SAML_URL, fallback=DEFAULT_SAML_URL)
        else:
            saml_url = DEFAULT_SAML_URL

    if args.cas_host is not None:
        cas_host = args.cas_host
    else:
        if gatech_config.has_section(GATECH):
            cas_host = gatech_config.get(GATECH, CAS_HOST, fallback=DEFAULT_CAS_HOST)
        else:
            cas_host = DEFAULT_CAS_HOST

    if args.action == CONFIGURE:
        if args.account is not None or args.role is not None:
            parser.error("configure does not support --account or --role")
            exit(1)

        configure(
            logger, gatech_config, gatech_config_file, aws_config, aws_config_file, saml_url, cas_host,
        )
    elif args.action == RETRIEVE:
        if args.account is None or args.role is None:
            # This should be prevented by argparse but checking here just in case
            parser.error("retrieve requires --account and --role")
            exit(1)

        if gatech_config.has_section(GATECH):
            username = gatech_config.get(GATECH, USERNAME)
        else:
            logger.error("The configuration file is missing or invalid. Rerun `gatech-aws-credentials configure`.")
            username = None
            exit(1)

        retrieve(logger, username, saml_url, cas_host, args.account, args.role)
    else:
        # This should be prevented by argparse but checking here just in case
        logger.error("An unexpected action was passed. Rerun with --help.")
        exit(1)
