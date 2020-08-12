"""
Retrieve credentials for Georgia Tech AWS accounts using CAS

Inspired by
https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/
"""
import base64
import logging
import sys
import xml.etree.ElementTree as ElementTree
from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime, timezone
from getpass import getpass
from importlib.metadata import version
from json import dumps
from os import mkdir, path
from re import search
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, quote, urlparse

import boto3  # type: ignore

from botocore import UNSIGNED  # type: ignore
from botocore.config import Config  # type: ignore

from bs4 import BeautifulSoup  # type: ignore

from keyring import get_password, set_password  # type: ignore

from requests import Session

# Defaults
DEFAULT_CAS_HOST = "cas-test.gatech.edu"
DEFAULT_SAML_URL = "https://cas-test.gatech.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices"

# Errors handled in several places
ERROR_INVALID_CREDENTIALS_IN_KEYRING = (
    "Invalid credentials in keyring. Run `gatech-aws-credentials configure` to update."
)
ERROR_INVALID_USERNAME = (
    "The username {source} does not match the expected format. If this is a real account that has"
    + " access to AWS, please contact the developers to update the validation logic."
)
ERROR_RETRIEVING_SAML_RESPONSE = (
    "Failed to retrieve a SAML response - try running again with `--debug` to troubleshoot."
)
ERROR_UNEXPECTED_RESPONSE_CODE = "Unexpected response code {code} while {action}"
ERROR_WRONG_PATH_TYPE = (
    "{path} is not a {type}, please remove it so this tool can write to that location"
)

# Other assorted constants
AWS_DIR = "~/.aws/"
CAS_HOST = "cas_host"
CONFIGURE = "configure"
GATECH = "gatech"
GET_TGT_URL = "https://{hostname}/cas/v1/tickets"
HTML_PARSER = "html.parser"
ISO_8601 = "%Y-%m-%dT%H:%M:%S%z"
KEYRING_SERVICE_NAME = "gatech-aws-credentials"
KEYRING_TGT_SUFFIX = "_tgt_url"
PASSWORD = "password"
RETRIEVE = "retrieve"
ROLE_ARN = "arn:aws:iam::{account}:role/{role_name}"
SAML_URL = "saml_url"
USERNAME = "username"


def read_config_file(filename: str, config: ConfigParser) -> None:
    """
    Safely reads filename into config, checking to see if it exists and is a file

    :param filename: filename to read
    :param config: config to read into
    :return: None
    """
    if path.exists(filename):
        if path.isfile(filename):
            config.read(filename)
        else:
            logging.getLogger().error(ERROR_WRONG_PATH_TYPE.format(path=filename, type="file"))
            sys.exit(1)


def is_valid_gatech_username(username: str) -> bool:
    """
    Rough validator for GT usernames

    :param username: the username to check
    :return: whether this is a valid username
    """
    if not username.isalnum():
        return False
    if not username[0].isalpha():
        return False
    if not username[-1].isnumeric():
        return False
    return True


def get_ticket_granting_ticket_url(
    hostname: str, session: Session, username: str, password: str
) -> Optional[str]:
    """
    Exchanges a username and password for a TGT

    :param hostname: the CAS hostname to use
    :param session: the session to use
    :param username: the username for the user
    :param password: the password for the user
    :return: the TGT url, or None if the credentials are wrong
    """
    response = session.post(
        GET_TGT_URL.format(hostname=hostname), data={USERNAME: username, PASSWORD: password},
    )

    if response.status_code == 401:
        return None

    tgt_url = BeautifulSoup(response.text, HTML_PARSER).form["action"]

    assert isinstance(tgt_url, str)

    return tgt_url


def get_saml_response(session: Session, saml_url: str, tgt_url: str) -> Optional[str]:
    """
    Exchanges a TGT for a SAML response

    :param session: the session to use
    :param saml_url: the URL to use to exchange a service ticket for a SAML response
    :param tgt_url: the TGT url
    :return: a SAML response, or None if there was an error exchanging a TGT for a ST
    """
    logger = logging.getLogger()
    start_request = session.get(saml_url, allow_redirects=False)

    if start_request.status_code != 200:
        logger.error(
            ERROR_UNEXPECTED_RESPONSE_CODE.format(
                code=start_request.status_code, action="starting SAML flow"
            )
        )

    service = BeautifulSoup(start_request.text, HTML_PARSER).form.input["value"]

    service_ticket_request = session.post(tgt_url, data={"service": service})

    if service_ticket_request.status_code != 200:
        logger.debug(
            ERROR_UNEXPECTED_RESPONSE_CODE.format(
                code=service_ticket_request.status_code, action="retrieving service ticket",
            )
        )
        logger.debug(service_ticket_request.text)
        return None

    saml_request = session.post(service + "&ticket=" + quote(service_ticket_request.text))

    if saml_request.status_code != 200:
        logger.error(
            ERROR_UNEXPECTED_RESPONSE_CODE.format(
                code=saml_request.status_code, action="retrieving SAML response"
            )
        )
        logger.debug(saml_request.text)
        sys.exit(1)

    saml_response = BeautifulSoup(saml_request.text, HTML_PARSER).form.input["value"]

    assert isinstance(saml_response, str)

    return saml_response


def parse_saml_response_to_roles(saml_response: str) -> List[str]:
    """
    Parses a SAML response to a list of role,saml-provider pairs

    :param saml_response: the SAML response to parse
    :return: a list of role,saml-provider pairs
    """
    roles = []
    root = ElementTree.fromstring(base64.b64decode(saml_response))

    for saml2attribute in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        if saml2attribute.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            for attribute_value in saml2attribute.iter(
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            ):
                role = attribute_value.text
                assert isinstance(role, str)
                roles.append(role)

    for role in roles:
        if role is None:
            raise TypeError("Unexpected None in list of roles")
        chunks = role.split(",")
        if "saml-provider" in chunks[0]:
            new_role = chunks[1] + "," + chunks[0]
            index = roles.index(role)
            roles.insert(index, new_role)
            roles.remove(role)

    return roles


def parse_role_arn_to_account_name_pair(role: str) -> Tuple[int, str]:
    """
    Parses out the account ID and role name from a role ARN

    :param role: a role ARN
    :return: the account ID and role name as a tuple
    """
    matches = search(r"arn:aws:iam::(\d{12}):role/([a-zA-Z-_]+)", role)
    if matches is None:
        raise ValueError("Could not parse role ARN")
    return int(matches.group(1)), matches.group(2)


def build_profile_name(account: int, role: str) -> str:
    """
    Builds a profile name from an account ID and role name

    :param account: the account ID
    :param role: the role name
    :return: a profile name
    """
    return f"gatech_{account:12}_{role}"


def build_credential_process_string(account: int, role: str) -> str:
    """
    Builds the credential_process value for a given account and role

    :param account: the account ID
    :param role: the role name
    :return: the credential_process value
    """
    return f"gatech-aws-credentials retrieve --account {account:12} --role {role}"


def add_profile_to_config(
    aws_config: ConfigParser, section_name: str, account: int, role: str
) -> None:
    """
    Adds the given account and role to the config under the given section name

    :param aws_config: the config to populate
    :param section_name: the section name to use
    :param account: the account ID
    :param role: the role name
    :return: None
    """
    if not aws_config.has_section(section_name):
        aws_config.add_section(section_name)

    aws_config.set(section_name, "region", "us-east-1")
    aws_config.set(section_name, "output", "json")
    aws_config.set(
        section_name, "credential_process", build_credential_process_string(account, role),
    )


def get_aws_credentials_from_saml_response(
    saml_response: str, account: int, role_name: str
) -> Optional[Dict[str, Union[str, int, datetime]]]:
    """
    Exchanges a SAML response for AWS credentials for the given account and role name

    :param saml_response: the SAML response to use
    :param account: the account ID
    :param role_name: the role name
    :return: a dict of credentials, or None if the requested account and role was not in the SAML response
    """
    roles = parse_saml_response_to_roles(saml_response)

    client = boto3.client("sts", config=Config(signature_version=UNSIGNED))

    for role in roles:
        chunks = role.split(",")
        role_arn = chunks[0]
        principal_arn = chunks[1]
        if role_arn == ROLE_ARN.format(account=account, role_name=role_name):
            credentials = client.assume_role_with_saml(
                RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=saml_response,
            )["Credentials"]
            assert isinstance(credentials, dict)
            return credentials

    return None


def datetime_to_iso_8601(obj: Union[datetime, str, int]) -> str:
    """
    Convert a datetime to ISO 8601. For use when serializing the credentials dict.

    :param obj: a datetime object
    :return: the ISO 8601 representation of the datetime
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"{type(obj)} is not serializable")


def print_credentials(credentials: Dict[str, Union[str, int, datetime]]) -> None:
    """
    Print a dict of credentials for consumption by the AWS CLI

    :param credentials: the credentials dict
    :return: None
    """
    print(dumps(credentials, indent=2, default=datetime_to_iso_8601))


def configure(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    gatech_config: ConfigParser, aws_config: ConfigParser, saml_url: str, cas_host: str,
) -> None:
    """
    Write out configuration files for future use by retrieve(...)

    :param gatech_config: the config object for storing GT-specific information
    :param aws_config: the config object for storing AWS information
    :param saml_url: the URL to use for exchanging a ST for a SAML response
    :param cas_host: the hostname to use to exchange credentials for a TGT and then a ST
    :return:
    """
    logger = logging.getLogger()
    logger.debug("Looking for username in config file")

    home = path.expanduser(AWS_DIR)
    gatech_config_file = home + GATECH
    aws_config_file = home + "config"

    if gatech_config.has_section(GATECH):
        username = gatech_config.get(GATECH, USERNAME).lower()
    else:
        username = None  # type: ignore

    if username is None or not is_valid_gatech_username(username):
        username = input("Username: ").lower()

        if not is_valid_gatech_username(username):
            logger.error(ERROR_INVALID_USERNAME.format(source="you entered"))
            sys.exit(1)

    # Check for credentials in keychain
    logger.debug("Looking for password in keyring")
    password = get_password(KEYRING_SERVICE_NAME, username)
    password_from_keyring = password is not None

    if password is None:
        password = getpass()
        print("")

    print(
        "Checking credentials"
        + (" found in keyring" if password_from_keyring else "")
        + ", please wait...",
        flush=True,
    )

    session = Session()

    tgt_url = get_ticket_granting_ticket_url(cas_host, session, username, password)

    if tgt_url is None and password_from_keyring:
        print(
            f"The credentials found the in keyring were not valid. Please enter the correct password for {username}."
            + f"To use a different username, please update {gatech_config_file}."
        )
        password = getpass()
        print("")

        print("Checking credentials, please wait...", flush=True)

        tgt_url = get_ticket_granting_ticket_url(cas_host, session, username, password)

    if tgt_url is None:
        logger.error("Invalid credentials provided.")
        sys.exit(1)

    saml_response = get_saml_response(session, saml_url, tgt_url)

    if saml_response is None:
        logger.error(ERROR_RETRIEVING_SAML_RESPONSE)
        sys.exit(1)

    roles = parse_saml_response_to_roles(saml_response)

    if len(roles) == 0:
        logger.error("You do not have access to any roles.")
        sys.exit(1)

    if len(roles) > 0:
        for role in roles:
            account, name = parse_role_arn_to_account_name_pair(role.split(",")[0])
            add_profile_to_config(
                aws_config, "profile " + build_profile_name(account, name), account, name,
            )

    aws_directory = path.expanduser(AWS_DIR)

    if path.exists(aws_directory):
        if not path.isdir(aws_directory):
            logger.error(ERROR_WRONG_PATH_TYPE.format(path=aws_directory, type="directory"))
            sys.exit(1)
    else:
        mkdir(aws_directory)

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


def retrieve(  # pylint: disable=too-many-arguments,too-many-locals
    gatech_config: ConfigParser,
    username: str,
    saml_url: str,
    cas_host: str,
    account: int,
    role: str,
) -> None:
    """
    Retrieve credentials for a given username, account, and role, using the provided CAS host and SAML URL

    :param gatech_config: the configuration for this application
    :param username: the username of the user
    :param saml_url: the URL to use to exchange a service ticket for a SAML response
    :param cas_host: the CAS host to use for exchanging credentials for a TGT and then a ST
    :param account: the account ID
    :param role: the role name
    :return: None
    """
    logger = logging.getLogger()
    aws_credentials_file = path.expanduser(AWS_DIR) + "credentials"
    aws_credentials = ConfigParser()

    home = path.expanduser(AWS_DIR)
    gatech_config_file = home + GATECH

    read_config_file(aws_credentials_file, aws_credentials)

    if not is_valid_gatech_username(username):
        logger.error(ERROR_INVALID_USERNAME.format(source="in the configuration file"))
        sys.exit(1)

    session = Session()

    password = get_password(KEYRING_SERVICE_NAME, username)
    if password is None:
        logger.error(
            "Could not find password in keychain. Run `gatech-aws-credentials configure` to set it."
        )
        sys.exit(1)

    tgt = get_password(KEYRING_SERVICE_NAME, username + KEYRING_TGT_SUFFIX)
    if tgt is None:
        tgt = get_ticket_granting_ticket_url(cas_host, session, username, password)
        if tgt is None:
            logger.error(ERROR_INVALID_CREDENTIALS_IN_KEYRING)
            sys.exit(1)

    saml_response = get_saml_response(session, saml_url, tgt)
    if saml_response is None:
        tgt = get_ticket_granting_ticket_url(cas_host, session, username, password)
        if tgt is None:
            logger.error(ERROR_INVALID_CREDENTIALS_IN_KEYRING)
            sys.exit(1)

        saml_response = get_saml_response(session, saml_url, tgt)
        if saml_response is None:
            logger.error(ERROR_RETRIEVING_SAML_RESPONSE)
            sys.exit(1)

    set_password(KEYRING_SERVICE_NAME, username + KEYRING_TGT_SUFFIX, tgt)

    credentials = get_aws_credentials_from_saml_response(saml_response, account, role)
    if credentials is None:
        logger.error(
            "The requested role was not found in the SAML response. Make sure you still have access."
        )
        sys.exit(1)

    credentials["Version"] = 1

    profile_name = build_profile_name(account, role)

    if not gatech_config.has_section(profile_name):
        gatech_config.add_section(profile_name)

    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        gatech_config.set(profile_name, field, str(credentials[field]))

    gatech_config.set(profile_name, "Expiration", datetime_to_iso_8601(credentials["Expiration"]))

    with open(gatech_config_file, "w") as file:
        gatech_config.write(file)

    print_credentials(credentials)


def main() -> None:  # pylint: disable=unused-variable,too-many-branches,too-many-statements,too-many-locals
    """
    Parses command-line arguments and calls out to either configure(...) or retrieve(...)

    :return: None
    """
    parser = ArgumentParser(
        description="Retrieve credentials for Georgia Tech AWS accounts using CAS",
        allow_abbrev=False,
    )
    parser.add_argument(
        "action",
        choices=[CONFIGURE, RETRIEVE],
        help="whether to write configuration files or retrieve credentials",
    )
    parser.add_argument(
        "--account",
        help="the numeric account ID, required for retrieve",
        type=int,
        required=RETRIEVE in sys.argv,
    )
    parser.add_argument(
        "--role", help="the role name, required for retrieve", required=RETRIEVE in sys.argv,
    )
    parser.add_argument(
        "--saml-url",
        help="the URL to use to retrieve a SAML response, can optionally be used with configure",
    )
    parser.add_argument(
        "--cas-host",
        help="the CAS host to use to retrieve a service ticket, can optionally be used with configure",
    )
    parser.add_argument("--debug", help="print debug information", action="store_true")
    parser.add_argument(
        "--version",
        action="version",
        version="gatech-aws-credentials v" + version("gatech-aws-credentials"),
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

    read_config_file(gatech_config_file, gatech_config)
    read_config_file(aws_config_file, aws_config)

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
            sys.exit(1)

        configure(gatech_config, aws_config, saml_url, cas_host)
    elif args.action == RETRIEVE:
        if args.account is None or args.role is None:
            # This should be prevented by argparse but checking here just in case
            parser.error("retrieve requires --account and --role")
            sys.exit(1)

        if gatech_config.has_section(GATECH):
            username = gatech_config.get(GATECH, USERNAME)
        else:
            logger.error(
                "The configuration file is missing or invalid. Rerun `gatech-aws-credentials configure`."
            )
            sys.exit(1)

        logger.debug("Looking in config file for existing credentials")
        profile_name = build_profile_name(args.account, args.role)
        if gatech_config.has_section(profile_name):
            expiring_in = (
                datetime.strptime(gatech_config.get(profile_name, "Expiration"), ISO_8601)
                - datetime.now(timezone.utc)
            ).total_seconds()
            logger.debug("Found credentials expiring in {} seconds".format(expiring_in))
            if expiring_in > 60:
                credentials: Dict[str, Union[str, int, datetime]] = {}

                # AWS CLI is case-sensitive but ConfigParser is not
                for field in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
                    credentials[field] = gatech_config.get(profile_name, field)

                credentials["Version"] = 1

                print_credentials(credentials)
                sys.exit(0)

        retrieve(gatech_config, username, saml_url, cas_host, args.account, args.role)
    else:
        # This should be prevented by argparse but checking here just in case
        logger.error("An unexpected action was passed. Rerun with --help.")
        sys.exit(1)
