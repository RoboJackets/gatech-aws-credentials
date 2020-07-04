# gatech-aws-credentials
![CI](https://github.com/RoboJackets/gatech-aws-credentials/workflows/CI/badge.svg)[![GitHub license](https://img.shields.io/github/license/RoboJackets/gatech-aws-credentials)](https://github.com/RoboJackets/gatech-aws-credentials/blob/main/LICENSE)
Retrieve credentials for Georgia Tech AWS accounts using CAS

## Install
The recommended install method is using `pipx`.

```shell
pipx install git+https://github.com/RoboJackets/gatech-aws-credentials

# Updates are also through pipx
pipx upgrade gatech-aws-credentials
```

## Run
```shell
# Set up configuration files
gatech-aws-credentials configure

# View configured profiles
aws configure list-profiles

# Run the AWS CLI with a configured profile
aws s3 ls --profile gatech_771971951923_Shibboleth-fulladmin

# Or set via environment variable
export AWS_PROFILE=gatech_771971951923_Shibboleth-fulladmin
aws s3 ls

# Run the script directly for debugging purposes
gatech-aws-credentials retrieve --account 771971951923 --role Shibboleth-fulladmin --debug
```
