# AWS Enumeration Library

This library is a light wrapper around `boto`, to be used to assist in enumerating assets when dealing with multiple accounts and all regions.

## Why?

Consider the use case: 

`I want to scan all external AWS assets we have`.

Well what if you have 11 AWS Accounts, each (currently) with 9 regions? Then it becomes a pain to have to loop through al these accounts/regions when you want to do simple things.

This library just wraps `boto` to help.

For some sample basic scripts, see [this script repo](https://TBD).

## Installation

You can install via pip directly from Github

```
pip install git+ssh://git@github.com/jfalken/aws_enumeration_lib
```

## Usage

Most method names are self explanatory, however more detailed docs will be added here.

```python
import yaml  # pip install pyyaml 
from ase import AwsSecurityEnumerator as ASE

# load config dictionary
config = yaml.load(open('config.yaml'))

# init the object
ase = ASE(config)
```

For example, get all public hostnames for all instances in all accounts and regions. Then use this to feed a scanner or whatever.

```python
instances = ase.get_all_instances()  # all accounts, all regions
public_hosts = [i.public_dns_name for i in instances]
```

## Config Dictionary

The configuration dictionary must be in the format:

```js
{'aws_accounts': [{'name': 'AWS_Account_1',
                   'key': 'AKIA...',
                   'secret': 'xxx_secret_key_xxx'},
                  {'name': 'AWS_Account_2',
                   'key': 'AKIA...',
                   'secret': 'xxx_secret_key_xxx'},
```

The scoped credentials need read-only permissions, for example, something like [listed here](https://aws.amazon.com/code/AWS-Policy-Examples/6851158459579252). You can (and should) restrict the credentials for only those services you will actually be reading.

I prefer to load credentials in a yaml file. The file `config.yaml` in this repo is provided as an example. When loaded via `pyyaml` (as in the examples), the yaml file will translate into the dict above.