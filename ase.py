#!/usr/bin/env python

''' A simple class that wraps boto functions to perform simple
    enumeration on AWS resources that can be used for security auditing purposes.
    This is primarily useful if you are writing tooling for multiple AWS accounts.
    Docs are formated for sphinx fucntion definitions
      ( https://pythonhosted.org/an_example_pypi_project/sphinx.html#function-definitions )
'''

import boto
import boto.ec2.elb


class ASEException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class AwsSecurityEnumerator(object):
    ''' The main AWS Security Enumeration object.
        config must be the yaml config file w/ AWS credentials.
        See github documentation for examples
        All exceptions raise ASEException w/ associated err message
    '''
    ASEException = ASEException

    def __init__(self, config):
        ''' init
           :param config: the yaml config dictionary
           :type config: dict
        '''
        self.config = config

    def get_all_aws_accounts(self):
        ''' Get a list of AWS Accounts
            :returns: list of account dictionaries via the config file
            :rtype: list
        '''
        return self.config['aws_accounts']

    def get_account_api_creds(self, account_name):
        ''' Returns Credentials for the named account_name
            :param account_name: string of the account name; specified in conf
            :type account_name: string
            :returns: dict of the access key id and secret key
            :rtype: dict
        '''
        accounts = self.config['aws_accounts']
        for account in accounts:
            if account['name'] == account_name.lower():
                return {'access_key': account['key'],
                        'secret_key': account['secret']}
        raise ASEException('Cannot obtain credentials for specified account')

    def __ec2_connect_all_regions(self, account_name):
        ''' Connects to ec2 and returns a list of ec2 connection objects, 
            one per region
            :param account_name: string of the account name
            :type account_name: string
            :returns: list of ec2 objects
            :rtype: list
        '''
        ec2s = []
        creds = self.get_account_api_creds(account_name)
        access_key = creds['access_key']
        secret_key = creds['secret_key']
        try:
            ec2 = boto.connect_ec2(access_key, secret_key)
            regions = ec2.get_all_regions()
            for region in regions:
                ec2 = region.connect(aws_access_key_id=access_key,
                                     aws_secret_access_key=secret_key)
                ec2s.append(ec2)
        except:
            raise ASEException('Cannot connect to ec2 region')
        return ec2s

    def get_instances_for_account(self, account_name):
        ''' Returns a list of all instances in all regions for account_name
        :param account_name: string of the account name
        :type account_name: string
        :returns: list of boto instance objects
        :rtype: list
        '''
        try:
            res_list = []
            ec2s = self.__ec2_connect_all_regions(account_name)
            for ec2 in ec2s:
                reservations = ec2.get_all_reservations()
                for reservation in reservations:
                    res_list.append(reservation)
            return [i for r in res_list for i in r.instances]
        except:
            raise ASEException('Cannot get instances for named account')

    def get_all_instances(self):
        ''' Same as `get_instances_for_account`, but for all accounts in config
        :returns: list of boto instances objects
        :rtype: list
        '''
        try:
            results = []
            accounts = [i['name'] for i in self.get_all_aws_accounts()]
            for a in accounts:
                results += self.get_instances_for_account(a)
            return results
        except:
            raise ASEException('Cannot get all instances')

    def get_elbs_for_account(self, account_name):
        ''' Returns a list of elastic load balancers for all regions in account_name
        :param account_name: string of the account name
        :type account_name: string
        :returns: list of boto load balancer objects
        :rtype: list
        '''
        creds = self.get_account_api_creds(account_name)
        ec2 = boto.connect_ec2(creds['access_key'], creds['secret_key'])
        regions = ec2.get_all_regions()
        elb_hosts = []
        try:
            for region in regions:
                elb = boto.ec2.elb.connect_to_region(
                    region.name,
                    aws_access_key_id=creds['access_key'],
                    aws_secret_access_key=creds['secret_key'])
                for lb in elb.get_all_load_balancers():
                    elb_hosts.append(lb)
            return elb_hosts
        except:
            raise ASEException('Cannot get ELBs for named account')

    def get_all_elbs(self):
        ''' Same as `get_elbs_for_account`, but for all accounts in config
        :returns: list of boto load balancer objects
        :rtype: list
        '''
        try:
            results = []
            accounts = [i['name'] for i in self.get_all_aws_accounts()]
            for a in accounts:
                results += self.get_elbs_for_account(a)
            return results
        except:
            raise ASEException('Cannot get all ELBs')

    def __get_all_instance_status(self, account_name):
        ''' Returns a list of instance status objects for account_name, all regions
        :param account_name: string of the account name
        :type account_name: string
        :returns: list of boto instance status objects
        :rtype: list
        '''
        try:
            ec2s = self.__ec2_connect_all_regions(account_name)
            i_status = []
            for e in ec2s:
                for i in e.get_all_instance_status():
                    i_status.append(i)
            return i_status
        except:
            raise ASEException('Cannot obtain instance status')

    def get_all_instance_events(self, account_name):
        ''' Returns a list of dits of status events for account_name, all regions
        :param account_name: string of the account name
        :type account_name: string
        :returns: list of status dictionaries
        :rtype: list
        '''
        status_list = self.__get_all_instance_status(account_name)
        instances = self.get_instances_for_account(account_name)
        non_ok = []
        try:
            for s in status_list:
                if s.events:  # None returned in normal cases
                    # make a dict of the details
                    for event in s.events:
                        # find the instance id, for tags
                        instance = ''
                        for i in instances:
                            if i.id == s.id:
                                instance = i
                        completed = False
                        if '[Completed]' in event.description:
                            completed = True
                        non_ok.append({'instance_id': s.id,
                                       'completed'  : completed,
                                       'event_code' : event.code,
                                       'descript'   : event.description,
                                       'time_nb4'   : event.not_before,
                                       'time_nafter': event.not_after,
                                       'tags'       : instance.tags,
                                       'account'    : account_name,
                                       'region'     : instance.region.name})
            return non_ok
        except:
            raise ASEException('Cannot get instance maintenance events')

    def get_security_groups(self, account_name):
        ''' Returns a list of security groups all security groups in all 
            regions for account_name
        :param account_name: string of the account name
        :type account_name: string
        :returns: list of boto security group objects
        :rtype: list
        '''
        ec2s = self.__ec2_connect_all_regions(account_name)
        try:
            sgroups = []
            for e in ec2s:
                for g in e.get_all_security_groups():
                    sgroups.append(g)
            return sgroups
        except:
            raise ASEException('Cannot get security groups for named account')

    def get_all_security_groups(self):
        ''' Same as `get_security_groups`, but for all accounts in config
        :returns: list of boto security group objects
        :rtype: list
        '''
        try:
            results = []
            accounts = [i['name'] for i in self.get_all_aws_accounts()]
            for a in accounts:
                results += self.get_security_groups(a)
            return results
        except:
            raise ASEException('Cannot get all security groups')

