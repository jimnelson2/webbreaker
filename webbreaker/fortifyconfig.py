#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from webbreaker.webbreakerlogger import Logger
from subprocess import CalledProcessError
from webbreaker.secretclient import SecretClient

try:
    import ConfigParser as configparser

    config = configparser.SafeConfigParser()

except ImportError:  # Python3
    import configparser

    config = configparser.ConfigParser()


class FortifyConfig(object):
    def __init__(self):
        config_file = os.path.abspath('.config')
        try:
            config.read(config_file)
            self.ssc_url = config.get("fortify", "ssc_url")
            self.project_template = config.get("fortify", "project_template")
            self.application_name = config.get("fortify", "application_name")

            secret_client = SecretClient()
            self.username = secret_client.get('fortify', 'fortify_username')
            self.password = secret_client.get('fortify', 'fortify_password')

        except (configparser.NoOptionError, CalledProcessError) as noe:
            Logger.app.error("{} has incorrect or missing values {}".format(config_file, noe))
        except (configparser.Error) as e:
            Logger.app.error("Error reading {} {}".format(config_file, e))

    def clear_credentials(self):
        secret_client = SecretClient()
        secret_client.clear_credentials('fortify', 'fortify_username', 'fortify_password')

    def write_username(self, username):
        self.username = username
        secret_client = SecretClient()
        secret_client.set('fortify', 'fortify_username', username)

    def write_password(self, password):
        self.password = password
        secret_client = SecretClient()
        secret_client.set('fortify', 'fortify_password', password)

    def has_auth_creds(self):
        if self.username and self.password and self.ssc_url:
            return True
        else:
            return False
