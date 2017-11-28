#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil

try:
    import ConfigParser as configparser

    config = configparser.SafeConfigParser()
except ImportError:  # Python3
    import configparser

    config = configparser.ConfigParser()


class Config(object):
    def __init__(self):
        self.home = os.path.expanduser('~')
        self.install = self.set_path(install=self.home, dir_path='.webbreaker')
        self.config = self.set_path(file_name='config.ini')
        self.etc = self.set_path(dir_path='etc')
        self.git = self.set_path(dir_path='etc/webinspect')
        self.log = self.set_path(dir_path='log')
        self.agent_json = self.set_path(dir_path=self.etc, file_name='agent.json')

        self.secret = os.path.join(self.install, '.webbreaker')

        self.set_config()

    def set_path(self, install=None, dir_path=None, file_name=None):
        if not install:
            install = self.install
        if dir_path and file_name:
            dir_path = os.path.join(install, dir_path)
            full_path = os.path.join(dir_path, file_name)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            try:
                f = open(full_path, 'a+')
                f.close()
            except IOError:
                print("Unable to open {}".format(full_path))
                return 1
            return full_path

        elif not dir_path and file_name:
            dir_path = install
            full_path = os.path.join(dir_path, file_name)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            try:
                f = open(full_path, 'a+')
                f.close()
            except IOError:
                print("Unable to open {}".format(full_path))
                return 1
            return full_path

        elif dir_path and not file_name:
            dir_path = os.path.join(install, dir_path)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            return dir_path

    def conf_get(self, section, option, value):
        try:
            config.read(self.config)
            return config.get(section, option)

        except configparser.NoSectionError:
            config.add_section(section)
            config.set(section, option, value)
            with open(self.config, 'w') as configfile:
                config.write(configfile)
            return value

        except configparser.NoOptionError:
            config.set(section, option, value)
            with open(self.config, 'w') as configfile:
                config.write(configfile)
            return value

    def set_config(self):
        self.conf_get('webbreaker_install', 'dir', '.')

        self.conf_get('fortify', 'ssc_url', 'https://fortify.example.com')
        self.conf_get('fortify', 'project_template', 'Prioritized High Risk Issue Template')
        self.conf_get('fortify', 'application_name', 'WEBINSPECT')
        self.conf_get('fortify', 'fortify_username', '')
        self.conf_get('fortify', 'fortify_password', '')

        self.conf_get('threadfix', 'host', 'https://threadfix.example.com:8443/threadfix')
        self.conf_get('threadfix', 'api_key', 'ZfO0b7dotQZnXSgkMOEuQVoFIeDZwd8OEQE7XXX')

        self.conf_get('git', 'token', '43eb3ddb7152bbecXXabcee04859ee73eaa1XXXX')

        self.conf_get('webinspect_endpoints', 'large', '2')
        self.conf_get('webinspect_endpoints', 'medium', '1')
        self.conf_get('webinspect_endpoints', 'server01', 'https://webinspect-server-1.example.com:8083')
        self.conf_get('webinspect_endpoints', 'e01', '%(server01)s|%(large)s')

        self.conf_get('webinspect_default_size', 'default', 'large')

        self.conf_get('webinspect_size', 'large', '2')
        self.conf_get('webinspect_size', 'medium', '1')

        self.conf_get('webinspect_repo', 'git', 'git@github.com:automationdomination/WebInspect.git')
        self.conf_get('webinspect_repo', 'dir', './webinspect')

        self.conf_get('webinspect_policies', 'aggressivesqlinjection', '032b1266-294d-42e9-b5f0-2a4239b23941')
        self.conf_get('webinspect_policies', 'allchecks', '08cd4862-6334-4b0e-abf5-cb7685d0cde7')
        self.conf_get('webinspect_policies', 'apachestruts', '786eebac-f962-444c-8c59-7bf08a6640fd')
        self.conf_get('webinspect_policies', 'application', '8761116c-ad40-438a-934c-677cd6d03afb')
        self.conf_get('webinspect_policies', 'assault', '0a614b23-31fa-49a6-a16c-8117932345d8')
        self.conf_get('webinspect_policies', 'blank', 'adb11ba6-b4b5-45a6-aac7-1f7d4852a2f6')
        self.conf_get('webinspect_policies', 'criticalsandhighs', '7235cf62-ee1a-4045-88f8-898c1735856f')
        self.conf_get('webinspect_policies', 'crosssitescripting', '49cb3995-b3bc-4c44-8aee-2e77c9285038')
        self.conf_get('webinspect_policies', 'development', '9378c6fa-63ec-4332-8539-c4670317e0a6')
        self.conf_get('webinspect_policies', 'mobile', 'be20c7a7-8fdd-4bed-beb7-cd035464bfd0')
        self.conf_get('webinspect_policies', 'nosqlandnode.js', 'a2c788cc-a3a9-4007-93cf-e371339b2aa9')
        self.conf_get('webinspect_policies', 'opensslheartbleed', '5078b547-8623-499d-bdb4-c668ced7693c')
        self.conf_get('webinspect_policies', 'owasptop10applicationsecurityrisks2013',
                      '48cab8a0-669e-438a-9f91-d26bc9a24435')
        self.conf_get('webinspect_policies', 'owasptop10applicationsecurityrisks2007',
                      'ece17001-da82-459a-a163-901549c37b6d')
        self.conf_get('webinspect_policies', 'owasptop10applicationsecurityrisks2010',
                      '8a7152d5-2637-41e0-8b14-1330828bb3b1')
        self.conf_get('webinspect_policies', 'passivescan', '40bf42fb-86d5-4355-8177-4b679ef87518')
        self.conf_get('webinspect_policies', 'platform', 'f9ae1fc1-3aba-4559-b243-79e1a98fd456')
        self.conf_get('webinspect_policies', 'privilegeescalation', 'bab6348e-2a23-4a56-9427-2febb44a7ac4')
        self.conf_get('webinspect_policies', 'qa', '5b4d7223-a30f-43a1-af30-0cf0e5cfd8ed')
        self.conf_get('webinspect_policies', 'quick', 'e30efb2a-24b0-4a7b-b256-440ab57fe751')
        self.conf_get('webinspect_policies', 'safe', 'def6a5b3-d785-40bc-b63b-6b441b315bf0')
        self.conf_get('webinspect_policies', 'soap', 'a7eb86b8-c3fb-4e88-bc59-5253887ea5b1')
        self.conf_get('webinspect_policies', 'sqlinjection', '6df62f30-4d47-40ec-b3a7-dad80d33f613')
        self.conf_get('webinspect_policies', 'standard', 'cb72a7c2-9207-4ee7-94d0-edd14a47c15c')
        self.conf_get('webinspect_policies', 'transportlayersecurity', '0fa627de-3f1c-4640-a7d3-154e96cda93c')

        self.conf_get('emailer', 'smtp_host', 'smtp.example.com')
        self.conf_get('emailer', 'smtp_port', '25')
        self.conf_get('emailer', 'from_address', 'webbreaker-no-reply@example.com')
        self.conf_get('emailer', 'to_address', 'webbreaker-activity@example.com')
        self.conf_get('emailer', 'email_template', """
<html>
<head></head>
<body>
<p>Hello,<br /><br />
The following scan has logged new activity:
<ul>
<li>Attack traffic source: {0}</li>
<li>Attack traffic target(s):</li>
<ul>
{4}
</ul>
<li>Scan name: {1}</li>
<li>Scan ID: {2}</li>
<li><b>Action: {3}</b></li>
</ul>
</p>
<p>
Questions? Concerns? Please contact us in our Hipchat room, &quot;WebBreaker Activity&quot;,
or <a href="mailto:webbreaker-team@example.com">email us</a>.
</p>
<p>
Want to manage your subscription to these emails? Use <a href="http://wiki.example.com/index.php/GroupID">GroupID</a>, and
add/remove yourself from webbreaker-activity.
</p>
</body>
</html>
        """)

        self.conf_get('agent_emailer', 'smtp_host', 'smtp.example.com')
        self.conf_get('agent_emailer', 'smtp_port', '25')
        self.conf_get('agent_emailer', 'from_address', 'webbreaker-no-reply@example.com')
        self.conf_get('agent_emailer', 'default_to_address', '')
        self.conf_get('agent_emailer', 'chatroom', '')
        self.conf_get('agent_emailer', 'email_template', """
<html>
<head></head>
<body>
<p>Hello,<br /><br />
The following static scan has logged new activity:
<ul>
<li>Git Repository: {0}</li>
<li>Results available at: {1}</li>
<li>Scan name: {2}</li>
<li>Scan ID: {3}</li>
<li><b>Scan State: {4}</b></li>
</ul>
</p>
<p>
Questions? Concerns? Please contact us in our chat room, &quot;{5}&quot;,
or <a href="mailto:webbreaker-team@example.com">email us</a>.
</p>
<p>
Want to manage your subscription to these emails? Use <a href="http://wiki.example.com/index.php/GroupID">GroupID</a>, and
add/remove yourself from webbreaker-activity.
</p>
</body>
</html>
        """)
