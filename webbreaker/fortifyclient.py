#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import socket
from webbreaker.webbreakerhelper import WebBreakerHelper
from webbreaker.webbreakerlogger import Logger
from fortifyapi.fortify import FortifyApi


class FortifyClient(object):
    # Added new Fortify SSC Attribute values
    def __init__(self, fortify_url, business_risk_ranking=None, development_phase=None, development_strategy=None, accessibility=None, 
                 custom_attribute=None, project_template=None, application_name=None, fortify_username=None, fortify_password=None,
                 scan_name=None, extension=None, token=None):
        self.ssc_server = fortify_url
        # Added new Fortify SSC Attribute values
        self.business_risk_ranking = business_risk_ranking
        self.development_phase = development_phase
        self.development_strategy = development_strategy
        self.accessibility = accessibility
        self.custom_attribute = custom_attribute                
        self.project_template = project_template
        self.application_name = application_name
        self.user = fortify_username
        self.password = fortify_password
        self.fortify_version = scan_name
        self.extension = extension
        self.runenv = WebBreakerHelper.check_run_env()
        self.token = token
        
        # Add limited debugging 
        Logger.app.debug("ssc_server: {}".format(self.ssc_server))
        Logger.app.debug("business_risk_ranking: {}".format(self.business_risk_ranking))
        Logger.app.debug("development_phase: {}".format(self.development_phase))
        Logger.app.debug("development_strategy: {}".format(self.development_strategy))
        Logger.app.debug("accessibility: {}".format(self.accessibility))
        Logger.app.debug("custom_attribute: {}".format(self.custom_attribute))
        if not token:
            self.token = self.get_token()

        if not self.token:
            raise ValueError("Unable to obtain a Fortify API token.")

    def get_token(self):
        try:
            api = FortifyApi(self.ssc_server, username=self.user, password=self.password, verify_ssl=False)
            response = api.get_token()
            if response.success:
                token = response.data['data']['token']
                return token
            else:
                Logger.app.critical(response.message)
        except Exception as e:
            if hasattr(e, 'message'):
                Logger.app.critical("Exception while getting Fortify token: {0}".format(e.message))

        return None

    def __get_project_id__(self, project_name):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response = api.get_projects()
        if response.success:
            for project in response.data['data']:
                if project['name'] == project_name:
                    return project['id']
        return None

    def __project_version_description__(self):
        if self.runenv == "jenkins":
            return "WebInspect scan from WebBreaker " + os.getenv('JOB_URL', "jenkins server")
        else:
            return "WebBreaker scan from WebBreaker host " + socket.getfqdn()

    def __create_project_version__(self):
        """
        Create, add required attributes to, and commit a new project version
        :return: The new project_version_id if successful. Otherwise, None.
        """
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        try:
            response = api.create_project_version(project_name=self.application_name,
                                                  project_id=self.__get_project_id__(self.application_name),
                                                  project_template=self.project_template,
                                                  version_name=self.fortify_version,
                                                  description=self.__project_version_description__())

            if not response.success:
                raise ValueError("Failed to create a new project version")

            project_version_id = response.data['data']['id']

            # At Target, only one attribute is required
            response = api.add_project_version_attribute(project_version_id=project_version_id,
                                                         attribute_definition_id=self.__get_attribute_definition_id__(
                                                             search_expression='name:"CI Number"'),
                                                         value='New WebBreaker Application',
                                                         values=[])
            if not response.success:
                raise ValueError("Failed to create required project version attribute")

            response = api.commit_project_version(project_version_id=project_version_id)
            if not response.success:
                raise ValueError("Failed to commit new project version")
                # Logger.app.debug("Created new project version id {0}".format(project_version_id))
            return project_version_id

        except Exception as e:
            Logger.app.critical("Exception trying to create project version. {0}".format(e.message))

        return None

    def __create_new_project_version__(self):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)

        try:
            # Requires both project name and id for initial PV creation
            response = api.create_new_project_version(project_name=self.application_name,
                                                      project_template=self.project_template,
                                                      version_name=self.fortify_version,
                                                      description=self.__project_version_description__())

            if not response.success:
                raise ValueError("Failed to create a new project version")

            project_version_id = response.data['data']['id']
            project_id = response.data['data']['project']['id']

            """
            At Target, only one attribute is required
            TODO: Treatment of all required attributes development_strategy, accessability, custom_attribute, etc. 
            may accept null values (unconfirmed?), additional conditions need to be placed here to successfully complete this response.
            For example default SSC installations require attributeDefinitionId 1, 5, 6, and 7, however other deployments may have a single
            custom_attribute as is implemented below.  See also 
            https://github.com/target/fortifyapi/blob/134477ef708e63d8c7b555741f5c69610abad920/fortifyapi/fortify.py#L105
            search_expression='name:"CI Number"'
            """
            response = api.add_project_version_attribute(project_version_id=project_version_id,
                                                         attribute_definition_id=self.__get_attribute_definition_id__(
                                                             search_expression=custom_attribute),
                                                         value='New WebBreaker Application',
                                                         values=[])
            # Debug for above response
            Logger.app.debug("response before --->> {}".format(response))
            
            if not response.success:
                raise ValueError("Failed to create required project version attribute")

            response = api.commit_project_version(project_version_id=project_version_id)
            Logger.app.debug("response after --->> {}".format(response))
            
            if not response.success:
                raise ValueError("Failed to commit new project version")
                # Logger.app.debug("Created new project version id {0}".format(project_version_id))
        except (AttributeError, UnboundLocalError) as e:
            Logger.app.critical("Exception creating project version. {0}".format(e))

        return project_version_id

    def __get_attribute_definition_id__(self, search_expression):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response = api.get_attribute_definition(search_expression=search_expression)
        if response.success:
            return response.data['data'][0]['id']
        else:
            return None

    def __get_project_version__(self):
        """
        If a project version already exists, return it's project_version_id
        If a project version does NOT exist, create it and return it's project_version_id
        If none of the above succeeds, log the reason(s) and return None
        :return:
        """
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        try:
            response = api.get_all_project_versions()  # api should support a search expression here. alas...
            if response.success:
                for project_version in response.data['data']:
                    if project_version['project']['name'] == self.application_name:
                        if project_version['name'] == self.fortify_version:
                            # we have a matching project version
                            Logger.app.debug("Found existing project version {0}".format(project_version['id']))
                            return project_version['id']
                # Didn't find a matching project version, verify that our project exists
                for project_version in response.data['data']:
                    if project_version['project']['name'] == self.application_name:
                        # Our project exsits, so create a new version
                        return self.__create_project_version__()
                # Let upload_scan know that our project doesn't exist
                return -2
            elif "401" in response.message:
                # Avoid printing error for invalid token. Return -1 to reauth
                return -1
            else:
                Logger.app.critical("Failed to get project version. {0}".format(response.message))
        except Exception as e:
            Logger.app.critical("Exception trying to get project version. {0}".format(e.message))

        return None

    def upload_scan(self, file_name):
        try:
            file_name = self.trim_ext(file_name)
            api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
            project_version_id = self.__get_project_version__()
            # If our project doesn't exist, exit upload_scan
            if project_version_id == -1:
                return -1
            project_id = self.__get_project_id__(self.application_name)
            if not project_id:
                project_version_id = self.__create_new_project_version__()
            if not project_version_id:
                project_version_id = self.__create_project_version__()
            if project_version_id:
                response = api.upload_artifact_scan(file_path=('{0}.{1}'.format(file_name, self.extension)),
                                                    project_version_id=project_version_id)

            if response.success:
                Logger.console.info(
                    "Your scan file {0}.{1}, has been successfully uploaded to {2}!".format(file_name,
                                                                                            self.extension,
                                                                                            self.ssc_server))
            elif not response.success and "401" in response.message:
                return response.response_code
            else:
                Logger.app.error("Error uploading {0}.{1}!!!".format(self.fortify_version, self.extension))

        except UnboundLocalError as e:
            Logger.app.critical("Exception trying to create SSC project version: {}".format(e.message))

        return response

    def list_projects(self):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response = api.get_projects()
        if response.success:
            Logger.console.info("{0:^5} {1:30}".format('ID', 'Name'))
            Logger.console.info("{0:5} {1:30}".format('-' * 5, '-' * 30))
            for proj in response.data['data']:
                Logger.console.info("{0:^5} {1:30}".format(proj['id'], proj['name']))
        return None

    def list_versions(self):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        Logger.app.debug("API: {}".format(api))
        response = api.get_all_project_versions()
        if response.success:
            Logger.console.info("{0:^8} {1:30} {2:30}".format('ID', 'Application', 'Version'))
            Logger.console.info("{0:8} {1:30} {2:30}".format('-' * 8, '-' * 30, '-' * 30))
            for version in response.data['data']:
                Logger.console.info(
                    "{0:8} {1:30} {2:30}".format(version['id'], version['project']['name'], version['name']))
        elif not response.success and "401" in response.message:
            return response.response_code
        return None

    def list_application_versions(self, application):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response = api.get_all_project_versions()
        if response.success:
            Logger.console.info("{0:^8} {1:30} {2:30}".format('ID', 'Application', 'Version'))
            Logger.console.info("{0:8} {1:30} {2:30}".format('-' * 8, '-' * 30, '-' * 30))
            for version in response.data['data']:
                if version['project']['name'] == application:
                    Logger.console.info(
                        "{0:8} {1:30} {2:30}".format(version['id'], version['project']['name'], version['name']))
        elif not response.success and "401" in response.message:
            return response.response_code
        return None

    def find_version_id(self, version_name):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response = api.get_all_project_versions()
        if response.success:
            for version in response.data['data']:
                if version['project']['name'] == self.application_name:
                    if version['name'] == version_name:
                        return version['id']

        return False

    def download_scan(self, version_id):
        api = FortifyApi(self.ssc_server, token=self.token, verify_ssl=False)
        response, file_name = api.download_artifact_scan(version_id)
        if response.success:
            file_content = response.data
            with open(file_name, 'wb') as f:
                f.write(file_content)
            return file_name
        else:
            Logger.app.error("Error downloading scan file: {}".format(response.message))
            return False

    def build_pv_url(self):
        try:
            version_id = self.__get_project_version__()

            if version_id == -1:
                # This signals that an auth error occurred, CLI will attempt to reauth
                return -1
            if not self.__get_project_id__(self.application_name):
                version_id = self.__create_new_project_version__()
                if not version_id:
                    Logger.console.error("Unable to create new project version, see logs for details.")
                    return None
            if not version_id:
                version_id = self.__create_project_version__()
                if not version_id:
                    Logger.console.error("Unable to create new project version, see logs for details.")
                    return None
            if self.ssc_server[-1] == '/':
                self.ssc_server = self.ssc_server[:-1]

        except UnboundLocalError as e:
            Logger.app.critical("Exception trying to build Project Version URL. {0}".format(e))

        return self.ssc_server + '/ssc/html/ssc/index.jsp#!/version/' + str(version_id)

    def trim_ext(self, file, list=False):
        try:
            if list:
                result = []
                for f in file:
                    result.append(os.path.splitext(os.path.basename(f))[0])
                return result
            else:
                return os.path.splitext(os.path.basename(file))[0]
        except (TypeError, AttributeError):
            return file
