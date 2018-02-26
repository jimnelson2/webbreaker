#!/usr/bin/env python
# -*-coding:utf-8-*-

import os
import json
import webinspectapi.webinspect as webinspectapi
from webbreaker.webbreakerlogger import Logger
import sys
from exitstatus import ExitStatus


class WebinspectQueryClient(object):
    def __init__(self, host, username=None, password=None):
        self.host = host
        self.username = username
        self.password = password
        Logger.app.info("Using webinspect server: -->{}<-- for query".format(self.host))

    def get_scan_by_name(self, scan_name):
        """
        Search Webinspect server for a scan matching scan_name
        :param scan_name:
        :return: List of search results
        """
        scan_name = self.trim_ext(scan_name)
        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)

        response = api.get_scan_by_name(scan_name)

        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            sys.exit(ExitStatus.failure)

        return response.data

    def export_scan_results(self, scan_id, scan_name, extension):
        """
        Download scan as a xml for Threadfix or other Vuln Management System
        :param scan_id:
        :param scan_name:
        :param extension:
        """
        try:
            scan_name = self.trim_ext(scan_name)
            Logger.app.debug('Exporting scan: {}'.format(scan_id))
            detail_type = 'Full' if extension == 'xml' else None
            api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
            response = api.export_scan_format(scan_id, extension, detail_type)

            if response.success:
                try:
                    with open('{0}.{1}'.format(scan_name, extension), 'wb') as f:
                        Logger.app.info('Scan results file is available: {0}.{1}'.format(scan_name, extension))
                        f.write(response.data)
                except UnboundLocalError as e:
                    Logger.app.error('Error saving file locally {}'.format(e))
            elif response.response_code == 401:
                Logger.app.critical("An Authorization Error occured.")
                sys.exit(ExitStatus.failure)
            else:
                Logger.app.error('Unable to retrieve scan results. {} '.format(response.message))
        except (ValueError, UnboundLocalError, NameError) as e:
            Logger.app.error("There was an error exporting scan results: {}".format(e))

    def list_scans(self):
        """
        List all scans found on host
        :return: response.data from the Webinspect server
        """
        try:
            api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
            response = api.list_scans()
            if response.success:
                return response.data
            elif response.response_code == 401:
                Logger.app.critical("An Authorization Error occured.")
                sys.exit(ExitStatus.failure)
            else:
                Logger.app.critical("{}".format(response.message))
        except (ValueError, UnboundLocalError, NameError) as e:
            Logger.app.error("There was an error listing WebInspect scans! {}".format(e))

    def get_scan_status(self, scan_guid):
        """
        Get scan status from the Webinspect server
        :param scan_guid:
        :return: Current status of scan
        """
        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        try:
            response = api.get_current_status(scan_guid)
            if response.response_code == 401:
                Logger.app.critical("An Authorization Error occured.")
                sys.exit(ExitStatus.failure)
            status = json.loads(response.data_json())['ScanStatus']
            return status
        except (ValueError, TypeError, UnboundLocalError) as e:
            Logger.app.error("There was an error getting scan status: {}".format(e))
            return None

    def trim_ext(self, file):
        return os.path.splitext(os.path.basename(file))[0]
