#!/usr/bin/env python
# -*-coding:utf-8-*-

import random
import string
import webinspectapi.webinspect as webinspectapi
from webbreaker.webbreakerlogger import Logger
from webbreaker.confighelper import Config


class WebinspectProxyClient(object):
    def __init__(self, proxy_name, port, host, username=None, password=None):
        self.host = host
        self.username = username
        self.password = password
        if proxy_name:
            self.proxy_name = proxy_name
        else:
            self.proxy_name = "webinspect" + "-" + "".join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

        if port:
            self.port = port
        else:
            self.port = ""

    def get_cert_proxy(self):
        path = Config().cert

        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        response = api.cert_proxy()
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            try:
                with open(path, 'wb') as f:
                    f.write(response.data)
                    Logger.app.info('Cert has downloaded to\t:\t{}'.format(path))
            except UnboundLocalError as e:
                Logger.app.error('Error saving cert locally {}'.format(e))
        else:
            Logger.app.error('Unable to retrieve cert.\n ERROR: {} '.format(response.message))

    def start_proxy(self):

        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        response = api.start_proxy(self.proxy_name, self.port, "")
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            return response.data
        else:
            Logger.app.critical("{}".format(response.message))

    def delete_proxy(self):

        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        response = api.delete_proxy(self.proxy_name)
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            Logger.app.info("Proxy: '{0}' deleted from '{1}'".format(self.proxy_name, self.host))
        else:
            Logger.app.critical("{}".format(response.message))

    def list_proxy(self):
        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        response = api.list_proxies()
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            return response.data
        else:
            Logger.app.critical("{}".format(response.message))

    def download_proxy(self, webmacro, setting):
        Logger.app.debug('Downloading from: {}'.format(self.proxy_name))
        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        if webmacro:
            response = api.download_proxy_webmacro(self.proxy_name)
            extension = 'webmacro'
        elif setting:
            response = api.download_proxy_setting(self.proxy_name)
            extension = 'xml'
        else:
            Logger.app.error("Please enter a file type to download.")
            return 1
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            try:
                with open('{0}-proxy.{1}'.format(self.proxy_name, extension), 'wb') as f:
                    Logger.app.info('Scan results file is available: {0}-proxy.{1}'.format(self.proxy_name, extension))
                    f.write(response.data)
            except UnboundLocalError as e:
                Logger.app.error('Error saving file locally {}'.format(e))
        else:
            Logger.app.error('Unable to retrieve file. {} '.format(response.message))

    def upload_proxy(self, upload_file):
        Logger.app.info("Uploading to: '{}'".format(self.proxy_name))
        try:
            api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
            response = api.upload_webmacro_proxy(self.proxy_name, upload_file)
            if response.response_code == 401:
                Logger.app.critical("An Authorization Error occured.")
                exit(1)
            if response.success:
                Logger.app.info("Uploaded '{0}' to '{1}' on: {2}.".format(upload_file, self.proxy_name, self.host))
            else:
                Logger.app.error("Uploading {0} gave error: {1}".format(upload_file, response.message))
                return 1
        except (ValueError, UnboundLocalError) as e:
            Logger.app.error("Error uploading policy {}".format(e))
            return 1

    def get_proxy(self):
        api = webinspectapi.WebInspectApi(self.host, verify_ssl=False, username=self.username, password=self.password)
        response = api.get_proxy_information(self.proxy_name)
        if response.response_code == 401:
            Logger.app.critical("An Authorization Error occured.")
            exit(1)
        if response.success:
            return response.data
