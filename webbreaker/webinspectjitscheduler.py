#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import webinspectapi.webinspect as webinspectapi
from webbreaker.webbreakerlogger import Logger


class WebInspectJitScheduler(object):
    def __init__(self, endpoints, size_list, size_needed='size_large', username=None, password=None):
        self.endpoints = endpoints
        # TODO need to change size_list to make more sense, change to priority high/low to increase readability.
        self.size_list = size_list
        self.size_needed = size_needed
        self.username = username
        self.password = password
        self.max_scans = self.__convert_size_to_count__()

        Logger.app.debug("endpoints: {}".format(self.endpoints))
        Logger.app.debug("size_list: {}".format(self.size_list))
        Logger.app.debug("size_needed: {}".format(self.size_needed))
        Logger.app.debug("username: {}".format(self.username))
        Logger.app.debug("password: {}".format(self.password))
        Logger.app.debug("max_scans: {}".format(self.max_scans))

    def get_endpoint(self):

        try:
            endpoint = self.__get_available_endpoints__()
            if endpoint:
                Logger.app.info("WebBreaker has selected: {} for your WebInspect scan.".format(endpoint[0]))
            else:
                Logger.app.error("No available WebInspect servers are available, due to misconfigation or "
                                 "all scan engines are fully utilized!")
            return endpoint[0]
        except Exception as e:  # Ugly. Not sure what to expect for problems, so Pokemon handling, catch'em all :(
            Logger.app.error("Error has occured with identifying an appropriate WebInspect scan engine. {}".format(e))
            return None

    # TODO refactor to remove size_needed from the config file and change so that this doesn't use 1 or 2 high/medium
    # TODO     but instead uses priority_low or priority_high since that is more readable.
    def __convert_size_to_count__(self):
        max_scans = None
        for size in self.size_list:
            if size[0] == self.size_needed:
                max_scans = size[1]
        return max_scans

    def __get_available_endpoints__(self):

        # Expectation is that multiple instances of this program start simultaneously,
        # and there is significant delay b/w the selection of an endpoint and the endpoint
        # starting a scan. In an effort to prevent the same endpoint being selected as "available"
        # by multiple program instances, we will randomize the available endpoints AND
        # introduce a random/arbitrary length delay before testing. Might help, might not.
        # Need a re-architecture or some kind of inter-process communication?
        possible_endpoints = self.__get_possible_endpoints__(max_concurrent_scans=self.max_scans)
        Logger.app.debug("possible_endpoints: {}".format(possible_endpoints))
        random.shuffle(possible_endpoints)
        # time.sleep(random.randint(0, 30))
        for endpoint in possible_endpoints:
            if self.__is_endpoint_available__(endpoint=endpoint, max_concurrent_scans=self.max_scans):
                Logger.app.debug("We have an endpoint: {}".format(endpoint))
                return endpoint

        return None

    def __get_possible_endpoints__(self, max_concurrent_scans):
        """
        Given the provided max_concurrent_scans value, return a list of endpoints that are capable of running
        exactly than many scans. This does NOT take into consideration how many scans are currently running,
        it's just to determine if it's possible.
        :param max_concurrent_scans: 
        :return: 
        """
        possible_endpoints = []
        for endpoint in self.endpoints:
            if endpoint[1] == max_concurrent_scans:
                possible_endpoints.append(endpoint)
        return possible_endpoints

    def __is_endpoint_available__(self, endpoint, max_concurrent_scans):
        """
        Determine if the provided endpoint is available. (i.e. are there less than max_concurrent_scans
        with a Status of Running on the endpointß
        :param endpoint: The endpoint to evaluate
        :param max_concurrent_scans:  The max number of allowed scans to be running on the endpoint
        """
        api = webinspectapi.WebInspectApi(endpoint[0], verify_ssl=False, username=self.username, password=self.password)
        response = api.list_scans()
        active_scans = 0
        if response.success:
            for scan in response.data:
                if scan['Status'] == 'Running':
                    active_scans += 1
                    Logger.app.debug('WebInspect scanner {} has {} active scans'.format(endpoint, str(active_scans)))
            if active_scans < int(max_concurrent_scans):
                return True

        return False
