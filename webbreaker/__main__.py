#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (brandon.spruth2@target.com), Jim Nelson (jim.nelson2@target.com)," \
             "Matt Dunaj (matthew.dunaj@target.com), Kyler Witting (Kyler.Witting@target.com)"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson", "Matthew Dunaj", "Kyler Witting"]
__status__ = "Production"
__license__ = "MIT"

try:
    from signal import *
    from urlparse import urlparse
    import urllib
except ImportError:  # Python3
    import html.entities as htmlentitydefs
    from urllib.parse import urlparse
    import html.parser as HTMLParser
    import urllib.request as urllib

import requests.exceptions
import click
from webbreaker import __version__ as version
from webbreaker.webbreakerlogger import Logger
from webbreaker.webinspectconfig import WebInspectConfig, WebInspectAuthConfig
from webbreaker.webinspectclient import WebinspectClient
from webbreaker.webinspectqueryclient import WebinspectQueryClient
from webbreaker.fortifyclient import FortifyClient
from webbreaker.fortifyconfig import FortifyConfig
from webbreaker.webinspectscanhelpers import create_scan_event_handler
from webbreaker.webinspectscanhelpers import scan_running
from webbreaker.webbreakerhelper import WebBreakerHelper
from webbreaker.gitclient import GitClient, write_agent_info, read_agent_info, format_git_url
from webbreaker.secretclient import SecretClient
from webbreaker.threadfixclient import ThreadFixClient
from webbreaker.threadfixconfig import ThreadFixConfig
from webbreaker.webinspectproxyclient import WebinspectProxyClient
from webbreaker.logexceptionhelper import LogExceptionHelper
import re
import sys
from exitstatus import ExitStatus
import subprocess

logexceptionhelper = LogExceptionHelper()

try:
    from git.exc import GitCommandError
except ImportError as e:  # module will fail if git is not installed
    Logger.app.error("Please install the git client or add it to your PATH variable ->"
                     " https://git-scm.com/download.  See log {}!!!".format
                     (Logger.app_logfile, e.message))

handle_scan_event = None
reporter = None


class Config(object):
    def __init__(self):
        self.debug = False


pass_config = click.make_pass_decorator(Config, ensure=True)


def fortify_prompt():
    fortify_user = click.prompt('Fortify user')
    fortify_password = click.prompt('Fortify password', hide_input=True)
    return fortify_user, fortify_password

def webinspect_prompt():
    webinspect_user = click.prompt('WebInspect user')
    webinspect_password = click.prompt('WebInspect password', hide_input=True)
    return webinspect_user, webinspect_password


@click.group(help=WebBreakerHelper().webbreaker_desc())
@pass_config
def cli(config):
    # Show something pretty to start
    webbreaker_ascii = WebBreakerHelper.ascii_motd()
    b = WebBreakerHelper.banner(text=webbreaker_ascii)

    sys.stdout.write(str("{0}\nVersion {1}\n".format(b, version)))
    sys.stdout.write(str("Logging to files: {}\n".format(Logger.app_logfile)))
    SecretClient().verify_secret()


@cli.group(short_help="Interaction with Webinspect API",
           help=WebBreakerHelper().webinspect_desc(),
           )
@pass_config
def webinspect(config):
    pass


@webinspect.command(name='scan',
                    short_help="Launch WebInspect scan",
                    help=WebBreakerHelper().webinspect_scan_desc()
                    )
@click.option('--username',
              required=False,
              help="Specify WebInspect username")
@click.option('--password',
              required=False,
              help="Specify WebInspect password")
@click.option('--allowed_hosts',
              required=False,
              multiple=True,
              help="Override host(s) from start_urls option")
@click.option('--fortify_user',
              required=False,
              help="Auth Fortify user to upload WebInspect scan")
@click.option('--login_macro',
              required=False,
              help="Assign login macro to auth app")
@click.option('--scan_name',
              type=str,
              required=False,
              help="Assign name of scan")
@click.option('--scan_mode',
              required=False,
              type=click.Choice(['crawl', 'scan', 'all']),
              help="Override setting scan mode value")
@click.option('--scan_policy',
              required=False,
              help="Assign WebInspect policies,")
@click.option('--scan_scope',
              required=False,
              help="Assign all, strict, children, OR ancestors")
@click.option('--scan_start',
              required=False,
              type=click.Choice(['url', 'macro']),
              help="Assign type of scan to be performed")
@click.option('--settings',
              type=str,
              default='Default',
              required=True,
              help="Specify setting file")
@click.option('--size',
              required=False,
              type=click.Choice(['medium', 'large']),
              help="Specify scanner size")
@click.option('--start_urls',
              required=False,
              multiple=True,
              help="Assign starting url(s)")
@click.option('--upload_policy',
              required=False,
              help="Upload policy file to WebInspect")
@click.option('--upload_settings',
              required=False,
              help="Upload .xml settings file")
@click.option('--upload_webmacros',
              required=False,
              help="Upload webmacro to WebInspect")
@click.option('--workflow_macros',
              required=False,
              multiple=True,
              help="Assign workflow macro(s)")

@pass_config
def scan(config, **kwargs):
    try:
        # Setup our configuration...
        webinspect_config = WebInspectConfig()
        Logger.app.debug("Webinspect Config: {}".format(webinspect_config))

        ops = kwargs.copy()

        username = ops['username']
        password = ops['password']

        auth_config = WebInspectAuthConfig()
        if auth_config.authenticate:
            if username is not None and password is not None:
                pass
            elif auth_config.username and auth_config.password:
                username = auth_config.username
                password = auth_config.password
            else:
                username, password = webinspect_prompt()
        else:
            username = None
            password = None

        # Convert multiple args from tuples to lists
        ops['allowed_hosts'] = list(kwargs['allowed_hosts'])
        ops['start_urls'] = list(kwargs['start_urls'])
        ops['workflow_macros'] = list(kwargs['workflow_macros'])

        # ...as well as pulling down webinspect server config files from github...
        webinspect_config.fetch_webinspect_configs(ops)

        # ...and settings...
        webinspect_settings = webinspect_config.parse_webinspect_options(ops)

        # OK, we're ready to actually do something now

        # The webinspect client is our point of interaction with the webinspect server farm
        webinspect_client = WebinspectClient(webinspect_settings, username=username, password=password)

        # if a scan policy has been specified, we need to make sure we can find/use it
        webinspect_client.verify_scan_policy(webinspect_config)

        # Upload whatever configurations have been provided...
        # All skipped unless explicitly declared in CLI
        if webinspect_client.webinspect_upload_settings:
            webinspect_client.upload_settings()

        if webinspect_client.webinspect_upload_webmacros:
            webinspect_client.upload_webmacros()

        # if there was a provided scan policy, we've already uploaded so don't bother doing it again. hack.
        if webinspect_client.webinspect_upload_policy and not webinspect_client.scan_policy:
            webinspect_client.upload_policy()

        Logger.app.info("Launching a scan")
        # ... And launch a scan.

        try:
            scan_id = webinspect_client.create_scan()
            Logger.app.debug("Scan ID: {}".format(scan_id))

            if scan_id:
                # Initialize handle_scan_event first then go to webinspectscanhelpers

                global handle_scan_event
                Logger.app.debug("handle_scan_event: {}".format(handle_scan_event))
                handle_scan_event = create_scan_event_handler(webinspect_client, scan_id, webinspect_settings)
                handle_scan_event('scan_start')
                Logger.app.debug("Starting scan handling")
                Logger.app.info("Execution is waiting on scan status change")
                with scan_running():
                    webinspect_client.wait_for_scan_status_change(scan_id)  # execution waits here, blocking call
                status = webinspect_client.get_scan_status(scan_id)
                Logger.app.info("Scan status has changed to {0}.".format(status))

                if status.lower() != 'complete':  # case insensitive comparison is tricky. this should be good enough for now
                    Logger.app.error(
                        "See the WebInspect server scan log --> {}, typically the application to be scanned is"
                        "unavailable.".format(WebInspectConfig().endpoints))
                    Logger.app.error('Scan is incomplete and is unrecoverable. WebBreaker will exit!!')
                    handle_scan_event('scan_end')
                    sys.exit(ExitStatus.failure)

            webinspect_client.export_scan_results(scan_id, 'fpr')
            webinspect_client.export_scan_results(scan_id, 'xml')
            # TODO add json export

        except (
        requests.exceptions.ConnectionError, requests.exceptions.HTTPError, NameError, KeyError, IndexError) as e:
            Logger.app.error(
                # "Unable to connect to WebInspect {0}, see also: {1}".format(webinspect_settings['webinspect_url'], e))
                "WebInspect scan was not properly configured, unable to launch!! see also: {}".format(e))
            raise

        # If we've made it this far, our new credentials are valid and should be saved
        if username is not None and password is not None and not auth_config.has_auth_creds():
            auth_config.write_username(username)
            auth_config.write_password(password)

        try:
            handle_scan_event('scan_end')
            Logger.app.info("Webbreaker WebInspect has completed.")

        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError, TypeError, NameError, KeyError,
                IndexError) as e:
            Logger.app.error(
                # "Unable to connect to WebInspect {0}, see also: {1}".format(webinspect_settings['webinspect_url'], e))
                "Webbreaker WebInspect scan was unable to complete! See also: {}".format(e))
            raise

    except:
        Logger.app.error("WebBreaker exited due to an exception")



@webinspect.command(name='list',
                    short_help="List WebInspect scans",
                    help=WebBreakerHelper().webinspect_list_desc())
@click.option('--scan_name',
              required=False,
              help="Specify WebInspect scan name")
@click.option('--server',
              required=False,
              multiple=True,
              help="Specify WebInspect server URL(S)")
@click.option('--username',
              required=False,
              help="Specify WebInspect username")
@click.option('--password',
              required=False,
              help="Specify WebInspect password")
@pass_config
def webinspect_list(config, server, scan_name, username, password):
    if len(server):
        servers = []
        for s in server:
            servers.append(s)
    else:
        servers = [(e[0]) for e in WebInspectConfig().endpoints]

    auth_config = WebInspectAuthConfig()
    if auth_config.authenticate:
        if username is not None and password is not None:
            pass
        elif auth_config.username and auth_config.password:
            username = auth_config.username
            password = auth_config.password
        else:
            username, password = webinspect_prompt()
    else:
        username = None
        password = None
    for server in servers:
        query_client = WebinspectQueryClient(host=server, username=username,
                                             password=password)
        if scan_name:
            results = query_client.get_scan_by_name(scan_name)
            if results and len(results):
                print("Scans matching the name {} found on {}".format(scan_name, server))
                print("{0:80} {1:40} {2:10}".format('Scan Name', 'Scan ID', 'Scan Status'))
                print("{0:80} {1:40} {2:10}\n".format('-' * 80, '-' * 40, '-' * 10))
                for match in results:
                    print("{0:80} {1:40} {2:10}".format(match['Name'], match['ID'], match['Status']))
            else:
                Logger.app.error("No scans matching the name {} were found on {}".format(scan_name, server))

        else:
            results = query_client.list_scans()
            if results and len(results):
                print("Scans found on {}".format(server))
                print("{0:80} {1:40} {2:10}".format('Scan Name', 'Scan ID', 'Scan Status'))
                print("{0:80} {1:40} {2:10}\n".format('-' * 80, '-' * 40, '-' * 10))
                for scan in results:
                    print("{0:80} {1:40} {2:10}".format(scan['Name'], scan['ID'], scan['Status']))
            else:
                print("No scans found on {}".format(server))
        print('\n\n\n')
    # If we've made it this far, our new credentials are valid and should be saved
    if username is not None and password is not None and not auth_config.has_auth_creds():
        auth_config.write_username(username)
        auth_config.write_password(password)


@webinspect.command(name='servers',
                    short_help="List all WebInspect servers",
                    help=WebBreakerHelper().webinspect_servers_desc())
@pass_config
def servers_list(config):
    servers = [(e[0]) for e in WebInspectConfig().endpoints]
    print('\n\nFound WebInspect Servers')
    print('-' * 30)
    for server in servers:
        print(server)
    print('\n')


@webinspect.command(name='download',
                    short_help="Download WebInspect scan",
                    help=WebBreakerHelper().webinspect_download_desc())
@click.option('--server',
              required=True,
              help="Specify WebInspect server URL")
@click.option('--scan_name',
              required=True,
              help="WebInspect scan name to download")
@click.option('--scan_id',
              required=False,
              help="WebInspect scan ID to download")
@click.option('-x',
              required=False,
              default="fpr",
              help="Assign scan extension")
@click.option('--username',
              required=False,
              help="Specify WebInspect username")
@click.option('--password',
              required=False,
              help="Specify WebInspect password")
@pass_config
def download(config, server, scan_name, scan_id, x, username, password):

    try:
        auth_config = WebInspectAuthConfig()
        if auth_config.authenticate:
            if username is not None and password is not None:
                pass
            if auth_config.username and auth_config.password:
                username = auth_config.username
                password = auth_config.password
            else:
                username, password = webinspect_prompt()
        else:
            username = None
            password = None

        query_client = WebinspectQueryClient(host=server, username=username, password=password)

        if not scan_id:
            results = query_client.get_scan_by_name(scan_name)
            if len(results) == 0:
                Logger.app.error("No scans matching the name {} where found on this host".format(scan_name))
            elif len(results) == 1:
                scan_id = results[0]['ID']
                Logger.app.info("Scan matching the name {} found.".format(scan_name))
                Logger.app.info("Downloading scan {}".format(scan_name))
                query_client.export_scan_results(scan_id, scan_name, x)
            else:
                Logger.app.info("Multiple scans matching the name {} found.".format(scan_name))
                print("{0:80} {1:40} {2:10}".format('Scan Name', 'Scan ID', 'Scan Status'))
                print("{0:80} {1:40} {2:10}\n".format('-' * 80, '-' * 40, '-' * 10))
                for result in results:
                    print("{0:80} {1:40} {2:10}".format(result['Name'], result['ID'], result['Status']))
        else:
            if query_client.get_scan_status(scan_id):
                query_client.export_scan_results(scan_id, scan_name, x)
            else:
                Logger.console.error("Unable to find scan with ID matching {}".format(scan_id))

    except (UnboundLocalError, TypeError, UnboundLocalError) as e:
        # except (ValueError, UnboundLocalError, TypeError, NameError) as e:
        logexceptionhelper.LogErrorWebInspectDownload(e)

    # If we've made it this far, our new credentials are valid and should be saved
    if username is not None and password is not None and not auth_config.has_auth_creds():
        auth_config.write_username(username)
        auth_config.write_password(password)


@webinspect.command(name='proxy',
                    short_help="Interact with WebInspect proxy",
                    help=WebBreakerHelper().webinspect_proxy_desc())
@click.option('--download',
              required=False,
              is_flag=True,
              help="Flag to specify download")
@click.option('--list',
              required=False,
              is_flag=True,
              help="List WebInspect proxies currently available")
@click.option('--port',
              required=False,
              help="Assign WebInspect proxy port")
@click.option('--proxy_name',
              required=False,
              help="Assign WebInspect proxy ID")
@click.option('--setting',
              required=False,
              is_flag=True,
              help="Flag to download setting file from proxy_name")
@click.option('--server',
              required=False,
              help="Optional URL of specific WebInspect server(s)")
@click.option('--start',
              required=False,
              is_flag=True,
              help="Start a WebInspect proxy service")
@click.option('--stop',
              required=False,
              is_flag=True,
              help="Stop & delete a WebInspect proxy service")
@click.option('--upload',
              required=False,
              help="Webmacro file path to upload")
@click.option('--webmacro',
              required=False,
              is_flag=True,
              help="Flag to download webmacro file from proxy_name")
@click.option('--username',
              required=False,
              help="Specify WebInspect username")
@click.option('--password',
              required=False,
              help="Specify WebInspect password")
def webinspect_proxy(download, list, port, proxy_name, setting, server, start, stop, upload, webmacro, username, password):
    try:
        if server:
            servers = [server]
        else:
            servers = [(e[0]) for e in WebInspectConfig().endpoints]

        auth_config = WebInspectAuthConfig()
        if auth_config.authenticate:
            if username is not None and password is not None:
                pass
            if auth_config.username and auth_config.password:
                username = auth_config.username
                password = auth_config.password
            else:
                username, password = webinspect_prompt()
        else:
            username = None
            password = None

        if list:
            for server in servers:
                proxy_client = WebinspectProxyClient(proxy_name, port, server, username=username, password=password)
                results = proxy_client.list_proxy()
                if results and len(results):
                    print("Proxies found on {}".format(proxy_client.host))
                    print("{0:80} {1:40} {2:10}".format('Scan Name', 'Scan ID', 'Scan Status'))
                    print("{0:80} {1:40} {2:10}\n".format('-' * 80, '-' * 40, '-' * 10))
                    for match in results:
                        print("{0:80} {1:40} {2:10}".format(match['instanceId'], match['address'], match['port']))
                    Logger.app.info("Succesfully listed proxies from: '{}'".format(server))
                else:
                    Logger.app.error("No proxies found on '{}'".format(server))

        elif start:
            server = servers[0]
            proxy_client = WebinspectProxyClient(proxy_name, port, server, username=username, password=password)
            proxy_client.get_cert_proxy()
            result = proxy_client.start_proxy()

            if result and len(result):
                Logger.app.info("Proxy successfully started")
                print("Server\t\t:\t'{}'".format(server))
                print("Instance ID\t:\t{}".format(result['instanceId']))
                print("Address\t\t:\t{}".format(result['address']))
                print("Port\t\t:\t{}".format(result['port']))
            else:
                Logger.app.error("Unable to start proxy on '{}'".format(server))
                sys.exit(ExitStatus.failure)
        elif not proxy_name:
            Logger.app.error("Please enter a proxy name.")
            sys.exit(ExitStatus.failure)

        elif stop:
            for server in servers:

                proxy_client = WebinspectProxyClient(proxy_name, port, server, username=username, password=password)
                result = proxy_client.get_proxy()
                if result:
                    proxy_client.download_proxy(webmacro=False, setting=True)
                    proxy_client.download_proxy(webmacro=True, setting=False)
                    proxy_client.delete_proxy()
                    sys.exit(ExitStatus.success)
                else:
                    Logger.app.error("Proxy: '{}' not found on any server.".format(proxy_name))
                    sys.exit(ExitStatus.failure)

        elif download:
            for server in servers:
                server = 'https://' + server
                proxy_client = WebinspectProxyClient(proxy_name, port, server, username=username, password=password)
                result = proxy_client.get_proxy()
                if result:
                    proxy_client.download_proxy(webmacro, setting)
                    sys.exit(ExitStatus.success)
                else:
                    Logger.app.error("Proxy: '{}' not found on any server.".format(proxy_name))
                    sys.exit(ExitStatus.failure)

        elif upload:
            for server in servers:
                server = 'https://' + server
                proxy_client = WebinspectProxyClient(proxy_name, port, server, username=username, password=password)
                result = proxy_client.get_proxy()
                if result:
                    proxy_client.upload_proxy(upload)
                    sys.exit(ExitStatus.success)
                else:
                    Logger.app.error("Proxy: '{}' not found on any server.".format(proxy_name))
                    sys.exit(ExitStatus.failure)
        else:
            Logger.app.error("Error: No proxy command was given.")
            sys.exit(ExitStatus.failure)

        # If we've made it this far, our new credentials are valid and should be saved
        if username is not None and password is not None and not auth_config.has_auth_creds():
            auth_config.write_username(username)
            auth_config.write_password(password)

    except (UnboundLocalError, EnvironmentError) as e:
        Logger.app.critical("Incorrect WebInspect configurations found!! {}".format(e))
        sys.exit(ExitStatus.failure)


@cli.group(short_help="Interaction with Fortify API",
           help=WebBreakerHelper().fortify_desc(),
           )
@pass_config
def fortify(config):
    pass


@fortify.command(name='list',
                 short_help="List Fortify application versions",
                 help=WebBreakerHelper().fortify_list_desc())
@click.option('--fortify_user',
              required=False,
              help="Specify Fortify username")
@click.option('--fortify_password',
              required=False,
              help="Specify Fortify password")
@click.option('--application',
              required=False,
              help="Specify Fortify app name"
              )
@pass_config
def fortify_list(config, fortify_user, fortify_password, application):
    fortify_config = FortifyConfig()
    try:
        if fortify_user and fortify_password:
            Logger.app.info("Importing Fortify credentials")
            fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                           fortify_username=fortify_user,
                                           fortify_password=fortify_password)
            fortify_config.write_username(fortify_user)
            fortify_config.write_password(fortify_password)
            Logger.app.info("Fortify credentials stored")
        else:
            Logger.app.info("No Fortify username or password provided. Checking config.ini for credentials")
            if fortify_config.has_auth_creds():
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               fortify_username=fortify_config.username,
                                               fortify_password=fortify_config.password)
                Logger.app.info("Fortify username and password successfully found in config.ini")
            else:
                Logger.app.info("Fortify credentials not found in config.ini")
                fortify_user, fortify_password = fortify_prompt()
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               fortify_username=fortify_user,
                                               fortify_password=fortify_password)
                fortify_config.write_username(fortify_user)
                fortify_config.write_password(fortify_password)
                Logger.app.info("Fortify credentials stored")
        if application:
            fortify_client.list_application_versions(application)
        else:
            fortify_client.list_versions()
        Logger.app.info("Fortify list has successfully completed")
    except ValueError:
        Logger.app.error("Unable to obtain a Fortify API token. Invalid Credentials")
        sys.exit(ExitStatus.failure)
    except (AttributeError, UnboundLocalError, TypeError) as e:
        Logger.app.critical("Unable to complete command 'fortify list': {}".format(e))
        sys.exit(ExitStatus.failure)


@fortify.command(name='download',
                 short_help="Download Fortify .fpr scan",
                 help=WebBreakerHelper().fortify_download_desc())
@click.option('--fortify_user',
              required=False,
              help="Specify Fortify username")
@click.option('--fortify_password',
              required=False,
              help="Specify Fortify password")
@click.option('--application',
              required=False,
              help="Specify Fortify app name"
              )
@click.option('--version',
              required=True,
              help="Specify Fortify app version")
@pass_config
def fortify_download(config, fortify_user, fortify_password, application, version):
    fortify_config = FortifyConfig()
    if application:
        fortify_config.application_name = application
    try:
        if fortify_user and fortify_password:
            Logger.app.info("Importing Fortify credentials")
            fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                           project_template=fortify_config.project_template,
                                           application_name=fortify_config.application_name,
                                           fortify_username=fortify_user,
                                           fortify_password=fortify_password)
            fortify_config.write_username(fortify_user)
            fortify_config.write_password(fortify_password)
            Logger.app.info("Fortify credentials stored")
        else:
            Logger.app.info("No Fortify username or password provided. Checking config.ini for credentials")
            if fortify_config.has_auth_creds():
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               project_template=fortify_config.project_template,
                                               application_name=fortify_config.application_name,
                                               fortify_username=fortify_config.username,
                                               fortify_password=fortify_config.password)
                Logger.app.info("Fortify username and password successfully found in config.ini")
            else:
                Logger.app.info("Fortify credentials not found in config.ini")
                fortify_user, fortify_password = fortify_prompt()
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               project_template=fortify_config.project_template,
                                               application_name=fortify_config.application_name,
                                               fortify_username=fortify_user,
                                               fortify_password=fortify_password)
                fortify_config.write_username(fortify_user)
                fortify_config.write_password(fortify_password)
                Logger.app.info("Fortify credentials stored")
        version_id = fortify_client.find_version_id(version)
        if version_id:
            filename = fortify_client.download_scan(version_id)
            if filename:
                Logger.app.info("Scan file for version {} successfully written to {}".format(version_id, filename))
            else:
                Logger.app.error("Scan download for version {} has failed".format(version_id))
        else:
            Logger.app.error("No version matching {} found under {} in Fortify".format(version, application))
    except ValueError:
        Logger.app.error("Unable to obtain a Fortify API token. Invalid Credentials")
    except (AttributeError, UnboundLocalError) as e:
        Logger.app.critical("Unable to complete command 'fortify download': {}".format(e))


@fortify.command(name='upload',
                 short_help="Upload WebInspect scan to Fortify",
                 help=WebBreakerHelper().fortify_upload_desc())
@click.option('--fortify_user',
              required=False,
              help="Specify Fortify username")
@click.option('--fortify_password',
              required=False,
              help="Specify Fortify password")
@click.option('--application',
              required=False,
              help="Assign Fortify app name"
              )
@click.option('--version',
              required=True,
              help="Assign Fortify app version"
              )
@click.option('--scan_name',
              required=False,
              help="Specify name if file name is different than version")
@pass_config
def upload(config, fortify_user, fortify_password, application, version, scan_name):
    fortify_config = FortifyConfig()
    # Fortify only accepts fpr scan files
    x = 'fpr'
    if application:
        fortify_config.application_name = application
    if not scan_name:
        scan_name = version
    try:
        if not fortify_user or not fortify_password:
            Logger.console.info("No Fortify username or password provided. Validating config.ini for secret")
            if fortify_config.has_auth_creds():
                Logger.console.info("Fortify credentials found in config.ini")
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               project_template=fortify_config.project_template,
                                               application_name=fortify_config.application_name, scan_name=version,
                                               extension=x, fortify_username=fortify_config.username,
                                               fortify_password=fortify_config.password)
            else:
                Logger.console.info("Fortify credentials not found in config.ini")
                fortify_user, fortify_password = fortify_prompt()
                fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                               project_template=fortify_config.project_template,
                                               application_name=fortify_config.application_name,
                                               fortify_username=fortify_user,
                                               fortify_password=fortify_password, scan_name=version,
                                               extension=x)
                fortify_config.write_username(fortify_user)
                fortify_config.write_password(fortify_password)
                Logger.console.info("Fortify credentials stored")
        else:
            fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                           project_template=fortify_config.project_template,
                                           application_name=fortify_config.application_name,
                                           fortify_username=fortify_user,
                                           fortify_password=fortify_password, scan_name=version, extension=x)
            fortify_config.write_username(fortify_user)
            fortify_config.write_password(fortify_password)
            Logger.console.info("Fortify credentials stored")

        reauth = fortify_client.upload_scan(file_name=scan_name)

        if reauth == -2:
            # The given application doesn't exist
            Logger.console.critical("Fortify Application {} does not exist. Unable to upload scan.".format(application))

    except (IOError, ValueError) as e:
        Logger.console.critical("Unable to complete command 'fortify upload'\n Error: {}".format(e))
    except (UnboundLocalError):
        Logger.app.error("There are duplicate Fortify SSC Project Version names.  Please choose another one.")


@fortify.command(name='scan',
                 short_help="Start Fortify scan",
                 help=WebBreakerHelper().fortify_scan_desc())
@click.option('--fortify_user',
              required=False,
              help="Specify Fortify username")
@click.option('--fortify_password',
              required=False,
              help="Specify Fortify password")
@click.option('--application',
              required=False,
              help="Assign Fortify app name"
              )
@click.option('--version',
              required=True,
              help="Assign Fortify app version"
              )
@click.option('--build_id',
              required=True,
              help="Assign Jenkins BuildID")
@pass_config
def fortify_scan(config, fortify_user, fortify_password, application, version, build_id):
    fortify_config = FortifyConfig()
    if application:
        fortify_config.application_name = application

    if not fortify_user or not fortify_password:
        Logger.console.info("No Fortify username or password provided. Checking fortify.ini for secret")
        if fortify_config.has_auth_creds():
            Logger.console.info("Fortify credentials found in fortify.ini")
            fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                           project_template=fortify_config.project_template,
                                           application_name=fortify_config.application_name, scan_name=version,
                                           fortify_username=fortify_config.username,
                                           fortify_password=fortify_config.password)
        else:
            Logger.console.info("Fortify credentials not found in fortify.ini")
            fortify_user, fortify_password = fortify_prompt()
            fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                           project_template=fortify_config.project_template,
                                           application_name=fortify_config.application_name,
                                           fortify_username=fortify_user,
                                           fortify_password=fortify_password, scan_name=version)
            fortify_config.write_username(fortify_user)
            fortify_config.write_password(fortify_password)
            Logger.console.info("Fortify credentials stored")

        pv_url = fortify_client.build_pv_url()

        if pv_url and pv_url != -1:
            write_agent_info('fortify_pv_url', pv_url)
            write_agent_info('fortify_build_id', build_id)
        else:
            Logger.console.critical("Unable to complete command 'fortify scan'")

    else:
        fortify_client = FortifyClient(fortify_url=fortify_config.ssc_url,
                                       project_template=fortify_config.project_template,
                                       application_name=fortify_config.application_name,
                                       fortify_username=fortify_user,
                                       fortify_password=fortify_password, scan_name=version)
        fortify_config.write_username(fortify_user)
        fortify_config.write_password(fortify_password)
        Logger.console.info("Fortify credentials stored")
        pv_url = fortify_client.build_pv_url()
        if pv_url and pv_url != -1:
            write_agent_info('fortify_pv_url', pv_url)
            write_agent_info('fortify_build_id', build_id)
        else:
            Logger.console.critical("Unable to complete command 'fortify scan'")


@cli.group(short_help="Manage credentials & notifiers",
           help=WebBreakerHelper().admin_desc(),
           )
@pass_config
def admin(config):
    pass


@admin.command(name='notifier',
               short_help="Get contributors of git repo",
               help=WebBreakerHelper().admin_notifier_desc()
               )
@click.option('--email',
              is_flag=True,
              help="Flag to specify email notifications")
@click.option('--git_url',
              required=True,
              help="Specify Git URL")
@pass_config
def notifier(config, email, git_url):
    try:
        if not email:
            Logger.console.info(
                "'webbreaker admin notifier' currently only supports email notifications. Please use the '--email' flag")
            return
        else:
            git_url = format_git_url(git_url)
            if not git_url:
                Logger.console.info("The git_url provided is invalid")
                return
            else:
                parser = urlparse(git_url)
                host = "{}://{}".format(parser.scheme, parser.netloc)
                path = parser.path
                r = re.search('\/(.*)\/', path)
                owner = r.group(1)
                r = re.search('\/.*\/(.*)', path)
                repo = r.group(1)
                git_client = GitClient(host=host)
                emails = git_client.get_all_emails(owner, repo)

                if emails:
                    write_agent_info('git_emails', emails)
                    write_agent_info('git_url', git_url)
                else:
                    Logger.console.info("Unable to complete command 'webbreaker admin notifier'")

    except (AttributeError, UnboundLocalError) as e:
        Logger.app.error("Unable to query git repo for email".format(e))


@admin.command(name='agent',
               short_help="Monitor scans and notify contributors",
               help=WebBreakerHelper().admin_agent_desc()
               )
@click.option('--start',
              required=False,
              is_flag=True,
              help="Flag that instructs WebBreaker to create an agent")
@pass_config
def agent(config, start):
    if not start:
        try:
            agent_data = read_agent_info()
            sys.stdout.write(str("Git URL: {}\n".format(agent_data['git_url'])))
            sys.stdout.write(str("Contributer Emails: {}\n".format(", ".join(agent_data['git_emails']))))
            sys.stdout.write(str("SSC URL: {}\n".format(agent_data['fortify_pv_url'])))
            sys.stdout.write(str("Build ID: {}\n".format(agent_data['fortify_build_id'])))
            # sys.stdout.write(str("Your agent.json file is complete...\n"))
        except TypeError as e:
            Logger.app.error("Unable to complete command 'admin': {}".format(e))
            sys.stdout.write(str("Unable to complete read agent configurations!\n"))
            return
    else:
        try:
            # If any data is missing, verifier will output and exit
            # verifier = AgentVerifier('webbreaker/etc/agent.json')
            pid = subprocess.Popen(['python', 'webbreaker/webbreakeragent/agent.py', '.webbreaker/etc/agent.json'])
            sys.stdout.write(str("WebBreaker agent started successfully.\n"))
        except TypeError as e:
            Logger.app.error("Unable to complete command 'admin agent': {}".format(e))
        return


@admin.command(name='credentials',
               short_help="Create & update Fortify credentials",
               help=WebBreakerHelper().admin_credentials_desc()
               )
@pass_config
@click.option('--fortify',
              required=False,
              is_flag=True,
              help="Flag used to designate options as Fortify credentials")
@click.option('--webinspect',
              required=False,
              is_flag=True,
              help="Flag used to designate options as WebInspect credentials")
@click.option('--clear',
              required=False,
              is_flag=True,
              help="Flag to clear credentials of Fortify OR WebInspect")
@click.option('--username',
              required=False,
              help="Specify username")
@click.option('--password',
              required=False,
              help="Specify username")
def credentials(config, fortify, webinspect, clear, username, password):
    if fortify:
        fortify_config = FortifyConfig()
        if clear:
            fortify_config.clear_credentials()
            Logger.app.info("Successfully cleared fortify credentials from config.ini")
        else:
            if username and password:
                try:
                    fortify_config.write_username(username)
                    fortify_config.write_password(password)
                    Logger.app.info("Credentials stored successfully")
                except ValueError:
                    Logger.app.error("Unable to validate Fortify credentials. Credentials were not stored")

            else:
                username, password = fortify_prompt()
                try:
                    fortify_config.write_username(username)
                    fortify_config.write_password(password)
                    Logger.app.info("Credentials stored successfully")
                except ValueError:
                    Logger.app.error("Unable to validate Fortify credentials. Credentials were not stored")
    elif webinspect:
        webinspect_config = WebInspectAuthConfig()
        if clear:
            webinspect_config.clear_credentials()
            Logger.app.info("Successfully cleared WebInspect credentials from config.ini")
        else:
            if username and password:
                try:
                    webinspect_config.write_username(username)
                    webinspect_config.write_password(password)
                    Logger.app.info("Credentials stored successfully")
                except ValueError:
                    Logger.app.error("Unable to validate WebInspect credentials. Credentials were not stored")

            else:
                username, password = webinspect_prompt()
                try:
                    webinspect_config.write_username(username)
                    webinspect_config.write_password(password)
                    Logger.app.info("Credentials stored successfully")
                except ValueError:
                    Logger.app.error("Unable to validate WebInspect credentials. Credentials were not stored")
    else:
        sys.stdout.write(str("Please specify either the --fortify or --webinspect flag\n"))


@admin.command(name='secret',
               short_help="Generate & update encryption key",
               help=WebBreakerHelper().admin_secret_desc()
               )
@pass_config
@click.option('-f', '--force',
              required=False,
              is_flag=True,
              help="Optional flag to prevent confirmation prompt")
def secret(config, force):
    secret_client = SecretClient()
    if secret_client.secret_exists():
        if not force:
            if click.confirm('All stored credentials will be deleted. Do you want to continue?'):
                secret_client.wipe_all_credentials()
                secret_client.write_secret(overwrite=True)
            else:
                sys.stdout.write(str("New secret was not written\n"))
        else:
            secret_client.wipe_all_credentials()
            secret_client.write_secret(overwrite=True)
    else:
        secret_client.write_secret()


@cli.group(short_help="Interaction with ThreadFix API",
           help=WebBreakerHelper().threadfix_desc()
           )
@pass_config
def threadfix(config):
    pass


@threadfix.command(name='teams',
                   short_help="List all ThreadFix teams",
                   help=WebBreakerHelper().threadfix_team_desc()
                   )
@pass_config
def team(config):
    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    teams = threadfix_client.list_teams()
    if teams:
        print("{0:^10} {1:30}".format('ID', 'Name'))
        print("{0:10} {1:30}".format('-' * 10, '-' * 30))
        for team in teams:
            print("{0:^10} {1:30}".format(team['id'], team['name']))
        Logger.app.info("Successfully listed threadfix teams")
        print('\n\n')
    else:
        Logger.app.error("No teams were found")


@threadfix.command(name='applications',
                   short_help="List team's ThreadFix applications",
                   help=WebBreakerHelper().threadfix_application_desc(),
                   )
@pass_config
@click.option('--team_id',
              required=False,
              help="ThreadFix team ID")
@click.option('--team',
              required=False,
              help="ThreadFix team name")
def application(config, team_id, team):
    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    if not team_id and not team:
        Logger.app.error("Please specify either a team or team_id")
        return
    if team and not team_id:
        team_id = threadfix_client.get_team_id_by_name(team)
    if team_id is None:
        Logger.app.error("Unable to find team with name {}".format(team))
        return
    apps = threadfix_client.list_apps_by_team(team)
    if apps:
        print("{0:^10} {1:30}".format('ID', 'Name'))
        print("{0:10} {1:30}".format('-' * 10, '-' * 30))
        for app in apps:
            print("{0:^10} {1:30}".format(app['id'], app['name']))
        Logger.app.info("Successfully listed threadfix applications")
        print('\n\n')
    else:
        Logger.app.error("No applications were found for team_id {}".format(team_id))


@threadfix.command(name='create',
                   short_help="Create application in ThreadFix",
                   help=WebBreakerHelper().threadfix_create_desc()
                   )
@pass_config
@click.option('--team_id',
              required=False,
              help="Assign ThreadFix team ID")
@click.option('--team',
              required=False,
              help="Assign ThreadFix team name")
@click.option('--application',
              required=True,
              help="Assign a name")
@click.option('--url',
              required=False,
              default=None,
              help="Assign an Option URL")
def create(config, team_id, team, application, url):
    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    if not team_id and not team:
        Logger.app.error("Please specify either a team or team_id")
        return
    if team and not team_id:
        team_id = threadfix_client.get_team_id_by_name(team)
    if team_id is None:
        Logger.app.error("Unable to find team with application {}".format(team))
        return
    created_app = threadfix_client.create_application(team_id, application, url)
    if created_app:
        Logger.app.info("Application was successfully created with id {}".format(created_app['id']))
    else:
        Logger.app.error("Application was not created, either the application exists, invalid token, or ThreadFix"
                         " is unavailable!! ")


@threadfix.command(name='scans',
                   short_help="List ThreadFix scans",
                   help=WebBreakerHelper().threadfix_scan_desc())
@pass_config
@click.option('--app_id',
              required=True,
              help="ThreadFix Application ID")
def scan(config, app_id):
    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    scans = threadfix_client.list_scans_by_app(app_id)
    if scans:
        print("{0:^10} {1:30} {2:30}".format('ID', 'Scanner Name', 'Filename'))
        print("{0:10} {1:30} {2:30}".format('-' * 10, '-' * 30, '-' * 30))
        for scan in scans:
            print("{0:^10} {1:30} {2:30}".format(scan['id'], scan['scannerName'], scan['filename']))
        Logger.app.info("Successfully listed threadfix scans")
        print('\n\n')
    else:
        Logger.app.error("No scans were found for app_id {}".format(app_id))


@threadfix.command(name='upload',
                   short_help="Upload local scan to ThreadFix",
                   help=WebBreakerHelper().threadfix_upload_desc()
                   )
@pass_config
@click.option('--app_id',
              required=False,
              help="Assign ThreadFix Application ID")
@click.option('--application',
              required=False,
              help="Assign ThreadFix Application name")
@click.option('--scan_file',
              required=True,
              help="Assign file to upload")
def threadfix_upload(config, app_id, application, scan_file):
    if not app_id and not application:
        Logger.app.error("Please specify either an application or app_id!")
        return

    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    if not app_id:
        Logger.app.info("Attempting to find application matching name {}".format(application))
        apps = threadfix_client.list_all_apps()
        if not apps:
            Logger.app.error("Failed to retrieve applications from ThreadFix")
            return
        else:
            matches = []
            for app in apps:
                if app['app_name'] == application:
                    matches.append(app.copy())
            if len(matches) == 0:
                Logger.app.error("No application was found matching name {}".format(application))
                return
            if len(matches) > 1:
                Logger.app.error(
                    "Multiple applications were found matching name {}. Please specify the desired ID from below.".format(
                        application))
                print("{0:^10} {1:55} {2:30}".format('App ID', 'Team', 'Application'))
                print("{0:10} {1:55} {2:30}".format('-' * 10, '-' * 55, '-' * 30))
                for app in matches:
                    print("{0:^10} {1:55} {2:30}".format(app['app_id'], app['team_name'], app['app_name']))
                print('\n\n')
                return
            else:
                app_id = matches[0]['app_id']

    upload_resp = threadfix_client.upload_scan(app_id, scan_file)
    if upload_resp:
        Logger.app.info("{}".format(upload_resp))
    else:
        Logger.app.error("Scan file failed to upload!")


@threadfix.command(name='list',
                   short_help="List all ThreadFix applications",
                   help=WebBreakerHelper().threadfix_list_desc()
                   )
@click.option('--team',
              required=False,
              default=None,
              help="Specify team name to list")
@click.option('--application',
              required=False,
              default=None,
              help="Specify application name to list")
@pass_config
def threadfix_list(config, team, application):
    threadfix_config = ThreadFixConfig()
    threadfix_client = ThreadFixClient(host=threadfix_config.host, api_key=threadfix_config.api_key)
    applications = threadfix_client.list_all_apps(team, application)
    if applications is not False:
        if len(applications):
            print("{0:^10} {1:55} {2:30}".format('App ID', 'Team', 'Application'))
            print("{0:10} {1:55} {2:30}".format('-' * 10, '-' * 55, '-' * 30))
            for app in applications:
                print("{0:^10} {1:55} {2:30}".format(app['app_id'], app['team_name'], app['app_name']))
            print('\n\n')
            Logger.app.info("ThreadFix List successfully completed")
        else:
            query_info = ''
            if team is not None:
                query_info = ' with team name matching {}'.format(team)
            if application is not None:
                if query_info == '':
                    query_info = ' with application name matching {}'.format(application)
                else:
                    query_info = query_info + ' and application name matching {}'.format(application)
            Logger.app.info("No applications were found" + query_info)
    else:
        Logger.app.error("Possible cause could be your API token must be associated with a local account!!")


if __name__ == '__main__':
    cli()
