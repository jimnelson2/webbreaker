import pytest
import mock
import logging

from testfixtures import LogCapture
from webbreaker.__main__ import cli as webbreaker

import json
from mock import mock_open

# Disable debugging for log clarity in testing
logging.disable(logging.DEBUG)


@pytest.fixture(scope="module")
def runner():
    from click.testing import CliRunner
    return CliRunner()


@pytest.fixture()
def caplog():
    return LogCapture()


def general_exception():
    raise Exception('Test Failure')


def environment_error_exception():
    raise EnvironmentError('Test Failure')


def unbound_local_error_exception():
    raise UnboundLocalError('Test Failure')


# Move hard coded values to params
class WebInspectResponseTest(object):
    """Container for all WebInspect API responses, even errors."""

    def __init__(self):
        self.message = "This was only a test!"
        self.success = True
        self.response_code = "200"
        self.data = {"ScanId": "FakeScanID", "ScanStatus": "complete"}

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def data_json(self, pretty=False):
        """Returns the data as a valid JSON string."""
        if pretty:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_no_scans_found(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.return_value.export_scan_results.return_value = None
    test_mock.get_scan_by_name()
    test_mock.export_scan_results()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name where found on this host'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_one_scan_found(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.return_value.export_scan_results.return_value = None
    test_mock.get_scan_by_name()
    test_mock.export_scan_results()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'INFO', 'Scan matching the name test-name found.'),
        ('__webbreaker__', 'INFO', 'Downloading scan test-name'),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_many_scans_found(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'},
                                                            {'Name': 'test-name2', 'ID': 12345, 'Status': 'test2'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'INFO', 'Multiple scans matching the name test-name found.'),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_exception(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.side_effect = general_exception
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_req_success(test_mock, runner, caplog):
    test_mock.return_value.list_scans.return_value = None

    result = runner.invoke(webbreaker, ['webinspect', 'list', '--server', 'https://test-server'])

    # list_scans handles the logging
    caplog.check()
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_req_exception(test_mock, runner, caplog):
    test_mock.return_value.list_scans.side_effect = general_exception

    result = runner.invoke(webbreaker, ['webinspect', 'list', '--server', 'https://test-server'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_match(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'https://test-server01', '--server', 'https://test-server02',
                            '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()
    assert 'Scans matching the name test-name found on https://test-server01' in result.output
    assert 'Scans matching the name test-name found on https://test-server02' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_match_multi_server(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'https://test-server', '--server', 'https://test-server2', '--scan_name',
                            'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_no_match(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on https://test-server'),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_no_match_multi_server(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'https://test-server', '--server', 'https://test-server2', '--scan_name',
                            'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on https://test-server'),
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on https://test-server2'),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_error(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.side_effect = general_exception
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'https://test-server', '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1

#http
@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_no_scans_found_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.return_value.export_scan_results.return_value = None
    test_mock.get_scan_by_name()
    test_mock.export_scan_results()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name where found on this host'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_one_scan_found_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.return_value.export_scan_results.return_value = None
    test_mock.get_scan_by_name()
    test_mock.export_scan_results()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'INFO', 'Scan matching the name test-name found.'),
        ('__webbreaker__', 'INFO', 'Downloading scan test-name'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_many_scans_found_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'},
                                                            {'Name': 'test-name2', 'ID': 12345, 'Status': 'test2'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'INFO', 'Multiple scans matching the name test-name found.'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_download_req_exception_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.side_effect = general_exception
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'download', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_req_success_http(test_mock, runner, caplog):
    test_mock.return_value.list_scans.return_value = None

    result = runner.invoke(webbreaker, ['webinspect', 'list', '--server', 'http://test-server'])

    # list_scans handles the logging
    caplog.check()
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_req_exception_http(test_mock, runner, caplog):
    test_mock.return_value.list_scans.side_effect = general_exception

    result = runner.invoke(webbreaker, ['webinspect', 'list', '--server', 'http://test-server'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_match_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'http://test-server01', '--server',
                            'http://test-server02',
                            '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()
    assert 'Scans matching the name test-name found on http://test-server01' in result.output
    assert 'Scans matching the name test-name found on http://test-server02' in result.output

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_match_multi_server_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = [{'Name': 'test-name', 'ID': 1234, 'Status': 'test'}]
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'http://test-server', '--server',
                            'http://test-server2', '--scan_name',
                            'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_no_match_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on http://test-server'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_no_match_multi_server_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.return_value = []
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'http://test-server', '--server',
                            'http://test-server2', '--scan_name',
                            'test-name'])

    caplog.check(
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on http://test-server'),
        ('__webbreaker__', 'ERROR', 'No scans matching the name test-name were found on http://test-server2'),
    )
    caplog.uninstall()

    assert result.exit_code == 0

@mock.patch('webbreaker.__main__.WebinspectQueryClient')
def test_webinspect_list_scan_name_error_http(test_mock, runner, caplog):
    test_mock.return_value.get_scan_by_name.side_effect = general_exception
    test_mock.get_scan_by_name()

    result = runner.invoke(webbreaker,
                           ['webinspect', 'list', '--server', 'http://test-server', '--scan_name', 'test-name'])

    caplog.check()
    caplog.uninstall()

    assert result.exit_code == -1
    #end



# TODO: webbreaker webinespect download

# TODO: webinspect scan [OPTIONS]
# Write a test for False success and failure in create_scan. Just change WebInspectResponseTest() to False


@mock.patch('webbreaker.__main__.create_scan_event_handler')
@mock.patch('webbreaker.webinspectclient.WebInspectJitScheduler')
@mock.patch('webbreaker.webinspectclient.WebInspectApi')
@mock.patch('webbreaker.webinspectclient.open', new_callable=mock_open, read_data="data")
@mock.patch('webbreaker.__main__.open', new_callable=mock_open, read_data="data")
def test_webinspect_scan_req(main_open_mock, open_mock, scan_mock, endpoint_mock, email_mock, runner, caplog):
    endpoint_mock.return_value.get_endpoint.return_value = "test.hq.target.com"
    endpoint_mock.has_auth_creds()

    scan_mock.return_value.create_scan.return_value = WebInspectResponseTest()
    scan_mock.create_scan()
    scan_mock.return_value.get_current_status.return_value = WebInspectResponseTest()
    scan_mock.get_current_status()
    scan_mock.return_value.export_scan_format.return_value = WebInspectResponseTest()
    scan_mock.export_scan_format()

    email_mock.handle_scan_event = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'scan'])

    caplog.check(
        ('__webbreaker__', 'INFO', "Querying WebInspect scan engines for availability."),
        ('__webbreaker__', 'INFO', "Launching a scan"),
        ('__webbreaker__', 'INFO', "Execution is waiting on scan status change"),
        ('__webbreaker__', 'INFO', "Scan status has changed to complete."),
        ('__webbreaker__', 'INFO', "Exporting scan: FakeScanID as fpr"),
        ('__webbreaker__', 'INFO', "Exporting scan: FakeScanID as xml"),
        ('__webbreaker__', 'INFO', "Webbreaker WebInspect has completed."),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebInspectConfig')
def test_webinspect_servers(test_mock, runner, caplog):
    result = runner.invoke(webbreaker, ['webinspect', 'servers'])

    # WebInspectConfig handles all logging
    caplog.check()
    caplog.uninstall()

    assert result.exit_code == 0


# WebInspect CLI Proxy Testing - https
@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_list_success(test_mock, runner, caplog):
    test_mock.return_value.list_proxy.return_value = [{'instanceId': 'test-id', 'address': 'localhost', 'port': '80'}]

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--list', '--server', 'https://test-server'])

    caplog.check(
        ('__webbreaker__', 'INFO', "Succesfully listed proxies from: 'https://test-server'"),
    )
    caplog.uninstall()
    assert 'test-id' in result.output
    assert 'localhost' in result.output
    assert '80' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_list_no_result(test_mock, runner, caplog):
    test_mock.return_value.list_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--list', '--server', 'https://test-server'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "No proxies found on 'https://test-server'"),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_list_success_no_server(test_mock, runner):
    test_mock.return_value.list_proxy.return_value = [{'instanceId': 'test-id', 'address': 'localhost', 'port': '80'}]

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--list'])

    assert 'test-id' in result.output
    assert 'localhost' in result.output
    assert '80' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_success(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'https://test-server'])

    caplog.check(
        ('__webbreaker__', 'INFO', "Proxy successfully started"),
    )
    caplog.uninstall()

    assert 'test-id' in result.output
    assert 'localhost' in result.output
    assert '80' in result.output
    assert 'test-server' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_exception_unbound(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.side_effect = unbound_local_error_exception
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'https://test-server'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_exception_env(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.side_effect = environment_error_exception
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'https://test-server'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_no_results(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'https://test-server'])

    print(result.output)
    caplog.check(
        ('__webbreaker__', 'ERROR', "Unable to start proxy on 'https://test-server'"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_success(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.download_proxy.return_value = True
    test_mock.return_value.delete_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--server', 'https://test-server', '--stop', '--proxy_name', 'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_exception_unbound(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_exception_env(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_no_results(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_no_proxy_name(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Please enter a proxy name."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_success(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.download_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--server', 'https://test-server', '--download', '--proxy_name', 'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_exception_unbound(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_exception_env(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_no_results(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'https://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_no_proxy_name(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Please enter a proxy name."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


# TODO: webinspect proxy --upload --proxy_name (result == None)
# TODO: webinspect proxy --upload (UnboundLocalError from get_cert_proxy)
# TODO: webinspect proxy --upload (EnvironmentError from get_cert_proxy)
# TODO: webinspect proxy --upload (No Proxy Name Failure)
@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_success(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.upload_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'https://test-server', '--proxy_name',
                            'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_exception_unbound(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'https://test-server', '--proxy_name',
                            'test-id'])
    print(result.output)

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()
    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_exception_env(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'https://test-server', '--proxy_name',
                            'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()
    assert result.exit_code == 1

#http
@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_list_success_http(test_mock, runner, caplog):
    test_mock.return_value.list_proxy.return_value = [{'instanceId': 'test-id', 'address': 'localhost', 'port': '80'}]

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--list', '--server', 'http://test-server'])

    caplog.check(
        ('__webbreaker__', 'INFO', "Succesfully listed proxies from: 'http://test-server'"),
    )
    caplog.uninstall()
    assert 'test-id' in result.output
    assert 'localhost' in result.output
    assert '80' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_list_no_result_http(test_mock, runner, caplog):
    test_mock.return_value.list_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--list', '--server', 'http://test-server'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "No proxies found on 'http://test-server'"),
    )
    caplog.uninstall()

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_success_http(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'http://test-server'])

    caplog.check(
        ('__webbreaker__', 'INFO', "Proxy successfully started"),
    )
    caplog.uninstall()

    assert 'test-id' in result.output
    assert 'localhost' in result.output
    assert '80' in result.output
    assert 'test-server' in result.output

    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_exception_unbound_http(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.side_effect = unbound_local_error_exception
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'http://test-server'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_exception_env_http(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.side_effect = environment_error_exception
    test_mock.return_value.start_proxy.return_value = {'instanceId': 'test-id', 'address': 'localhost',
                                                       'uri': '/webinspect/proxy/test-id',
                                                       'port': '80'}

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'http://test-server'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_start_no_results_http(test_mock, runner, caplog):
    test_mock.return_value.get_cert_proxy.return_value = True
    test_mock.return_value.start_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--start', '--server', 'http://test-server'])

    print(result.output)
    caplog.check(
        ('__webbreaker__', 'ERROR', "Unable to start proxy on 'http://test-server'"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_success_http(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.download_proxy.return_value = True
    test_mock.return_value.delete_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--server', 'http://test-server', '--stop', '--proxy_name', 'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_exception_unbound_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_exception_env_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_stop_no_results_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--stop', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_success_http(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.download_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--server', 'http://test-server', '--download', '--proxy_name', 'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_exception_unbound_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_exception_env_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()

    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_download_no_results_http(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--download', '--server', 'http://test-server', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()

    assert result.exit_code == 1



# TODO: webinspect proxy --upload --proxy_name (result == None)
# TODO: webinspect proxy --upload (UnboundLocalError from get_cert_proxy)
# TODO: webinspect proxy --upload (EnvironmentError from get_cert_proxy)
# TODO: webinspect proxy --upload (No Proxy Name Failure)
@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_success_http(test_mock, runner):
    test_mock.return_value.get_proxy.return_value = True
    test_mock.return_value.upload_proxy.return_value = True

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'http://test-server', '--proxy_name',
                            'test-id'])

    # Logging and printing handled in webinespctproxyclient
    assert result.exit_code == 0


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_exception_unbound(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = unbound_local_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'http://test-server', '--proxy_name',
                            'test-id'])
    print(result.output)

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()
    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_exception_env(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.side_effect = environment_error_exception

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'http://test-server', '--proxy_name',
                            'test-id'])

    caplog.check(
        ('__webbreaker__', 'CRITICAL', "Incorrect WebInspect configurations found!! Test Failure"),
    )
    caplog.uninstall()
    assert result.exit_code == 1


@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_no_results(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'http://test-server', '--proxy_name',
                            'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()
    assert result.exit_code == 1



@mock.patch('webbreaker.__main__.WebinspectProxyClient')
def test_webinspect_proxy_upload_no_results(test_mock, runner, caplog):
    test_mock.return_value.get_proxy.return_value = None

    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file', '--server', 'https://test-server', '--proxy_name',
                            'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Proxy: 'test-id' not found on any server."),
    )
    caplog.uninstall()
    assert result.exit_code == 1


def test_webinspect_proxy_upload_no_proxy_name(runner, caplog):
    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--upload', 'test-file'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Please enter a proxy name."),
    )
    caplog.uninstall()
    assert result.exit_code == 1


def test_webinspect_no_proxy_name(runner, caplog):
    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Please enter a proxy name."),
    )
    caplog.uninstall()

    assert result.exit_code == 1


def test_webinspect_no_proxy_command(runner, caplog):
    result = runner.invoke(webbreaker,
                           ['webinspect', 'proxy', '--proxy_name', 'test-id'])

    caplog.check(
        ('__webbreaker__', 'ERROR', "Error: No proxy command was given."),
    )
    caplog.uninstall()

    assert result.exit_code == 1
