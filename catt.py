#!/usr/bin/env python3
"""
CVP2 Authentication Test Tool
This tool tests:
  * That a server's DTCPIP key is a valid production key, with the CVP2 bit set.
  * That the server accepts connections from clients with a valid production
    key with the CVP2 bit set.
 * That the server rejects connections from clients with:
     - A CVP2 test key with the CVP2 bit set.
     - A CVP2 test key without the CVP2 bit set.
     - A CVP2 production key without the CVP2 bit set.
"""
import argparse
import configparser
import enum
import io
import os
import subprocess
import sys


# The maximum number of seconds to wait for OpenSSL to finish
WAIT_TIME = 10


class Test(object):
    def __init__(self, name, log_name, library, key, should_succeed):
        self.name = name
        self.log_name = log_name
        self.library = library
        self.key = key
        self.should_succeed = should_succeed

    def run(self, debug, host, openssl, log_path):
        filename = os.path.join(log_path, "{}.log".format(self.log_name))
        print("Testing: {} (log: {})".format(self.name, filename))

        if self.key is None:
            print("SKIP: Required key not given as argument\n")
            return

        fail = False
        args = [openssl, "s_client", "-host", host,
            "-port", "443", "-quiet", "-dtcp", "-dtcp_dll_path", self.library,
            "-dtcp_key_storage_dir", self.key]
        if debug:
            print("Running: {}".format(" ".join(args)))

        with open(filename, "w") as log:
            p = subprocess.Popen(args, stdin=subprocess.PIPE,
                stdout=log, stderr=subprocess.STDOUT)
            p.communicate(input=b"GET / HTTP/1.0\r\n\r\n")
            return_code = p.wait(WAIT_TIME)

        with open(filename, "r") as log:
            output = log.read()

            # Check output to make sure the CVP2 bit was set on the server side
            if not "CVP2_DTCIP_VerifyRemoteCert(): CVP2 bit set" in output:
                fail = True
                print("FAIL: CVP2 bit not set in remote cert")
            # TODO: Check for "CVP2 bit not set" or whatever the message is
            # once we have a failure case
            elif debug:
                print("Debug: CVP2 bit is set")

            # Make sure the client attempts to continue the connection, even
            # if the server authentication failed
            if not "Inside DTCPIPAuth_SignData" in output:
                fail = True
                print("ERROR: OpenSSL is setup incorrectly. Make sure validate_dtcp_suppdata() in s_client.c *always* returns 0, including in error conditions (note: this is insecure and should only be used for the test tool)")

        if return_code != 0 and self.should_succeed:
            print("FAIL: Connection failed when it should have succeeded")
        elif return_code == 0 and not self.should_succeed:
            print("FAIL: Connection succeeded when it should have failed")
        elif not fail:
            print("PASS")
        print()


class Tester(object):
    def __init__(self, debug, openssl, log_path, production_library_cvp2,
            production_library_no_cvp2, test_library_cvp2,
            test_library_no_cvp2, production_key_cvp2,
            production_key_no_cvp2, test_key_cvp2, test_key_no_cvp2):
        self.debug = debug
        self.openssl = openssl
        self.log_path = log_path
        os.makedirs(log_path, exist_ok=True)
        self.tests = [
            Test("Production Key With CVP2 Bit", "production-cvp2",
                production_library_cvp2, production_key_cvp2,
                should_succeed=True),
            Test("Production Key Without CVP2 Bit", "production-no-cvp2",
                production_library_no_cvp2, production_key_no_cvp2,
                should_succeed=False),
            Test("Test Key With CVP2 Bit", "test-cvp2",
                test_library_cvp2, test_key_cvp2,
                should_succeed=False),
            Test("Test Key Without CVP2 Bit", "test-no-cvp2",
                test_library_no_cvp2, test_key_no_cvp2,
                should_succeed=False)
        ]

    def run_tests(self, host):
        for test in self.tests:
            test.run(self.debug, host, self.openssl, self.log_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVP2 Authentication Test Tool")
    parser.add_argument("--host", required=True, help="host to test")
    parser.add_argument("--debug", "-d", help="extra debug output",
        action="store_const", const=True, default=False)
    parser.add_argument("--config", "-c", help="path to config file (see included catt.conf)")

    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)
    programs = config["Programs"]
    logs = config["Logs"]
    libraries = config["Libraries"]
    keys = config["Keys"]

    tester = Tester(debug=args.debug,
        openssl = programs["OpenSSL"],
        log_path = logs.get("LogPath", "."),
        production_library_cvp2 = libraries["ProductionLibCvp2"],
        production_library_no_cvp2 = libraries["ProductionLibNoCvp2"],
        test_library_cvp2 = libraries["TestLibCvp2"],
        test_library_no_cvp2 = libraries["TestLibNoCvp2"],
        production_key_cvp2 = keys["ProductionKeyCvp2"],
        production_key_no_cvp2 = keys["ProductionKeyNoCvp2"],
        test_key_cvp2 = keys.get("TestKeyCvp2", None),
        test_key_no_cvp2 = keys["TestKeyNoCvp2"])
    tester.run_tests(args.host)
