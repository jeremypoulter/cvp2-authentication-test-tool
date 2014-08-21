#!/usr/bin/env python3
"""
CVP2 Authentication Test Tool
Brendan Long <b.long@cablelabs.com>

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


class Path(object):
    def __init__(self, value):
        self.value = str(value)
        if not self.value.startswith("/"):
            self.value = "/" + self.value

    def __str__(self):
        return self.value


class Port(object):
    def __init__(self, value):
        self.value = int(value)
        if self.value < 1 or self.value > 65535:
            raise TypeError("port numbers must be between 1 and 65535")

    def __str__(self):
        return str(self.value)


class Test(object):
    def __init__(self, name, log_name, library, key, should_succeed):
        self.name = name
        self.log_name = log_name
        self.library = library
        self.key = key
        self.should_succeed = should_succeed

    def run(self, debug, ca_file, host, port, path, openssl, log_path):
        filename = os.path.join(log_path, "{}.log".format(self.log_name))
        print("Testing: {} (log: {})".format(self.name,
            os.path.relpath(filename)))

        if self.key is None:
            print("Required key not given as argument")
            print("TEST SKIPPED\n")
            return

        fail = False
        # -ign_eof tells s_client to wait for a server response instead of
        # immediately stopping once it sees an EOF in stdin
        args = [openssl, "s_client", "-host", host, "-ign_eof",
            "-port", str(port), "-dtcp", "-dtcp_dll_path",
            self.library, "-dtcp_key_storage_dir", self.key]
        if debug:
            print("Running: {}".format(" ".join(args)))

        with open(filename, "w") as log:
            p = subprocess.Popen(args, stdin=subprocess.PIPE,
                stdout=log, stderr=subprocess.STDOUT)
            p.communicate(input="GET {} HTTP/1.0\r\n\r\n".format(path).encode("UTF-8"))
            return_code = p.wait(WAIT_TIME)

        with open(filename, "r") as log:
            output = log.read()

        # Make sure the openssl program supports -dtcp
        if "unknown option -dtcp" in output:
            print("ERROR: OpenSSL does not support -dtcp argument in s_client. Make sure you're using the CVP2 OpenSSL (https://community.cablelabs.com/wiki/display/CBLCVP2/Openssl+Implementation)\n")
            return

        # Make sure the client attempts to continue the connection, even
        # if the server authentication failed
        if not "Inside DTCPIPAuth_SignData" in output:
            print("ERROR: OpenSSL is setup incorrectly. Make sure validate_dtcp_suppdata() in s_client.c ALWAYS returns 0, including in error conditions (note: this is insecure and should only be used for the test tool)\n")
            return

        if return_code != 0:
            print("Connection failed")
            if self.should_succeed:
                fail = True
        else:
            print("Connection succeeded")
            if not self.should_succeed:
                fail = True
        if fail:
            print("TEST FAILED")
        else:
            print("TEST SUCCEEDED")
        print()


class VerifyServerTest(Test):
    def run(self, debug, ca_file, host, port, path, openssl, log_path):
        filename = os.path.join(log_path, "{}.log".format(self.log_name))
        print("Testing: {} (log: {})".format(self.name,
            os.path.relpath(filename)))

        if self.key is None:
            print("Required key not given as argument")
            print("TEST SKIPPED\n")
            return

        fail = False
        # -ign_eof tells s_client to wait for a server response instead of
        # immediately stopping once it sees an EOF in stdin
        args = [openssl, "s_client", "-host", host, "-ign_eof",
            "-port", str(port), "-CAfile", ca_file, "-verify", "10"]
        if debug:
            print("Running: {}".format(" ".join(args)))

        with open(filename, "w") as log:
            p = subprocess.Popen(args, stdin=subprocess.PIPE,
                stdout=log, stderr=subprocess.STDOUT)
            p.communicate(input="GET {} HTTP/1.0\r\n\r\n".format(path).encode("UTF-8"))
            return_code = p.wait(WAIT_TIME)

        with open(filename, "r") as log:
            output = log.read()

        x509_pass = "Verify return code: 0 (ok)" in output
        if x509_pass:
            print("Server X.509 certificate verification succeeded")
        else:
            args += ["-dtcp", "-dtcp_dll_path", self.library,
                "-dtcp_key_storage_dir", self.key]

            with open(filename, "a") as log:
                p = subprocess.Popen(args, stdin=subprocess.PIPE,
                    stdout=log, stderr=subprocess.STDOUT)
                p.communicate(input="GET {} HTTP/1.0\r\n\r\n".format(path).encode("UTF-8"))
                return_code = p.wait(WAIT_TIME)

            with open(filename, "r") as log:
                output = log.read()

            # Check output to make sure the CVP2 bit was set on the server side
            if not "CVP2_DTCIP_VerifyRemoteCert(): CVP2 bit set" in output:
                fail = True
                print("CVP2 bit is NOT set in remote certificate")
            # TODO: Check for "CVP2 bit not set" or whatever the message is
            # once we have a failure case
            else:
                print("CVP2 bit is set in remote certificate")

        if return_code != 0:
            print("Connection failed")
            if self.should_succeed:
                fail = True
        else:
            print("Connection succeeded")
            if not self.should_succeed:
                fail = True
        if fail:
            print("TEST FAILED")
        else:
            print("TEST SUCCEEDED")
        print()


class Tester(object):
    def __init__(self, debug, openssl, log_path, ca_file,
            production_library_cvp2, production_library_no_cvp2,
            test_library_cvp2, test_library_no_cvp2, production_key_cvp2,
            production_key_no_cvp2, test_key_cvp2, test_key_no_cvp2):
        self.debug = debug
        self.openssl = openssl
        self.log_path = log_path
        self.ca_file = ca_file
        os.makedirs(log_path, exist_ok=True)
        self.tests = [
            VerifyServerTest("Verify Server's X.509 or DTCP certificate",
                "server-verify", production_library_cvp2, production_key_cvp2,
                should_succeed=True),
            Test("Client DTCP Production Key With CVP2 Bit", "production-cvp2",
                production_library_cvp2, production_key_cvp2,
                should_succeed=True),
            Test("Client DTCP Production Key Without CVP2 Bit", "production-no-cvp2",
                production_library_no_cvp2, production_key_no_cvp2,
                should_succeed=False),
            Test("Client DTCP Test Key With CVP2 Bit", "test-cvp2",
                test_library_cvp2, test_key_cvp2,
                should_succeed=False),
            Test("Client DTCP Test Key Without CVP2 Bit", "test-no-cvp2",
                test_library_no_cvp2, test_key_no_cvp2,
                should_succeed=False)
        ]

    def run_tests(self, host, port, path):
        for test in self.tests:
            test.run(self.debug, self.ca_file, host, port, path, self.openssl,
                self.log_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVP2 Authentication Test Tool")
    parser.add_argument("--host", required=True, help="host to test")
    parser.add_argument("--port", "-p", default=443, type=Port,
        help="port to connect to (default: 443)")
    parser.add_argument("--debug", "-d", help="extra debug output",
        action="store_const", const=True, default=False)
    parser.add_argument("--config", "-c", help="path to config file (see included catt.conf)")
    parser.add_argument("--path", default="/", type=Path,
        help="the absolute path to request on the server (defaults is \"/\")")

    args = parser.parse_args()

    config = configparser.ConfigParser()
    config["DEFAULT"] = {
        "CATT_DIR": os.path.dirname(os.path.realpath(__file__))
    }
    config.read(args.config)
    main = config["Main"]
    libraries = config["Libraries"]
    keys = config["Keys"]

    tester = Tester(debug=args.debug,
        openssl = main["OpenSSL"],
        log_path = main.get("LogPath", "."),
        ca_file = main.get("CAFile"),
        production_library_cvp2 = libraries["ProductionLibCvp2"],
        production_library_no_cvp2 = libraries["ProductionLibNoCvp2"],
        test_library_cvp2 = libraries["TestLibCvp2"],
        test_library_no_cvp2 = libraries["TestLibNoCvp2"],
        production_key_cvp2 = keys["ProductionKeyCvp2"],
        production_key_no_cvp2 = keys["ProductionKeyNoCvp2"],
        test_key_cvp2 = keys.get("TestKeyCvp2", None),
        test_key_no_cvp2 = keys["TestKeyNoCvp2"])
    tester.run_tests(args.host, args.port, args.path)
