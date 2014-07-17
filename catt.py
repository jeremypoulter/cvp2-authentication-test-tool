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
import enum
import io
import subprocess
import sys


# The maximum number of seconds to wait for OpenSSL to finish
WAIT_TIME = 10


class Test(object):
    def __init__(self, name, library, key, should_succeed):
        self.name = name
        self.library = library
        self.key = key
        self.should_succeed = should_succeed


class Tester(object):
    def __init__(self, openssl, host, production_library, test_library,
            production_key_cvp2, production_key_no_cvp2, test_key_cvp2,
            test_key_no_cvp2, require_cvp2_bit=True, debug=False):
        self.openssl = openssl
        self.host = host
        self.debug = debug
        self.tests = [
            # TODO: Should be production_key_cvp2
            Test("No Client Key", production_library, production_key_no_cvp2,
                should_succeed=True),
            Test("Production Key With CVP2 Bit", production_library,
                production_key_cvp2, should_succeed=True),
            Test("Production Key Without CVP2 Bit", production_library,
                production_key_no_cvp2, should_succeed=not require_cvp2_bit),
            Test("Test Key With CVP2 Bit", test_library, test_key_cvp2,
                should_succeed=False),
            Test("Test Key Without CVP2 Bit", test_library, test_key_no_cvp2,
                should_succeed=False)
        ]

    def run_tests(self):
        for test in self.tests:
            self.run_test(test)

    def run_test(self, test):
        print("Testing: {}".format(test.name))
        if test.key is None:
            print("SKIP: Required key not given as argument\n")
            return
        args = [self.openssl, "s_client", "-host", self.host,
            "-port", "443", "-quiet", "-dtcp", "-dtcp_dll_path", test.library,
            "-dtcp_key_storage_dir", test.key]
        p = subprocess.Popen(args, stdin=subprocess.PIPE,
            stdout=None if self.debug else subprocess.DEVNULL,
            stderr=subprocess.STDOUT)
        p.communicate(input=b"GET / HTTP/1.0\r\n\r\n")
        return_code = p.wait(WAIT_TIME)
        if return_code != 0 and test.should_succeed:
            print("FAIL: Connection failed when it should have succeeded")
        elif return_code == 0 and not test.should_succeed:
            print("FAIL: Connection succeeded when it should have failed")
        else:
            print("PASS")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVP2 Authentication Test Tool")
    parser.add_argument("--openssl", required=True, help="OpenSSL binary")
    parser.add_argument("--host", required=True, help="host to test")
    parser.add_argument("--production-library", required=True,
        help="path to production DTCP library")
    parser.add_argument("--test-library", required=True,
        help="path to test DTCP library")
    parser.add_argument("--production-key-cvp2",
        help="path to directory with production key with CVP2 bit set")
    parser.add_argument("--production-key-no-cvp2", required=True,
        help="path to directory with production key without CVP2 bit set")
    parser.add_argument("--test-key-cvp2",
        help="path to directory with test key with CVP2 bit set")
    parser.add_argument("--test-key-no-cvp2", required=True,
        help="path to directory with test key without CVP2 bit set")
    parser.add_argument("--no-require-cvp2-bit", action="store_const",
        default=False, const=True,
        help="don't require keys to have the CVP2 bit set")
    parser.add_argument("--debug", "-d", action="store_const", default=False,
        const=True, help="output command stdout and stderr")
    
    args = parser.parse_args()
    tester = Tester(args.openssl, args.host, args.production_library,
        args.test_library, args.production_key_cvp2,
        args.production_key_no_cvp2, args.test_key_cvp2, args.test_key_no_cvp2,
        require_cvp2_bit=not args.no_require_cvp2_bit, debug=args.debug)
    tester.run_tests()
