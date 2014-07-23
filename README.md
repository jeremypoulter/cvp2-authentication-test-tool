# CVP2 Authentication Test Tool

Brendan Long <b.long@cablelabs.com>

## Setup

### OpenSSL

First, get a checkout of the CVP2 team's OpenSSL build:

    git clone https://github.com/cablelabs/openssl.git
    cd openssl

Then open s_client.c:

    gedit apps/s_client.c &

Change line 2826 at the end of `validate_dtcp_suppdata()` from `return -1;` to `return 0;`. This will cause OpenSSL to ignore server DTCP validation errors.

**Note: This is extremely insecure.** We need to do this for our test program because we want the test that the server rejects our connection, and normally the client wouldn't even try once it knows that the server certificate is invalid. Needless to say, don't use this checkout for anything that needs to be actually secure.

Now build OpenSSL:

    ./config
    make

[Email me](mailto:b.long@cablelabs.com) if that's not enough to build OpenSSL.

Edit catt.conf's `OpenSSL` line to be the full path to apps/openssl (`echo $PWD/apps/openssl` might help).

## Get Keys

To run the tool, you will need:

  * A production DTCP library.
  * A test DTCP library.
  * A production DTCP certificate and key with the CVP2 bit set.
  * A production DTCP certificate and key without the CVP2 bit set.
  * A test DTCP certificate and key without the CVP2 bit set.

If you have a test DTCP certificate and key with the CVP2 bit set, you can also use that.

Collect all of those files, then edit catt.conf to point to them.

## Run

Clone this repo if you haven't already:

    git clone https://github.com/cablelabs/cvp2-authentication-test-tool.git
    cd cvp2-authentication-test-tool

See the output of `./catt.py -h` for all options. Most likely you will want to run it like:

    ./catt.py --config catt.conf --host [...]

For example, to run against localhost:

    ./catt.py --config catt.conf --host localhost
