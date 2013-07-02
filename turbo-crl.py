#!/usr/bin/python
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Turbo-CRL -- A tool for fetching CRL lists.
#
TCRL_VER = "Turbo-CRL v1.0.1a (development version)"

import os
import sys
import time
import getopt
import random
import urllib2
import subprocess

# Constants which probably don't need changing
# The path to the openssl binary
OPENSSL_PATH = "/usr/bin/openssl"
# Extension of the CRL URL file
CRLURL_EXT = ".crl_url"
# Extension of a CRL file
CRL_EXT = ".r0"
# Extension of a temporary CRL file
CRL_TMP_EXT = ".r0.tmp"
# Extension of a hashed certificate
# (Normally a symlink to a .pem file)
CA_EXT = ".0"


class TCRL:
  """ TCRL class -- Main logic for the Turbo-CRL application. """

  @staticmethod
  def get_files(base_path, ext):
    """ Look in "base_path" for all files ending with "ext" and return them
        as a list.
    """
    found_files = []
    for file in os.listdir(base_path):
      file_base, file_ext = os.path.splitext(file)
      if file_ext == ext:
        found_files.append(file_base)
    return found_files

  @staticmethod
  def fix_links(base_path, debug = False):
    """ This searches base_path and creates CRL links using some rules:
          1) Find all the <hash>.0 files to get all the CA hashes.
          2) Dereference the <hash>.0 symlinks to get <ca>.pem files
          3) Create <hash>.r0 -> <ca>.r0 symlink if it doesn't already exist
             (Overwriting any other .r0 files that other tools make).
    """
    for file_name in TCRL.get_files(base_path, CA_EXT):
      cert_link = file_name + CA_EXT
      cert_link_full = os.path.join(base_path, cert_link)
      if not os.path.islink(cert_link_full):
        print "Unexpected file (should be a symlink): %s" % cert_link_full
        continue
      cert_target = os.readlink(cert_link_full)
      ca_name, _ = os.path.splitext(cert_target)
      crl_target = ca_name + CRL_EXT
      crl_link = file_name + CRL_EXT
      crl_link_full = os.path.join(base_path, crl_link)
      # Check if the link already exists
      if os.path.lexists(crl_link_full):
        # It does, so verify it...
        if (not os.path.islink(crl_link_full)) \
             or (os.readlink(crl_link_full) != crl_target):
          # <hash>.r0 is not a link, or doesn't point to the right place...
          # Remove it.
          if debug:
            print "Deleting bad CRL link %s." % crl_link_full
          os.unlink(crl_link_full)
        else:
          # Link exists and is fine, just skip it
          if debug:
            print "CRL link %s is OK." % crl_link_full
          continue
      # Create <hash>.r0 -> <ca>.r0 link if it doesn't exist
      # If it does exist, it must already be correct
      if not os.path.lexists(crl_link_full):
        if debug:
          print "Linking CRL %s -> %s" % (crl_link_full, crl_target)
        os.symlink(crl_target, crl_link_full)

  @staticmethod
  def process_crls(base_path, debug = False):
    """ Search base_path for crl_url files.
        Run fetch_crl for each file discovered.
    """
    for ca_name in TCRL.get_files(base_path, CRLURL_EXT):
      TCRL.fetch_crl(base_path, ca_name, debug)

  @staticmethod
  def fetch_crl(base_path, ca_name, debug = False):
    """ Fetch a CRL from a <base_path>/<ca_name>.crl_url URL
        and write it to <base_path>/<ca_name>.r0 (using write_crl).
    """
    if debug:
      print "Processing CA %s..." % ca_name
    error = None
    f = open(os.path.join(base_path, ca_name + CRLURL_EXT), "r")
    for url in f:
      url = url.strip()
      if (len(url) == 0) or (url.startswith("#")):
        continue # Skip blank and comment lines
      # Actually try to get the data and write the file
      try:
        if debug:
          print "Trying URL '%s'..." % url
        http_resp = urllib2.urlopen(url)
        crl_data = http_resp.read()
        TCRL.write_crl(base_path, ca_name, crl_data, debug)
        # Success, CRL written, don't try any more URLs
        error = None
        break
      except Exception, err:
        error = "Failed to fetch %s: %s" % (ca_name, str(err))
        if debug:
          print "Intermediate error: %s" % error
    f.close()
    if error:
      # Failed to get from any URLs, print the last error
      print error

  @staticmethod
  def write_crl(base_path, ca_name, crl_data, debug = False):
    """ Write <crl_data> in PEM format to <base_path>/<ca_name>.r0
        If <crl_data> is in DER format, convert it.
        If <crl_data> is unrecognised, throw an exception.
    """
    if not crl_data.startswith("-----BEGIN X509 CRL-----"):
      # CRL data is not PEM...
      if not crl_data.startswith("0"):
        # CRL data is not DER...
        raise Exception("Unrecognised data type from %s." % ca_name)
      # Convert crl_data from DER to PEM
      if debug:
        print "Converting %s data from DER to PEM..." % ca_name
      crl_data = TCRL.crl_pem_to_der(crl_data)
    # Check we're not about to write nonsense...
    if not crl_data.startswith("-----BEGIN X509 CRL-----"):
      raise Exception("Bad CRL data from %s." % ca_name)
    # Now write the actual file
    crl_tmp_full = os.path.join(base_path, ca_name + CRL_TMP_EXT)
    crl_final_full = os.path.join(base_path, ca_name + CRL_EXT)
    # Write to a temp file and then rename to get an atomic replace on POSIX!
    if debug:
      print "Writing temp CRL file '%s'..." % crl_tmp_full
    f = open(crl_tmp_full, "w")
    f.write(crl_data)
    f.close()
    if debug:
      print "Overwriting final CRL '%s' with temp CRL..." % crl_final_full
    os.rename(crl_tmp_full, crl_final_full)

  @staticmethod
  def crl_pem_to_der(der_data):
    """ Convert <der_data> to PEM format and return it as a string.
        This internally shells openssl to do the conversion.
    """
    conv_cmd = [ OPENSSL_PATH, "crl", "-inform",  "DER",
                                      "-outform", "PEM" ]
    p = subprocess.Popen(conv_cmd, stdin  = subprocess.PIPE,
                                   stdout = subprocess.PIPE,
                                   stderr = subprocess.PIPE)
    p.stdin.write(der_data)
    output_pem, _ = p.communicate()
    return output_pem


def print_help():
  """ Print the usage information for the program and exit. """
  print TCRL_VER
  print "Usage: turbo-crl.py [--verbose/-v] [--delay/-d <time>] <cert dir>"
  print ""
  print "Option meanings:"
  print "  --verbose / -v -- Show debug output."
  print "  --delay / -d   -- Wait a random time, up to <time> at start."
  print ""
  sys.exit(0)

if __name__ == "__main__":
  debug = False
  delay = 0

  # Process command line args:
  try:
    optlist, args = getopt.getopt(sys.argv[1:], 'vd:h',
                      ['verbose', 'delay', 'help'])
  except getopt.GetoptError, err:
    print str(err)
    print_help()

  for opt in optlist:
    if opt[0] in ("-h", "--help"):
      print_help()
    if opt[0] in ("-v", "--verbose"):
      debug = True
    if opt[0] in ("-d", "--delay"):
      try:
        delay = int(opt[1])
      except:
        print "Delay value must be a number."
        print_help()

  if len(args) == 0:
    print "<cert dir> missing."
    print_help()
  if len(args) > 1:
    print "Too many arguments after <cert dir>?"
    print_help()
  cert_dir = args[0]

  if delay:
    real_delay = random.randint(0, delay)
    if debug:
      print "Waiting %d seconds (out of a max of %d)." % (real_delay, delay)
    time.sleep(real_delay)

  # Download the CRLs
  if debug:
    print "Fetching CRLs..."
  TCRL.process_crls(cert_dir, debug)
  # Create any missing "hash-symlinks" to the CRLs
  if debug:
    print "Fixing CRL symlinks..."
  TCRL.fix_links(cert_dir, debug)
  # Mission complete.
  sys.exit(0)

