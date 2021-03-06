import os, shutil
from subprocess import call

KEY_STRENGTH = 2048
DAYS_VALID  = 3653 # ~10 years
TMPL_CA_CERT = "openssl req -x509 -config openssl.cnf -newkey rsa:{0} -days {1} -out cacert.pem -outform PEM -subj \"{2}\" -nodes"
TMPL_CONVERT = "openssl x509 -in cacert.pem -out cacert.cer -outform DER"
TMPL_CA_HASH = "c_rehash -n {0} "
DEV_NULL = open('/dev/null', 'w')

OPENSSL_CNF = """
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME      = .
RANDFILE    = $ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file   = $ENV::HOME/.oid
oid_section   = new_oids


# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions    = 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca' and 'req'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:

####################################################################
[ ca ]
default_ca  = CA_default    # The default ca section

####################################################################
[ CA_default ]

dir             = {0}                   # Where everything is kept
certs           = $dir/certs            # Where the issued certs are kept
crl_dir         = $dir/crl              # Where the issued crl are kept
database        = $dir/index.txt        # database index file.
#unique_subject = no                    # Set to 'no' to allow creation of
                                        # several ctificates with same subject.
new_certs_dir   = $dir/certs            # default place for new certs.

certificate = $dir/cacert.pem   # The CA certificate
serial    = $dir/serial     # The current serial number
crl   = $dir/crl.pem    # The current CRL
private_key = $dir/private/cakey.pem  # The private key
RANDFILE  = $dir/private/.rand  # private random number file

x509_extensions = usr_cert    # The extentions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt  = ca_default    # Subject Name options
cert_opt  = ca_default    # Certificate field options

# Extension copying option: use with caution.
# copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crl_extensions  = crl_ext

default_days  = 365     # how long to certify for
default_crl_days= 30      # how long before next CRL
default_md  = sha256      # which md to use.
preserve  = no      # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy    = policy_anything

# For the CA policy
[ policy_match ]
countryName   = match
stateOrProvinceName = match
organizationName  = match
organizationalUnitName  = optional
commonName    = supplied
emailAddress    = optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName   = optional
stateOrProvinceName = optional
localityName    = optional
organizationName  = optional
organizationalUnitName  = optional
commonName    = supplied
emailAddress    = optional

####################################################################
[ req ]
default_bits    = 2048
default_keyfile   = private/cakey.pem
distinguished_name  = req_distinguished_name
attributes    = req_attributes
x509_extensions = v3_ca # The extentions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix   : PrintableString, BMPString.
# utf8only: only UTF8Strings.
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: current versions of Netscape crash on BMPStrings or UTF8Strings
# so use this option with caution!
string_mask = nombstr

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName     = Country Name (2 letter code)
countryName_default   = ZZ
countryName_min     = 2
countryName_max     = 2

#stateOrProvinceName    = State or Province Name (full name)
#stateOrProvinceName_default  = Berkshire

#localityName     = Locality Name (eg, city)
#localityName_default   = Newbury

0.organizationName    = Organization Name (eg, company)
0.organizationName_default  = Fake Org

# we can do this but it is not needed normally :-)
#1.organizationName   = Second Organization Name (eg, company)
#1.organizationName_default = World Wide Web Pty Ltd

organizationalUnitName    = Organizational Unit Name (eg, section)
organizationalUnitName_default  = Hosts

commonName      = Common Name (eg, your name or your server\'s hostname)
commonName_max      = 64
commonName_default    = Fake Org Fake CA - d59341ee

# SET-ex3     = SET extension number 3

[ req_attributes ]
unstructuredName    = An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# This will be displayed in Netscape's comment listbox.
nsComment     = "Completely Fake Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
subjectAltName=email:copy

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
#keyUsage = nonRepudiation, digitalSignature, keyEncipherment
keyUsage = keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer:always

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# For normal client use this is typical
nsCertType = client, email

# This is typical in keyUsage for a client certificate.
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

"""

class CA:

    def __init__(self, cadir, subj, force):
        self.cadir = os.path.realpath(self.normalize_directory_path(cadir))
        self.subj = subj
        self.force = force

    def normalize_directory_path(self, path):
        if path.endswith(os.sep):
            return path[:-1]
        else:
            return path

    def create_dir_if_not_exist(self, dir):
        if not os.path.exists(dir):
            try:
                os.mkdir(dir)
            except Exception as e:
                return dict(success=False, msg=e)
        return dict(success=True)

    def log(self, msg):
        logifle = open('/tmp/tcri-cert.log', 'a')
        logifle.write(msg)
        logifle.write("\n")
        logifle.write("\n")
        logifle.close()

    def execute_command(self, cmd):
        call(cmd, shell=True, stdout=DEV_NULL, stderr=DEV_NULL)

    def check_if_ca_exists(self):
        return os.path.isfile(fname) 

    def validate_setup(self):
        certDirValid = self.create_dir_if_not_exist(self.cadir)
        if not certDirValid["success"]:
            return certDirValid
        elif not "CN=" in self.subj:
            return dict(success=False, msg="Common Name (CN) not found in subject string.")
        else:
            return dict(success=True)

    def setup(self):
        changed = False
        changes = []

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        fileOpensslCnf = "openssl.cnf"

        if not os.path.exists(fileOpensslCnf):
            opensslCnf = open(fileOpensslCnf, "w")
            opensslCnf.write(OPENSSL_CNF.format(self.cadir))
            opensslCnf.close()
            changes.append("Wrote openssl.cnf file.")
            changed = True

        dirPrivate = "private"

        if not os.path.exists(dirPrivate):
            os.mkdir(dirPrivate, 0700)
            changes.append("Created private directory.")
            changed = True

        dirCerts = "certs"

        if not os.path.exists(dirCerts):
            os.mkdir(dirCerts)
            changes.append("Created certs directory.")
            changed = True

        fileSerial = "serial"

        if not os.path.exists(fileSerial):
            serial = open(fileSerial, "w")
            serial.write("01")
            serial.close()
            changes.append("Created serial file.")
            changed = True

        fileIndexTxt = "index.txt"

        if not os.path.exists(fileIndexTxt):
            with file(fileIndexTxt, "a"):
                os.utime(fileIndexTxt, None)
            changes.append("Created index.txt file")
            changed = True

        fileCaCert = "cacert.pem"

        if not os.path.exists(fileCaCert):
            cmd = TMPL_CA_CERT.format(KEY_STRENGTH, DAYS_VALID, self.subj)
            self.execute_command(cmd)

            cmd = TMPL_CA_HASH.format(self.cadir)
            self.execute_command(cmd)

            changes.append("Created CA certificate.")
            changed = True

        fileCaDerCert = "cacert.cer"

        if not os.path.exists(fileCaDerCert):
            cmd = TMPL_CONVERT
            self.execute_command(cmd)
            changes.append("Converted CA certificate to DER format.")
            changed = True

        os.chdir(CURDIR)

        return dict(success=True, changed=changed, changes=changes)

    def removeCA(self):

        if os.path.exists(self.cadir):
            shutil.rmtree(self.cadir)
            return dict(success=True, changed=True, changes=["Directory '{0}' removed".format(self.cadir)])
        else:
            return dict(success=True, changed=False, changes=[], msg="CA directory '{0}' does not exist.".format(self.cadir))
