
from ca import CA
from certificate import Certificate
from keytool import Keytool
import os

line = "----------------------------------------------"

cadir = "./testca"

ca = CA(cadir, "/CN=Test CA/", True)

ca.validate_setup()

r1 = ca.setup()

print "CA present"
print line
print r1

def createCert(certname, subj, password, isServerCert, subjAltName):
    print line
    print "Creating certificate for: {}".format(certname)
    cert = Certificate(cadir, certname, subj, password, isServerCert, subjAltName)
    print cert.create_certificate()
    return cert


createCert("test.openampere.com", "/CN=Test/", "abc123!@#$", True, "DNS.1=client,DNS.2=test.openamepere.com,IP.1=192.168.1.2")
c1 = createCert("client.openampere.com", "/CN=Client/", "asdfaer13", False, "")
createCert("client2.openampere.com", "/DC=com/DC=openampere/DC=test/CN=Client2", "asdf", False, "")
s2 = createCert("test2.openampere.com", "/CN=Test 2", "asdf987", True, "DNS.1=client,DNS.2=test.openamepere.com,IP.1=192.168.1.2")

print line
print "Removing cert for client.openampere.com"
c1.remove_certificate()

print line
print "Removing cert for test2.openampere.com"
s2.remove_certificate()

keytool = Keytool(cadir, "client2.openampere.com", "abc123!@#`902", [ "test.openampere.com" ])

print line
print "Validating keytool config"
print keytool.validate()

print line
print "Building truststore"
print keytool.build_trust_store()

print line
print "Removing truststore"
#print keytool.remove_trust_store()

