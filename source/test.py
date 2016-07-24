
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



createCert("test.openampere.com", "/CN=Test/", "testpassword", True, "DNS:client,DNS:test.openamepere.com,IP:192.168.2.2")
print ""

c1 = createCert("client.openampere.com", "/CN=Client/", "clientpassword", False, "")
print ""

createCert("client2.openampere.com", "/DC=com/DC=openampere/DC=test/CN=Client2", "client2password", False, "")
print ""

s2 = createCert("test2.openampere.com", "/CN=Test 2", "test2password", True, "DNS:client,DNS:test.openamepere.com,IP:192.168.2.2")
print ""
#
keytool = Keytool(cadir, "test2.openampere.com", "test2password", "", "keystore","test2password")
print ""
print keytool.build_trust_store()

print "Validating keytool config"
print keytool.validate()

keytool = Keytool(cadir, "client2.openampere.com", "client2password", [ "test2.openampere.com" ], "truststore","client2password")
print keytool.build_trust_store()
print ""
print line

print "Validating keytool config"
print keytool.validate()

print line
print "Building truststore"
print keytool.build_trust_store()

print line
print "Removing truststore"
#print keytool.remove_trust_store()

print line
print "Removing cert for client.openampere.com"
c1.remove_certificate()

print line
print "Removing cert for test2.openampere.com"
s2.remove_certificate()

