
from subprocess import call
import os

TMPL_GEN_TS = "keytool -import -noprompt -alias {0} -file {1} -keystore {2} -storepass '{3}'"
TMPL_GEN_KS = "keytool -importkeystore -noprompt -alias {0} -srckeystore {1} -destkeystore {2}  -srcstoretype PKCS12   -deststorepass '{3}' -destkeypass '{3}' -srcstorepass '{4}'"

DEV_NULL = open('/dev/null', 'w')

class Keytool:


    def __init__(self, cadir, certname, store_password, hosts_to_trust, certtype, src_password):

        self.cadir = os.path.realpath(cadir)
        self.certname = certname
        self.certtype = certtype
        self.store_password = store_password
        self.src_password = src_password
        self.hosts_to_trust = hosts_to_trust

    def log(self, msg):
        logifle = open('/tmp/keytoo.log', 'a')
        logifle.write(msg)
        logifle.write("\n")
        logifle.write("\n")
        logifle.close()

    def execute_command(self, cmd):
        call(cmd, shell=True, stdout=DEV_NULL, stderr=DEV_NULL)

    def validate(self):

        if not os.path.exists(self.cadir):
            return dict(success=False, msg="CA directory '{0}' does not exist.".format(self.cadir))
        elif self.certtype == 'truststore' and len(self.hosts_to_trust) == 0:
            return dict(success=False, msg="No hosts specified for the truststore.")
        else:
            return dict(success=True)

    def ensure_directory_exists(self, dir):
        if not os.path.exists(dir):
            os.mkdir(dir)

    def get_truststore_path(self, certtype):
        if certtype == "keystore":
          return self.cadir + "/keystores" + os.sep + self.certname + ".keystore.jks"
        else:
          return "truststores" + os.sep + self.certname + ".trust.jks"

    def get_storepass_path(self):
        return self.certname + ".storepass"

    def resolve_certificate(self, host):
        server = ""
        client = ""
        if self.certtype == "keystore":
          server = self.cadir + "/server/{0}/{0}.keycert.p12".format(host)
          client = self.cadir + "/client/{0}.keycert.p12".format(host)
        else:
          server = self.cadir + "/server/{0}/{0}.cert.pem.pub".format(host)
          client = self.cadir + "/client/{0}.keycert.pem".format(host)
        if os.path.exists(server):
            return server
        elif os.path.exists(client):
            return client
        else:
            return None

    def build_trust_store(self):

        changed = False
        success = True
        errors = []
        changes = []

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        if self.certtype == "truststore":
          self.ensure_directory_exists("truststores")
        else:
          self.ensure_directory_exists("keystores")

        truststore_path = self.get_truststore_path(self.certtype)
        storepass_path = self.get_storepass_path()

        if not os.path.exists(truststore_path):

            # Write the password out to file.
            with open(storepass_path, "w") as storepass:
                storepass.write(self.store_password)

            try:

                if self.certtype == "truststore":
                  cmd = TMPL_GEN_TS.format("CA", self.cadir + "/cacert.pem", self.cadir + "/" + truststore_path, self.store_password)
                  self.execute_command(cmd)
                  changed = True
                  changes.append("Added the CA Certificate to the truststore.")

                if self.certtype == "keystore":
                    hostcert = self.resolve_certificate(self.certname)
                    cmd = TMPL_GEN_KS.format(self.certname, hostcert, truststore_path, self.store_password, self.src_password)
                    self.execute_command(cmd)
                    os.chdir(CURDIR)

                    return dict(success=success, changed=changed, changes=changes, path=truststore_path, errors=errors, msg=", ".join(errors))

                for host in self.hosts_to_trust:

                    hostcert = self.resolve_certificate(host)

                    cmd = ""
                    if not hostcert is None:
                        cmd = TMPL_GEN_TS.format(host, hostcert, truststore_path, self.store_password)

                        changes.append("Executing: '{0}'".format(cmd))
                        self.execute_command(cmd)
                        changed = True
                        changes.append("Added '{0}' to the truststore.".format(host))
                    else:
                        success=False
                        errors.append("Could not find cert for host: {0}".format(hostcert))

            except Exception as e:
                success = False
                errors.append(e.message)

            finally:
                # Remove the password
                if os.path.exists(storepass_path):
                    os.remove(storepass_path)

        if success == False:
            os.remove(truststore_path)

        os.chdir(CURDIR)

        return dict(success=success, changed=changed, changes=changes, path=truststore_path, errors=errors, msg=", ".join(errors))


    def remove_trust_store(self):

        changed = False
        changes = []

        CURDIR = os.getcwd()

        os.chdir(self.cadir)

        truststore_path = self.get_truststore_path(self.certtype)

        if os.path.exists(truststore_path):
            os.remove(truststore_path)
            changed=True
            changes.append("Successfully removed truststore.")

        os.chdir(CURDIR)

        return dict(success=True, changed=changed, changes=changes, msg="")





