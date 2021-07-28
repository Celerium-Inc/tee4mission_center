import glob
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from absl import app, flags
from pymisp import PyMISP

from mission_center_api import MissionCenter
from misp_api import misp_upload_stix
from splunk_api import splunk_upload_stix

FLAGS = flags.FLAGS

# Flag names are globally defined!  So in general, we need to be
# careful to pick names that are unlikely to be used by other libraries.
# If there is a conflict, we'll get an error at import time.
flags.DEFINE_string('mc_host', 'https://missioncenter.celeriumd.net', 'Mission Center Host')
flags.DEFINE_string('mc_username', '', 'Mission Center Username')
flags.DEFINE_string('mc_api_key', '', 'Mission Center API Token')
flags.DEFINE_boolean('mc_ssl_verify', True, 'Mission Center SSL Verify')

flags.DEFINE_string('misp_api_key', '', 'MISP API Token')
flags.DEFINE_string('misp_host', '', 'MISP Host')
flags.DEFINE_boolean('misp_ssl_verify', True, 'MISP SSL Verify')

flags.DEFINE_string('splunk_username', '', 'Splunk Username')
flags.DEFINE_string('splunk_password', '', 'Splunk Password')
flags.DEFINE_string('splunk_host', '', 'Splunk Host')
flags.DEFINE_boolean('splunk_ssl_verify', True, 'Splunk SSL Verify')

flags.DEFINE_boolean('debug', False, 'Produces debugging output')


def main(argv):
    if FLAGS.debug:
        print('non-flag arguments:', argv)
        print(f'Hello, {FLAGS.mc_username}!')

    mc_api = MissionCenter(FLAGS)
    mc_api.get_threat_extraction()

    for path in glob.glob('./data/*.json'):
        with open(path) as fh:
            try:
                data = json.load(fh)
            except json.decoder.JSONDecodeError:
                print(f'Invalid JSON in the file: {path}')
                continue
            splunk_upload_stix(data=data, FLAGS=FLAGS)

    misp = PyMISP(FLAGS.misp_host, FLAGS.misp_api_key, FLAGS.misp_ssl_verify)
    for path in glob.glob('./data/*.stix'):
        misp_upload_stix(misp, path=path, version=1)


if __name__ == '__main__':
    app.run(main)

