import glob

from absl import app, flags
import requests
from pymisp import PyMISP

from mission_center_api import MissionCenter
from misp_api import misp_upload_stix
from splunk_api import splunk_upload_stix

FLAGS = flags.FLAGS

# Flag names are globally defined!  So in general, we need to be
# careful to pick names that are unlikely to be used by other libraries.
# If there is a conflict, we'll get an error at import time.
flags.DEFINE_string('ms_host', 'https://missioncenter.celeriumd.net', 'Mission Center Host')
flags.DEFINE_string('ms_username', '', 'Username')
flags.DEFINE_string('ms_api_key', '', 'API Token')
flags.DEFINE_string('thread_id', '16121783', 'Thread ID')
flags.DEFINE_boolean('debug', False, 'Produces debugging output')

flags.DEFINE_string('misp_api_key', '', 'MISP API Token')
flags.DEFINE_string('misp_host', '', 'MISP Host')
flags.DEFINE_boolean('misp_ssl_verify', True, 'MISP SSL Verify')

flags.DEFINE_string('splunk_username', '', 'Splunk Username')
flags.DEFINE_string('splunk_password', '', 'Splunk Password')
flags.DEFINE_string('splunk_host', '', 'Splunk Host')
flags.DEFINE_boolean('splunk_ssl_verify', True, 'Splunk SSL Verify')


def main(argv):
    if FLAGS.debug:
        print('non-flag arguments:', argv)
        print(f'Hello, {FLAGS.ms_username}!')

    splunk_upload_stix(data={'bar': 'foo'}, FLAGS=FLAGS)

    ms_api = MissionCenter(FLAGS.ms_host, FLAGS.ms_username, FLAGS.ms_api_key)
    # response = ms_api.get_current_user()
    # response = ms_api.get_group_threads()
    response = ms_api.get_threat_extraction()
    if FLAGS.debug:
        print(response)

    misp = PyMISP(FLAGS.misp_host, FLAGS.misp_api_key, FLAGS.misp_ssl_verify)

    for path in glob.glob('./data/*.xml'):
        result = misp_upload_stix(misp, path=path, version=1)
        if FLAGS.debug:
            print(result)
        break


if __name__ == '__main__':
    app.run(main)

