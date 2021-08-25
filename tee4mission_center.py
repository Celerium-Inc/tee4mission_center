import base64
import glob
import json
import os
import urllib3

from absl import app, flags
from pymisp import PyMISP

from mission_center_api import MissionCenter
from misp_api import misp_upload_stix
from splunk_api import splunk_upload_stix, splunk_es_upload_stix

FLAGS = flags.FLAGS

# Flag names are globally defined!  So in general, we need to be
# careful to pick names that are unlikely to be used by other libraries.
# If there is a conflict, we'll get an error at import time.
flags.DEFINE_string('mc_host', '', 'Mission Center Host')
flags.DEFINE_string('mc_username', '', 'Mission Center Username')
flags.DEFINE_string('mc_api_key', '', 'Mission Center API Token')
flags.DEFINE_boolean('mc_ssl_verify', True, 'Mission Center SSL Verify')

# get a report of groups/categories
flags.DEFINE_boolean('mc_get_categories', False, 'Get Mission Center Categories, write a report, and exit')
flags.DEFINE_boolean('mc_get_threads', False, 'Get Mission Center Threads, write a report, and exit')

# process subset of groups/categories/threads
flags.DEFINE_list('mc_include_categories', None, 'Specify list of `groupId;categoryId,...` to upload')
flags.DEFINE_list('mc_include_threads', None, 'Specify list of `threadId,...` to upload')

flags.DEFINE_string('misp_host', '', 'MISP Host')
flags.DEFINE_string('misp_api_key', '', 'MISP API Token')
flags.DEFINE_boolean('misp_ssl_verify', True, 'MISP SSL Verify')

flags.DEFINE_string('splunk_host', '', 'Splunk Host')
flags.DEFINE_string('splunk_username', '', 'Splunk Username')
flags.DEFINE_string('splunk_password', '', 'Splunk Password')
flags.DEFINE_boolean('splunk_ssl_verify', True, 'Splunk SSL Verify')
flags.DEFINE_boolean('splunk_es', True, 'Splunk Enterprise Security')

flags.DEFINE_boolean('debug', False, 'Produces debugging output')


def main(argv):
    if False in (FLAGS.splunk_ssl_verify, FLAGS.misp_ssl_verify, FLAGS.mc_ssl_verify):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if FLAGS.debug:
        print('non-flag arguments:', argv)

    mc_api = MissionCenter(FLAGS)

    if FLAGS.mc_host and FLAGS.mc_get_categories:
        mc_api.get_categories()
    elif FLAGS.mc_host and FLAGS.mc_get_threads:
        mc_api.get_categories(get_threads=True)
    elif FLAGS.mc_host:
        mc_api.get_threat_extraction()

    if FLAGS.splunk_host:
        if FLAGS.splunk_es:
            for path in glob.glob('./staging/*.stix'):
                with open(path) as fh:
                    stix = fh.read()
                    b64str = base64.b64encode(stix.encode('utf-8')).decode('utf-8')
                success = splunk_es_upload_stix(b64str, path, FLAGS=FLAGS)
                if success:
                    os.rename(path, path.replace('staging', 'complete'))  # mv from staging to complete
                else:
                    os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed
        else:
            for path in glob.glob('./staging/*.json'):
                with open(path) as fh:
                    try:
                        data = json.load(fh)
                    except json.decoder.JSONDecodeError:
                        print(f'Invalid JSON in the file: {path}')
                        continue
                    success = splunk_upload_stix(data=data, FLAGS=FLAGS)
                    if success:
                        os.rename(path, path.replace('staging', 'complete'))  # mv from staging to complete
                    else:
                        os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed

    if FLAGS.misp_host:
        misp = PyMISP(FLAGS.misp_host, FLAGS.misp_api_key, FLAGS.misp_ssl_verify)
        for path in glob.glob('./staging/*.stix'):
            success = misp_upload_stix(misp, path=path, version=1)
            if success:
                os.rename(path, path.replace('staging', 'complete'))  # mv from staging to complete
            else:
                os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed


if __name__ == '__main__':
    app.run(main)
