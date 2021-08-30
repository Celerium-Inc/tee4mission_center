import base64
import glob
import json
import os
import urllib3

from absl import app, flags
from pymisp import PyMISP

from mission_center_api import MissionCenter
from misp_api import misp_upload_stix
from splunk_api import splunk_upload_stix, splunk_upload_kv

from common import log

FLAGS = flags.FLAGS

# Flag names are globally defined!  So in general, we need to be
# careful to pick names that are unlikely to be used by other libraries.
# If there is a conflict, we'll get an error at import time.
flags.DEFINE_string('mc_host', '', 'Mission Center Host')
flags.DEFINE_string('mc_username', '', 'Mission Center Username')
flags.DEFINE_string('mc_api_key', '', 'Mission Center API Token')
flags.DEFINE_list('mc_te_types', ['stix', 'json'], 'Mission Center Threat Extraction file types')
flags.DEFINE_boolean('mc_ssl_verify', True, 'Mission Center SSL Verify')

# get a report of groups/categories
flags.DEFINE_boolean('mc_get_categories', False, 'Get Mission Center Categories, write a report, and exit')
flags.DEFINE_boolean('mc_get_threads', False, 'Get Mission Center Threads, write a report, and exit')

# process subset of groups/categories/threads
flags.DEFINE_list('mc_include_categories', None, 'Specify list of `groupId;categoryId,...` to upload')
flags.DEFINE_list('mc_include_threads', None, 'Specify list of `threadId,...` to upload')

flags.DEFINE_boolean('mc_extract_only', False, 'Extract to staging/ and skip uploading.')
flags.DEFINE_boolean('mc_upload_only', False, 'Upload from staging/ without checking for new extractions.')


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

    log(FLAGS, f'non-flag arguments: {argv}')

    mc_api = MissionCenter(FLAGS)

    threads_df = mc_api.get_categories(get_threads=True)

    if not FLAGS.mc_upload_only:
        mc_api.get_threat_extraction()

    if FLAGS.splunk_host and not FLAGS.mc_extract_only:
        for path in glob.glob('./staging/*.json'):
            with open(path) as fh:
                try:
                    data = json.loads(fh.read())
                except:
                    log(FLAGS, 'problem reading json')
                    os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed
                    continue
            if FLAGS.splunk_es:
                success = splunk_upload_kv(data, path, threads_df, FLAGS=FLAGS)
            else:
                success = splunk_upload_stix(data=data, FLAGS=FLAGS)
            if success:
                os.rename(path, path.replace('staging', 'complete'))  # mv from staging to complete
            else:
                os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed

    if FLAGS.misp_host and not FLAGS.mc_extract_only:
        misp = PyMISP(FLAGS.misp_host, FLAGS.misp_api_key, FLAGS.misp_ssl_verify)
        for path in glob.glob('./staging/*.stix'):
            success = misp_upload_stix(misp, path=path, version=1)
            if success:
                os.rename(path, path.replace('staging', 'complete'))  # mv from staging to complete
            else:
                os.rename(path, path.replace('staging', 'failed'))  # mv from staging to failed


if __name__ == '__main__':
    app.run(main)
