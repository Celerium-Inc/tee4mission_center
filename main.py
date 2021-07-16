from absl import app
from absl import flags

from mission_center_api import MissionCenter

FLAGS = flags.FLAGS

# Flag names are globally defined!  So in general, we need to be
# careful to pick names that are unlikely to be used by other libraries.
# If there is a conflict, we'll get an error at import time.
flags.DEFINE_string('host', 'https://missioncenter.celeriumd.net', 'Mission Center Host')
flags.DEFINE_string('username', '', 'Username')
flags.DEFINE_string('api_key', '', 'API Token')
flags.DEFINE_string('thread_id', '16121783', 'Thread ID')
flags.DEFINE_boolean('debug', False, 'Produces debugging output.')


def main(argv):
    if FLAGS.debug:
        print('non-flag arguments:', argv)
        print(f'Hello, {FLAGS.username}!')
    ms_api = MissionCenter(FLAGS.host, FLAGS.username, FLAGS.api_key)
    response = ms_api.get_current_user()

if __name__ == '__main__':
    app.run(main)

