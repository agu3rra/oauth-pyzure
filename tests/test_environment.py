import os


class TestEnvironment():

    def test_environment(self):
        env_list = [
            'CLIENT_ID',
            'CLIENT_SECRET',
            'RESOURCE',
            'PYTHONPATH'
        ]
        for item in env_list:
            assert os.environ.get(item, None) is not None
