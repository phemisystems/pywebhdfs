from tornado import ioloop
from tornado.gen import coroutine
from pywebhdfs.tornado.webhdfs import PyWebHdfsClient
import logging

logging.basicConfig(level=logging.DEBUG)
_LOG = logging.getLogger(__name__)


@coroutine
def test_func():
    example_dir = 'user/hdfs/example_dir'
    example_file = '{dir}/example.txt'.format(dir=example_dir)
    example_data = '01010101010101010101010101010101010101010101\n'
    rename_dir = 'user/hdfs/example_rename'

    hdfs = PyWebHdfsClient(host='localhost', port='50070',
                           user_name='hduser')

    #create a new directory for the example
    print('making new HDFS directory at: {0}\n'.format(example_dir))
    yield hdfs.make_dir(example_dir)

    # get a dictionary of the directory's status
    dir_status = yield hdfs.get_file_dir_status(example_dir)
    print dir_status

    # create a new file on hdfs
    print('making new file at: {0}\n'.format(example_file))
    yield hdfs.create_file(example_file, example_data)

    file_status = yield hdfs.get_file_dir_status(example_file)
    print file_status

    #append to the file created in previous step
    print('appending to file at: {0}\n'.format(example_file))
    yield hdfs.append_file(example_file, example_data)

    file_status = yield hdfs.get_file_dir_status(example_file)
    print file_status

    #read in the data for the file
    print('reading data from file at: {0}\n'.format(example_file))
    file_data = yield hdfs.read_file(example_file)
    print file_data

    #rename the example_dir
    print('renaming directory from {0} to {1}\n').format(example_dir, rename_dir)
    yield hdfs.rename_file_dir(example_dir, '/{0}'.format(rename_dir))

    #list the contents of the new directory
    listdir_stats = yield hdfs.list_dir(rename_dir)
    print listdir_stats

    example_file = '{dir}/example.txt'.format(dir=rename_dir)

    #delete the example file
    print('deleting example file at: {0}'.format(example_file))
    yield hdfs.delete_file_dir(example_file)

    #list the contents of the directory
    listdir_stats = yield hdfs.list_dir(rename_dir)
    print listdir_stats

    #delete the example directory
    print('deleting the example directory at: {0}'.format(rename_dir))
    yield hdfs.delete_file_dir(rename_dir, recursive='true')

    ioloop.IOLoop.instance().stop()

if __name__ == '__main__':
    io_loop = ioloop.IOLoop.instance()
    io_loop.add_callback(test_func)
    io_loop.start()