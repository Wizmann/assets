import sys
import md5
import datetime

import qiniu.conf
import qiniu.io
import qiniu.rs

qiniu.conf.ACCESS_KEY = 'gx-bfKXZFRujsZqGkAA9g460U7DmS-mMuRqpEyO1'
qiniu.conf.SECRET_KEY = 'cVCsugwD14nbDzSfdoqtecJHvpVan576l0pqXZm8'

BUCKET_NAME = 'wizmann-pic'

def get_uptoken():
    print BUCKET_NAME
    policy = qiniu.rs.PutPolicy(BUCKET_NAME)
    uptoken = policy.token()
    return uptoken

def get_md5(fn):
    #return md5.new(fn).hexdigest()
    return fn

def print_usage():
    print 'USAGE: ./qiniupic pic_file_path'

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    uptoken = get_uptoken()

    local_file = sys.argv[1]
    key = get_md5(local_file)

    ret, err = qiniu.io.put_file(uptoken, key, local_file)

    if err is None:
        print ret
    else:
        print >> sys.stderr, err
    

