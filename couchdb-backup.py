#!/usr/bin/python

import argparse
import json
import hashlib
import couchdb
import gnupg
import tarfile
import boto
import os
from boto.s3.key import Key
from boto.s3.lifecycle import Lifecycle
from pynsca import NSCANotifier
from couchdb.tools import dump


def couchdb_backup(db_url, db_file_path):
    with open(db_file_path, 'w') as f:
        couchdb.tools.dump.dump_db(db_url, output=f)
    print 'Finished taking %s' % (db_file_path,)


def backup_tar_gz(source_file_path, tgz_file_path):
    with tarfile.open(tgz_file_path, "w:gz") as f:
        f.add(source_file_path)
    print 'Finished packing %s as %s' % (source_file_path, tgz_file_path,)


def pgp_file_encrypt(gpg_home, gpg_file_path):
    gpg = gnupg.GPG(homedir=gpg_home)
    with open(gpg_file_path, 'r') as f:
        gpg.encrypt_file(f, output=gpg_file_path + '.gpg')
    print 'Finished encrypting %s - Saved as %s' % (gpg_home, gpg_file_path + '.gpg',)


def file_checksum(cs_file_path, algorithm='md5', read_block_size=int(8192)):
    with open(cs_file_path, 'r') as f:
        hashed = hashlib.__dict__[algorithm]()
        for data in f.read(read_block_size):
            if not data:
                break
            hashed.update(data)
        return {algorithm: hashed.hexdigest()}


def s3_uploader(db_backup_bucket, gpg_file_path, update_seq, checksum):
    if db_backup_bucket not in con_s3.get_all_buckets():
        print 'Backup bucket is missing, creating new bucket ', db_backup_bucket
        con_s3.create_bucket(db_backup_bucket)
        bucket = con_s3.get_bucket(db_backup_bucket)

    else:
        bucket = con_s3.get_bucket(db_backup_bucket)
        lifecycle = Lifecycle()
        lifecycle.add_rule('14 Days CouchDB Expiration', os.path.basename(gpg_file_path), 'Enabled', 14)
        bucket.configure_lifecycle(lifecycle)

    key = Key(bucket)
    key.key = os.path.basename(gpg_file_path)
    key.set_acl('authenticated-read')
    key.set_metadata('UpdateSeq', update_seq)
    key.set_metadata('Checksum', checksum)
    key.set_contents_from_file(gpg_file_path)
    key.close()

    print 'Finished uploading backup to S3'


def get_update_seq(db_url, db_backup_bucket, gpg_file_path):
    bucket = con_s3.get_bucket(db_backup_bucket)
    key = bucket.get_key(os.path.basename(gpg_file_path))
    s3_update_seq = key.get_metadata('UpdateSeq')
    db_update_seq = couchdb.client.Database(db_url).info()['update_seq']

    return {'s3_update_seq': s3_update_seq, 'db_update_seq': db_update_seq}


def send_nsca(nsca_server_name, service_description, return_code, return_code_description):
    notify = NSCANotifier(nsca_server_name)
    notify.svc_result(nsca_server_name, service_description, return_code, return_code_description)


def run_backup():
    print 'Starting backup ...'
    couchdb_backup(db_url, db_file_path)
    backup_tar_gz(source_file_path, tgz_file_path)
    pgp_file_encrypt(gpg_home, gpg_file_path)
    checksum = file_checksum(cs_file_path, algorithm, read_block_size)
    s3_uploader(db_backup_bucket, gpg_file_path, update_seq['db_update_seq'], checksum['algorithm'])


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='CouchDB Backup Script')
    parser.add_argument('--file', help='Full path of a config file in JSON format', required=True)
    parser.add_argument('--force', help='Force backup process regardless update_seq or checksum verification results',
                        required=False)
    args = parser.parse_args()

    config = json.load(open(args.file, 'r'))

    con_s3 = boto.connect_s3(aws_region=config['aws_credentials']['aws_region'],
                             aws_access_key_id=config['aws_credentials']['aws_access_key_id'],
                             aws_secret_access_key=config['aws_credentials']['aws_secret_access_key'])

    db_url = config['couchdb_backup']['db_url']
    db_file_path = config['couchdb_backup']['db_file_path']
    source_file_path = config['backup_tar_gz']['source_file_path']
    tgz_file_path = config['backup_tar_gz']['tgz_file_path']
    gpg_home = config['pgp_file_encrypt']['gpg_home']
    gpg_file_path = config['pgp_file_encrypt']['gpg_file_path']
    cs_file_path = config['file_checksum']['cs_file_path']
    algorithm = config['file_checksum']['algorithm']
    read_block_size = config['file_checksum']['read_block_size']
    db_backup_bucket = ['s3_uploader']['db_backup_bucket']
    nsca_server_name = ['send_nsca']['nsca_server_name']
    service_description = ['send_nsca']['service_description']

    update_seq = get_update_seq(db_url, db_backup_bucket, gpg_file_path)

    if update_seq['s3_update_seq'] is not update_seq['db_update_seq']:
        try:
            run_backup()
            send_nsca(nsca_server_name, service_description, 0, 'CouchDB Backup finished successfully')
        except Exception as e:
            send_nsca(nsca_server_name, service_description, 2, e)
            print e

    elif update_seq['s3_update_seq'] is update_seq['db_update_seq']:
        if args.force:
            try:
                run_backup()
                send_nsca(nsca_server_name, service_description, 1, 'CouchDB Backup finished successfully using --force')
            except Exception as e:
                send_nsca(nsca_server_name, service_description, 2, e)
                print e

        else:
            print 'update_seq values of S3 backup and CouchDB server are equal no need to backup\
                   \n use --force to backup regardless update_seq value'
            send_nsca(nsca_server_name, service_description, 1, 'Backup Skipped - update_seq values of S3 backup'
                                                               ' and CouchDB server are equal')