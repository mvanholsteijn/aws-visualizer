import boto3

def get_account_id_and_region():
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account'], sts.meta.region_name

