

def misp_upload_stix(misp, path='./data', version=1):
    misp.upload_stix(path=path, version=version)
