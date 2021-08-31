def misp_upload_stix(misp, path='./staging/', version=1):
    result = misp.upload_stix(path=path, version=version)
    return result.status_code < 300
