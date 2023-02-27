#! /usr/bin/python3
import logging
import os
import smtplib
# # # # # # # # # # # # # # #
#Description: this function will validate aws resources 
# needed for the pgp-transform to work 
#Parameters : NA
# # # # # # # # # # # # # # #
def validate_pgp_transform():
    os.system("export HTTP_PROXY=http://outbound-proxy.services.aws.fico.com:3128;")
    os.system("export HTTPS_PROXY=http://outbound-proxy.services.aws.fico.com:3128;")
    os.system("export NO_PROXY=169.254.169.254;")
    os.system("/bin/python3 -m pytest /usr/local/lib/pgp_transform/test-pgp-transform.py > /tmp/test_result.log")
    errorCount=os.popen("grep failed /tmp/test_result.log | wc -l").read()
    if int(str(errorCount).strip())  >  0 : 
        logging.warning('pgp transform installation have some issues or unavailable / not Standard aws resources verify log /usr/local/lib/pgp_transform/test_result.log')
        
# # # # # # # # # # # # # # #
#Description: 
#Parameters : NA
# # # # # # # # # # # # # # #

try:
    if __name__ == '__main__':
        import time
        import pgp_transform
        validate_pgp_transform()
        while True:
            pgp_transform.process_messages()
            time.sleep(5)
except Exception as e:
    logging.exception(e)
