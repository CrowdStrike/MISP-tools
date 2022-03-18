import logging
import requests
import time
import os
from pymisp import ExpandedPyMISP, MISPObject, MISPEvent, MISPAttribute, MISPOrganisation



class MISP(ExpandedPyMISP):
    MAX_RETRIES = 3
    MAX_THREAD_COUNT = 32
    def __init__(self, *args, **kwargs):
        max_thread_count = int(kwargs.get("max_threads", min(32, (os.cpu_count() or 1) * 4)))
        kwargs.pop("max_threads")
        super().__init__(*args, **kwargs)
        
        self._PyMISP__session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=max_thread_count, pool_maxsize=max_thread_count))
        self.MAX_THREAD_COUNT = max_thread_count

    def delete_event(self, event, *args, **kwargs):
        for i in range(self.MAX_RETRIES):
            try:
                response = super().delete_event(event, *args, **kwargs)
                if 'errors' not in response:
                    return

                if i + 1 < self.MAX_RETRIES:
                    timeout = 0.3 * 2 ** i
                    logging.warning('Caught an error from MISP server: %s. Re-trying the request %f seconds', response['errors'], timeout)
                    time.sleep(timeout)
                else:
                    logging.warning('Caught an error from MISP server: %s. Exceeded number of retries', response['errors'])
            except Exception as e:
                if i + 1 < self.MAX_RETRIES:
                    timeout = 0.3 * 2 ** i
                    logging.warning('Caught an error from MISP server. Re-trying the request %f seconds', timeout)
                    time.sleep(timeout)
                else:
                    logging.exception('Caught an error from MISP server. Exceeded number of retries')