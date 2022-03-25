import logging
import requests
import time
import os

try:
    from pymisp import ExpandedPyMISP, PyMISPError
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP project must be installed in order to use this program."
        ) from no_pymisp


class MISP(ExpandedPyMISP):
    MAX_RETRIES = 3
    def __init__(self, *args, **kwargs):
        self.thread_count = int(kwargs.get("max_threads") or min(32, (os.cpu_count() or 1) * 4))
        kwargs.pop("max_threads")
        super().__init__(*args, **kwargs)
        self._PyMISP__session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=int(self.thread_count), pool_maxsize=int(self.thread_count)*2))

        self.deleted_event_count = 0

    def paged_search(self, tags, timestamp):
        PAGE_LIMIT = 5000
        while True:
            for page in self.search(tags=tags, timestamp=timestamp, limit=PAGE_LIMIT):
                yield page

                if not page['Event']:
                    break
            #break

    def delete_event(self, *args, **kwargs):
        if self.deleted_event_count % 5000 == 0 and self.deleted_event_count:
            logging.info("%i events deleted.", self.deleted_event_count)
        result = self._retry(super().delete_event, *args, **kwargs)
        if "errors" not in result:
            self.deleted_event_count += 1

    def get_organisation(self, *args, **kwargs):
        return self._retry(super().get_organisation, *args, **kwargs)

    def _retry(self, f, *args, **kwargs):
        for i in range(self.MAX_RETRIES):
            try:
                response = f(*args, **kwargs)

                if "errors" not in response:
                    return response
                if response["errors"][0] == 404:
                    return response

                if i + 1 < self.MAX_RETRIES:
                    timeout = 0.3 * 2 ** i
                    logging.warning('Caught an error from MISP server: %s. Re-trying the request %f seconds', response['errors'], timeout)
                    time.sleep(timeout)
                else:
                    raise PyMISPError("MISP Error: {}".format(response['errors']))
            except Exception as e:
                if i + 1 < self.MAX_RETRIES:
                    timeout = 0.3 * 2 ** i
                    logging.warning('Caught an error from MISP server. Re-trying the request %f seconds', timeout)
                    time.sleep(timeout)
                else:
                    logging.exception('Caught an error from MISP server. Exceeded number of retries')
                    raise e
