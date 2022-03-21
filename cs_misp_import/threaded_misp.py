import logging
import requests
import time
import os

try:
    from pymisp import ExpandedPyMISP
except ImportError as no_pymisp:
    raise SystemExit(
        "The PyMISP project must be installed in order to use this program."
        ) from no_pymisp


class MISP(ExpandedPyMISP):
    MAX_RETRIES = 3
    def __init__(self, *args, **kwargs):
        self.thread_count = kwargs.get("max_threads") or min(32, (os.cpu_count() or 1) * 4)
        kwargs.pop("max_threads")
        super().__init__(*args, **kwargs)
        self._PyMISP__session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=int(self.thread_count), pool_maxsize=int(self.thread_count)))

    # def add_event(self, event, *args, **kwargs):
    #     for i in range(self.MAX_RETRIES):
    #         try:
    #             response = super().add_event(event, *args, **kwargs)
    #             if 'errors' not in response:
    #                 event_id = event["id"]
    #                 event_info = event["info"]
    #                 logging.info(f'Event {event_id} added. ({event_info})')
    #                 return

    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server: %s. Re-trying the request %f seconds', response['errors'], timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.warning('Caught an error from MISP server: %s. Exceeded number of retries', response['errors'])
    #         except Exception as e:
    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server. Re-trying the request %f seconds', timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.exception('Caught an error from MISP server. Exceeded number of retries')

    # def add_object(self, obj, *args, **kwargs):
    #     for i in range(self.MAX_RETRIES):
    #         try:
    #             response = super().add_object(obj, *args, **kwargs)
    #             if 'errors' not in response:
    #                 obj_id = obj["id"]
    #                 obj_info = obj["info"]
    #                 logging.info(f'Object {obj_id} added. ({obj_info})')
    #                 return

    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server: %s. Re-trying the request %f seconds', response['errors'], timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.warning('Caught an error from MISP server: %s. Exceeded number of retries', response['errors'])
    #         except Exception as e:
    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server. Re-trying the request %f seconds', timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.exception('Caught an error from MISP server. Exceeded number of retries')

    # def add_attribute(self, attrib, *args, **kwargs):
    #     for i in range(self.MAX_RETRIES):
    #         try:
    #             response = super().add_attribute(attrib, *args, **kwargs)
    #             if 'errors' not in response:
    #                 attrib_id = attrib["id"]
    #                 attrib_info = attrib["info"]
    #                 logging.info(f'Attribute {attrib_id} added. ({attrib_info})')
    #                 return

    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server: %s. Re-trying the request %f seconds', response['errors'], timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.warning('Caught an error from MISP server: %s. Exceeded number of retries', response['errors'])
    #         except Exception as e:
    #             if i + 1 < self.MAX_RETRIES:
    #                 timeout = 0.3 * 2 ** i
    #                 logging.warning('Caught an error from MISP server. Re-trying the request %f seconds', timeout)
    #                 time.sleep(timeout)
    #             else:
    #                 logging.exception('Caught an error from MISP server. Exceeded number of retries')

    def delete_event(self, event, *args, **kwargs):
        for i in range(self.MAX_RETRIES):
            try:
                response = super().delete_event(event, *args, **kwargs)
                if 'errors' not in response:
                    event_id = event["id"]
                    event_info = event["info"]
                    logging.info(f'Event {event_id} deleted. ({event_info})')
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
