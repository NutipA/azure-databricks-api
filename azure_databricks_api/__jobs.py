# Copyright (c) 2018 Microsoft
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

from azure_databricks_api.__base import RESTBase
from azure_databricks_api.exceptions import ResourceDoesNotExist, APIError, AuthorizationError, ERROR_CODES


class JobsAPI(RESTBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def create(self, name='Untitled', existing_cluster_id=None, new_cluster=None, **kwargs):
        METHOD = 'POST'
        API_PATH = '/jobs/create'

        job_config = {'name': name}

        # Validate if existing_cluster_id OR new_cluster is specified
        if existing_cluster_id:
            job_config.update(existing_cluster_id=existing_cluster_id)
        elif new_cluster:
            job_config.update(new_cluster=new_cluster)
        else:
            raise ValueError("Either 'existing_cluster_id' OR 'new_cluster' argument should be provided.")

        # Validate if at least one from notebook_task, spark_jar_task, spark_python_task, spark_submit_task
        # is specified
        if not any(x in kwargs for x in ['notebook_task', 'spark_jar_task', 'spark_python_task', 'spark_submit_task']):
            raise ValueError("At least one of 'notebook_task', 'spark_jar_task', 'spark_python_task', " +
                             "'spark_submit_task' argument should be provided.")

        # Validate if notebook_task field is not specified in conjunction with spark_jar_task
        if 'notebook_task' in kwargs and 'spark_jar_task' in kwargs:
            raise ValueError("'notebook_task' argument should not be provided in conjunction with 'spark_jar_task' " +
                             "argument.")

        # Merge kwargs and job_config
        job_config.update(kwargs)

        resp = self._rest_call[METHOD](API_PATH, data=job_config)

        if resp.status_code == 200:
            return resp.json()['job_id']

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                               resp.json().get('error_code'),
                                                               resp.json().get('message')))



    def list(self):
        METHOD = 'GET'
        API_PATH = '/jobs/list'

        resp = self._rest_call[METHOD](API_PATH)

        if resp.status_code == 200:
            return resp.json().get('jobs')

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            if resp.json().get("error_code") in ERROR_CODES:
                raise ERROR_CODES[resp.json().get('error_code')](resp.json().get('message'))
            else:
                raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                                   resp.json().get('error_code'),
                                                                   resp.json().get('message')))

    def delete(self):
        METHOD = 'POST'
        API_PATH = '/jobs/delete'

        raise NotImplementedError

    def get(self, job_id=None):
        METHOD = 'GET'
        API_PATH = '/jobs/get'

        data = {"job_id": job_id}

        resp = self._rest_call[METHOD](API_PATH, data=data)

        if resp.status_code == 200:
            return resp.json()

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            if resp.json().get("error_code") in ERROR_CODES:
                raise ERROR_CODES[resp.json().get('error_code')](resp.json().get('message'))
            else:
                raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                                   resp.json().get('error_code'),
                                                                   resp.json().get('message')))

    def reset(self):
        METHOD = 'POST'
        API_PATH = '/jobs/reset'

        raise NotImplementedError

    def run_now(self, job_id, **kwargs):
        METHOD = 'POST'
        API_PATH = '/jobs/run-now'

        run_config = {'job_id': job_id}

        # Merge kwargs and run_config
        run_config.update(kwargs)

        resp = self._rest_call[METHOD](API_PATH, data=run_config)

        if resp.status_code == 200:
            return resp.json()

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                               resp.json().get('error_code'),
                                                               resp.json().get('message')))

    def runs_submit(self):
        METHOD = 'POST'
        API_PATH = '/jobs/runs/submit'

        raise NotImplementedError

    def runs_list(self):
        METHOD = 'GET'
        API_PATH = '/jobs/runs/list'

        resp = self._rest_call[METHOD](API_PATH)

        if resp.status_code == 200:
            return resp.json().get('runs')

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            if resp.json().get("error_code") in ERROR_CODES:
                raise ERROR_CODES[resp.json().get('error_code')](resp.json().get('message'))
            else:
                raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                                   resp.json().get('error_code'),
                                                                   resp.json().get('message')))

    def runs_get(self, run_id=None):
        METHOD = 'GET'
        API_PATH = '/jobs/runs/get'

        data = {"run_id": run_id}

        resp = self._rest_call[METHOD](API_PATH, data=data)

        if resp.status_code == 200:
            return resp.json()

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            if resp.json().get("error_code") in ERROR_CODES:
                raise ERROR_CODES[resp.json().get('error_code')](resp.json().get('message'))
            else:
                raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                                   resp.json().get('error_code'),
                                                                   resp.json().get('message')))

    def runs_export(self):
        METHOD = 'GET'
        API_PATH = '/jobs/runs/export'

        raise NotImplementedError

    def runs_cancel(self):
        METHOD = 'POST'
        API_PATH = '/jobs/runs/cancel'

        raise NotImplementedError

    def runs_get_output(self, run_id=None):
        METHOD = 'GET'
        API_PATH = '/jobs/runs/get-output'

        data = {"run_id": run_id}

        resp = self._rest_call[METHOD](API_PATH, data=data)

        if resp.status_code == 200:
            return resp.json().get('notebook_output')

        elif resp.status_code == 403:
            raise AuthorizationError("User is not authorized or token is incorrect.")

        else:
            if resp.json().get("error_code") in ERROR_CODES:
                raise ERROR_CODES[resp.json().get('error_code')](resp.json().get('message'))
            else:
                raise APIError("Response code {0}: {1} {2}".format(resp.status_code,
                                                                   resp.json().get('error_code'),
                                                                   resp.json().get('message')))

    def runs_delete(self):
        METHOD = 'POST'
        API_PATH = '/jobs/runs/delete'

        raise NotImplementedError
