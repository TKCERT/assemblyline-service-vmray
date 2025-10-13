import shutil
import base64
import time
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Tuple

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultJSONSection
from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError


class VMRayService(ServiceBase):

    class JobType(Enum):
        JOBS = ("jobs", "job_id", "job")  # Dynamic or Web Analysis jobs
        # MD_JOBS = ... Deprecated in VMRay
        REPUTATION_JOBS = ("reputation_jobs", "reputation_job_id", "reputation_job")
        STATIC_JOBS = ("static_jobs", "job_id", "job")    # Shares the same structure with dynamic jobs
        VT_JOBS = ("vt_jobs", "vt_job_id", "vt_job")  # Virtus Total
        # Unclear how this part of the rest API works. There don't seem to be any corresponding rest endpoints
        # WHOIS_JOBS = (...)

    VMRAY_SERVICE_URL_CONFIG_KEY: str = "vmray_service_url"
    VMRAY_SERVICE_API_KEY_CONFIG_KEY: str = "vmray_service_api_key"

    def __init__(self, config=None):
        super(VMRayService, self).__init__(config)

        self.vmray_service_url: str = config.get(self.VMRAY_SERVICE_URL_CONFIG_KEY)
        self.vmray_api_key: str = config.get(self.VMRAY_SERVICE_API_KEY_CONFIG_KEY)
        self.verify = self.config.get("verify_certificate", True)

        if not self.vmray_service_url:
            raise RuntimeError("VMRay service URL not set in the config. Check the config section in the manifest?")

        if not self.vmray_api_key:
            raise RuntimeError("VMRay service API key not set in the config. Check the config section in the manifest?")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request):

        # The -15s is to give a bit of a margin before the timeout to collect and return some sort of status
        timeout_time = datetime.now() + timedelta(minutes=self.service_attributes.timeout) - timedelta(minutes=1)

        self.log.info(f"execute() from {self.service_attributes.name} service called for '{request.file_name}'")

        args = {"shareable": True,  # indicates whether the hash of the sample will be shared with VirusTotal.
                "reanalyze": True   # indicates whether a duplicate submission will create analysis jobs
                }

        try:
            with open(request.file_path, "rb") as sample_file_object:
                args["sample_file"] = sample_file_object
                args["sample_filename_b64enc"] = base64.b64encode(request.file_name.encode("utf-8")).decode("utf-8")

                try:
                    api = VMRayRESTAPI(self.vmray_service_url,
                                       self.vmray_api_key,
                                       verify_cert=self.verify)

                    vmray_data = self.submit_sample(api, args)
                except Exception as ex:
                    raise Exception(f"VMRay failed to process '{request.file_name}': {str(ex)}")

            errors = vmray_data.get("errors")
            if errors:
                errors = [error["error_msg"] for error in errors]
                message = f"VMRay failed to process '{request.file_name}': " + errors[0] \
                    if len(errors) == 1 \
                    else "\n" + "\n".join(f" - {error}" for error in errors)
                raise Exception(message)

            vmray_submission_id: str = vmray_data["submissions"][0]["submission_id"]
            vmray_submission_original_filename: str = vmray_data["submissions"][0]["submission_original_filename"]

            running_job_ids = defaultdict(list)

            job_count: int = 0

            for _name, job_type in self.JobType.__members__.items():
                job_category_key, job_id_key, _job_rest_endpoint = job_type.value
                if job_category_key in vmray_data:
                    for job in vmray_data[job_category_key]:
                        running_job_ids[job_type].append(job[job_id_key])
                        job_count += 1

            self.log.info(f"VMRay created {job_count} job(s) for the submission '{vmray_submission_original_filename}' "
                          f"(vmray id: {vmray_submission_id}):")
            for job_type, job_ids in running_job_ids.items():
                self.log.info(f"{job_type.value[1]}(s): {','.join([str(job_id) for job_id in job_ids])}")

            finished_jobs = []

            while running_job_ids:

                # create a copy of the jobs, so the original can be modified in the loop
                current_jobs: List[Tuple[self.JobType, List[int]]] = list(running_job_ids.items())

                unfinished_jobs = []

                for job_tuple in current_jobs:

                    job_type: self.JobType = job_tuple[0]
                    job_ids: List[int] = job_tuple[1]
                    _job_category_key, _job_id_key, job_rest_endpoint = job_type.value

                    for job_id in job_ids:

                        analysis = self.get_job_analysis(api, job_id)
                        if analysis:
                            self.log.info(f"VMRay finished analysis for {job_rest_endpoint} ({job_id_key}: {job_id}) "
                                          f"for the submission '{vmray_submission_original_filename}' (vmray id: "
                                          f"{vmray_submission_id})")
                            finished_jobs.append(analysis)
                            running_job_ids[job_type].remove(job_id)

                            report_file_path = f"/tmp/vmray_report_job{job_id}.pdf"
                            with open(report_file_path, "wb+") as report_file:
                                report_stream = api.call("GET", f"/rest/analysis/job/{job_id}/archive/report/report.pdf", raw_data=True)
                                shutil.copyfileobj(report_stream, report_file)
                            request.add_supplementary(report_file_path, f"VMRay_Analysis_Report_job{job_id}.pdf", f"VMRay generated report for job: {job_id}")
                        else:
                            self.log.info(f"VMRay hasn't finished analysis for {job_rest_endpoint} ({job_id_key}: "
                                          f"{job_id}) for the submission '{vmray_submission_original_filename}' (vmray "
                                          f"id: {vmray_submission_id})")
                            unfinished_jobs.append(self.get_job_status(api, job_id, job_rest_endpoint))

                    if not running_job_ids[job_type]:  # no more jobs for this job type
                        del running_job_ids[job_type]

                if datetime.now() >= timeout_time:
                    break

                time.sleep(10)  # Wait before the next round of calls to prevent hammering the server

            result = Result()

            finished_json_section = ResultJSONSection('VMRay Response')
            finished_json_section.set_json(finished_jobs)
            result.add_section(finished_json_section)

            if unfinished_jobs:
                self.log.warn(f"VMRay wasn't able to complete the following {len(unfinished_jobs)} of"
                              f" {len(finished_jobs) + len(unfinished_jobs)} before the "
                              f"~{self.service_attributes.timeout} minute timeout: {unfinished_jobs}")
                unfinished_json_section = ResultJSONSection(
                    "VMRay jobs not completed before the AssemblyLine service timeout of "
                    f" ~{self.service_attributes.timeout} minutes.")
                unfinished_json_section.set_json(unfinished_jobs)
                result.add_section(unfinished_json_section)

            self.log.debug(result)

            request.result = result
        except Exception as ex:
            self.log.error(str(ex))
            raise

    def submit_sample(self, api, args):
        ''' Submit the sample to VMRay'''
        return api.call("POST", "/rest/sample/submit", args)

    def get_job_analysis(self, api, job_id: int):
        try:
            return api.call("GET", f"/rest/analysis/job/{job_id}")
        except VMRayRESTAPIError as error:
            if error.args[0] == "No such element":
                return None
            else:
                raise

    def get_job_status(self, api, job_id: int, endpoint: str):
        try:
            return api.call("GET", f"/rest/{endpoint}/{job_id}")
        except VMRayRESTAPIError as error:
            if error.args[0] == "No such element":
                return None
            else:
                raise
