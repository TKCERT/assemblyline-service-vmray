import json
import shutil
import tempfile
from typing import Any, Dict, Optional
from pathlib import Path

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultImageSection
from vmray.rest_api import VMRayRESTAPI
from vmray.integration_kit import VMRaySubmissionKit

# TODO: Very important: make sure the verdict is extracted and mapped to AL tags and score
# TODO: extract artifacts as well as IOCs and add them to the result as tags

class VMRayService(ServiceBase):
    VMRAY_SERVICE_URL_CONFIG_KEY: str = "vmray_service_url"
    VMRAY_SERVICE_API_KEY_CONFIG_KEY: str = "vmray_service_api_key"

    def __init__(self, config: Optional[Dict] = None) -> None:
        super(VMRayService, self).__init__(config)

        self.vmray_service_url = self.config.get(self.VMRAY_SERVICE_URL_CONFIG_KEY)
        self.vmray_api_key = self.config.get(self.VMRAY_SERVICE_API_KEY_CONFIG_KEY)
        self.verify = self.config.get("verify_certificate", True)

        if not self.vmray_service_url:
            raise RuntimeError("VMRay service URL not set in the config. Check the config section in the manifest?")

        if not self.vmray_api_key:
            raise RuntimeError("VMRay service API key not set in the config. Check the config section in the manifest?")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request: ServiceRequest) -> None:
        self.log.info(f"execute() from {self.service_attributes.name} service called for '{request.file_name}'")

        request.result = Result()

        self.log.info(f"Submitting file to VMRay for analysis with timeout {self.service_attributes.timeout} seconds")

        submission_kit = VMRaySubmissionKit(self.vmray_service_url, self.vmray_api_key, self.verify)
        submission_results = submission_kit.submit_file(Path(request.file_path), params={
            "shareable": True,  # indicates whether the hash of the sample will be shared with VirusTotal
            "reanalyze": True,  # indicates whether a duplicate submission will create analysis jobs
            "user_config": json.dumps({"timeout": int(self.service_attributes.timeout / 2)}),
        })

        api = submission_kit._api
        for submission_result in submission_results:
            sample_id = submission_result._sample_id

            self._download_pdf_report_as_supplementary(
                request=request,
                api=api,
                report_endpoint=f"/rest/sample/{sample_id}/report",
                supplementary_filename=f"VMRay_Summary_{sample_id}.pdf",
                supplementary_description=f"Sample #{sample_id}",
            )

            analyses = submission_kit._api.get_analyses_by_submission_id(submission_result.submission_id)
            for analysis in analyses:
                analysis_id = analysis["analysis_id"]
                if "analysis_vm_description" in analysis:
                    analysis_name = f"{analysis['analysis_vm_description']} | {analysis['analysis_configuration_name']}"
                elif "analysis_static_config_name" in analysis:
                    analysis_name = f"{analysis['analysis_static_config_name']} static configuration"
                else:
                    analysis_name = f"Analysis #{analysis_id}"

                if analysis["analysis_pdf_created"]:
                    self._download_pdf_report_as_supplementary(
                        request=request,
                        api=api,
                        report_endpoint=f"/rest/analysis/{analysis_id}/archive/report/report.pdf",
                        supplementary_filename=f"VMRay_Analysis_{analysis_id}.pdf",
                        supplementary_description=analysis_name,
                    )

                if analysis["analysis_analyzer_name"] in ("vmray", "vmray_web"):
                    image_section = ResultImageSection(request, analysis_name)
                    for screenshot_name in self._iter_screenshot_filenames(api=api, analysis_id=analysis_id):
                        self._download_screenshot_into_image_section(
                            request=request,
                            image_section=image_section,
                            api=api,
                            analysis_id=analysis_id,
                            screenshot_name=screenshot_name,
                        )
                    request.result.add_section(image_section)

                print("analysis", json.dumps(analysis))
                report = submission_kit._api.get_report(analysis_id)
                print("report", json.dumps(json.load(report)))

    def _download(
        self,
        api: VMRayRESTAPI,
        file_endpoint: str,
    ) -> Any:
        return api.call("GET", file_endpoint, raw_data=True)

    def _download_pdf_report_as_supplementary(
        self,
        request: ServiceRequest,
        api: VMRayRESTAPI,
        report_endpoint: str,
        supplementary_filename: str,
        supplementary_description: str,
    ):
        with tempfile.NamedTemporaryFile(
            mode="wb+",
            suffix=".pdf",
            prefix="vmray_report_",
            dir=self.working_directory,
            delete=False,
        ) as output_file:
            shutil.copyfileobj(self._download(api, report_endpoint), output_file)
            return request.add_supplementary(output_file.name, supplementary_filename, supplementary_description)

    def _download_screenshot_into_image_section(
        self,
        request: ServiceRequest,
        image_section: ResultImageSection,
        api: VMRayRESTAPI,
        analysis_id: int,
        screenshot_name: str,
    ):
        screenshot_stream = self._download(
            api,
            file_endpoint=f"/rest/analysis/{analysis_id}/archive/screenshots/{screenshot_name}",
        )
        with tempfile.NamedTemporaryFile(
            mode="wb+",
            suffix=screenshot_name,
            prefix="vmray_screenshot_",
            dir=self.working_directory,
            delete=False,
        ) as output_file:
            shutil.copyfileobj(screenshot_stream, output_file)
            return image_section.add_image(output_file.name, screenshot_name, f"Screenshot for analysis {analysis_id}")

    def _iter_screenshot_filenames(
        self,
        api: VMRayRESTAPI,
        analysis_id: int,
    ) -> Any:
        for screenshot in self._download(
            api,
            file_endpoint=f"/rest/analysis/{analysis_id}/archive/screenshots/index.log",
        ).readlines():
            yield screenshot.decode().strip().split(" | ")[-1]
