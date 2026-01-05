import json
import os.path
import shutil
import tempfile
from datetime import timedelta
from typing import Any, Dict, Optional
from pathlib import Path

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT, Result, ResultSection, ResultImageSection, ResultTextSection, ResultJSONSection
)
from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError
from vmray.integration_kit import VMRaySubmissionKit

class VMRayService(ServiceBase):
    VMRAY_SERVICE_URL_CONFIG_KEY: str = "vmray_service_url"
    VMRAY_SERVICE_API_KEY_CONFIG_KEY: str = "vmray_service_api_key"
    VMRAY_SERVICE_SHAREABLE_CONFIG_KEY: str = "vmray_service_shareable"
    VMRAY_SERVICE_REANALYZE_CONFIG_KEY: str = "vmray_service_reanalyze"
    VMRAY_SERVICE_MAX_JOBS_CONFIG_KEY: str = "vmray_service_max_jobs"
    VMRAY_DEBUG_ADD_JSON_CONFIG_KEY: str = "vmray_debug_add_json"
    VMRAY_DEBUG_SAMPLE_ID_CONFIG_KEY: str = "vmray_debug_sample_id"

    def __init__(self, config: Optional[Dict] = None) -> None:
        super(VMRayService, self).__init__(config)

        self.vmray_service_url = self.config.get(self.VMRAY_SERVICE_URL_CONFIG_KEY)
        self.vmray_service_api_key = self.config.get(self.VMRAY_SERVICE_API_KEY_CONFIG_KEY)
        self.vmray_service_shareable = self.config.get(self.VMRAY_SERVICE_SHAREABLE_CONFIG_KEY, True)
        self.vmray_service_reanalyze = self.config.get(self.VMRAY_SERVICE_REANALYZE_CONFIG_KEY, True)
        self.vmray_service_max_jobs = self.config.get(self.VMRAY_SERVICE_MAX_JOBS_CONFIG_KEY, 1)
        self.vmray_debug_add_json = self.config.get(self.VMRAY_DEBUG_ADD_JSON_CONFIG_KEY, False)
        self.vmray_debug_sample_id = self.config.get(self.VMRAY_DEBUG_SAMPLE_ID_CONFIG_KEY, 0)
        self.verify = self.config.get("verify_certificate", True)

        if not self.vmray_service_url:
            raise RuntimeError("VMRay service URL not set in the config. Check the config section in the manifest?")

        if not self.vmray_service_api_key:
            raise RuntimeError("VMRay service API key not set in the config. Check the config section in the manifest?")

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request: ServiceRequest) -> None:
        self.log.info(f"execute() from {self.service_attributes.name} service called for '{request.file_name}'")

        request.result = Result()

        self.log.info(f"Submitting file to VMRay for analysis with timeout {self.service_attributes.timeout} seconds")

        submission_kit = VMRaySubmissionKit(self.vmray_service_url, self.vmray_service_api_key, self.verify)
        if self.vmray_debug_sample_id:
            submission_results = submission_kit.get_submissions_from_sample_id(self.vmray_debug_sample_id)[-1:]
        else:
            submission_results = submission_kit.submit_file(Path(request.file_path), params={
                "shareable": self.vmray_service_shareable,  # if the hash of the sample will be shared with VirusTotal
                "reanalyze": self.vmray_service_reanalyze,  # if a duplicate submission will create analysis jobs
                "max_jobs":  self.vmray_service_max_jobs,   # the maximum number of analysis jobs to create
                "user_config": json.dumps({"timeout": int(self.service_attributes.timeout / 2)}),  # 50% job timeout
            })

        self.log.info(f"Retrieved {len(submission_results)} submission result(s) from VMRay, processing analyses")

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

                analysis_section = ResultTextSection(analysis_name)
                request.result.add_section(analysis_section)

                messages_section = ResultTextSection("Notes")
                analysis_section.add_subsection(messages_section)

                analysis_verdict = analysis.get("analysis_verdict", "unknown")
                reason_code = analysis.get("analysis_verdict_reason_code", analysis.get("analysis_result_code"))
                reason_text = analysis.get("analysis_verdict_reason_description", analysis.get("analysis_result_str"))
                if reason_code and reason_text:
                    analysis_section.add_line(f"VERDICT: {analysis_verdict} ({reason_code}: {reason_text})")
                else:
                    analysis_section.add_line(f"VERDICT: {analysis_verdict}")
                if analysis_verdict == "malicious":
                    analysis_section.set_heuristic(4)
                elif analysis_verdict == "suspicious":
                    analysis_section.set_heuristic(3)
                elif analysis_verdict == "clean":
                    analysis_section.set_heuristic(0)

                if analysis["analysis_analyzer_name"] in ("vmray", "vmray_web"):
                    image_section = ResultImageSection(request, "Screenshots")
                    for screenshot_time, screenshot_name in self._iter_screenshots(api=api, analysis_id=analysis_id):
                        try:
                            self._download_screenshot_into_image_section(
                                request=request,
                                image_section=image_section,
                                api=api,
                                analysis_id=analysis_id,
                                screenshot_name=screenshot_name,
                                screenshot_text=f"Screenshot at {screenshot_time}",
                            )
                        except OSError:
                            self._log_exception(analysis_section, f"Could not download screenshot '{screenshot_name}'")
                    analysis_section.add_subsection(image_section)

                if self.vmray_debug_add_json:
                    analysis_json = ResultJSONSection("Analysis JSON", auto_collapse=True)
                    analysis_json.set_json(analysis)
                    analysis_section.add_subsection(analysis_json)

                try:
                    report = json.load(submission_kit._api.get_report(analysis_id))
                except Exception:
                    self._log_exception(analysis_section, f"Could not get summary report for analysis #{analysis_id}")
                    continue

                try:
                    self._convert_report_to_result(analysis_section, messages_section, report)
                except Exception:
                    self._log_exception(analysis_section, f"Could not convert report for analysis #{analysis_id}")

                try:
                    self._create_process_tree(analysis_section, messages_section, report)
                except Exception:
                    self._log_exception(analysis_section, f"Could not create process tree for analysis #{analysis_id}")

                if self.vmray_debug_add_json:
                    report_json = ResultJSONSection("Summary JSON", auto_collapse=True)
                    report_json.set_json(report)
                    analysis_section.add_subsection(report_json)

    def _log_exception(self, section: ResultTextSection, message: str) -> None:
        self.log.exception(message)
        section.add_line(f"EXCEPTION: {message}")

    def _convert_report_to_result(
        self,
        analysis_section: ResultTextSection,
        messages_section: ResultTextSection,
        report: Dict,
    ) -> None:
        if "remarks" in report:
            remarks = report["remarks"]
            for info in remarks.get("infos", []):
                messages_section.add_line(f"INFO: {info['message']}")
            for warning in remarks.get("warnings", []):
                analysis_section.add_line(f"WARNING: {warning['message']}")
            for error in remarks.get("errors", []):
                analysis_section.add_line(f"ERROR: {error['message']}")

        if "mitre_attack" in report:
            mitre_attack = report["mitre_attack"]
            if "v4" in mitre_attack:
                techniques = mitre_attack["v4"].get("techniques", {}).values()
                for technique in techniques:
                    analysis_section.heuristic.add_attack_id(technique["technique_id"])

        if "anti_virus" in report:
            for av_engine in report["anti_virus"].values():
                av_matches = av_engine.get("matches", {}).values()
                for av in av_matches:
                    section = messages_section if av["verdict"] == "clean" else analysis_section
                    section.add_tag("av.virus_name", av["threat"]["name"])

        if "vti" in report:
            vti_matches = report["vti"].get("matches", {}).values()
            for vti in vti_matches:
                section = messages_section if vti["analysis_score"] < 2 else analysis_section
                section.add_tag("dynamic.signature.category", vti["category_desc"])
                section.add_tag("dynamic.signature.name", vti["operation_desc"])
                for vti_threat in vti.get("threat_names", []):
                    section.add_tag("dynamic.signature.family", vti_threat)

        if "yara" in report:
            yara_matches = report["yara"].get("matches", {}).values()
            for yara_rule in yara_matches:
                analysis_section.heuristic.add_signature_id(yara_rule["rule_name"])

        if "filenames" in report:
            for filename in report["filenames"].values():
                if filename["is_artifact"] or filename["is_ioc"]:
                    for original_filename in filename.get("original_filenames", []):
                        section = messages_section if filename["verdict"] == "clean" else analysis_section
                        section.add_tag("file.name.extracted", original_filename["filename"])

        if "emails" in report:
            for email in report["emails"].values():
                if email["is_artifact"] or email["is_ioc"]:
                    section = messages_section if email["verdict"] == "clean" else analysis_section
                    section.add_tag("network.email.subject", email["subject"])

        if "email_addresses" in report:
            for email_address in report["email_addresses"].values():
                if email_address["is_artifact"] or email_address["is_ioc"]:
                    section = messages_section if email_address["verdict"] == "clean" else analysis_section
                    section.add_tag("network.email.address", email_address["email_address"])

        if "domains" in report:
            for domain in report["domains"].values():
                if domain["is_artifact"] or domain["is_ioc"]:
                    section = messages_section if domain["verdict"] == "clean" else analysis_section
                    section.add_tag("network.dynamic.domain", domain["domain"])

        if "ip_addresses" in report:
            for ip_address in report["ip_addresses"].values():
                if ip_address["is_artifact"] or ip_address["is_ioc"]:
                    section = messages_section if ip_address["verdict"] == "clean" else analysis_section
                    section.add_tag("network.dynamic.ip", ip_address["ip_address"])

        if "urls" in report:
            for url in report["urls"].values():
                if url["is_artifact"] or url["is_ioc"]:
                    section = messages_section if url["verdict"] == "clean" else analysis_section
                    section.add_tag("network.dynamic.uri", url["url"])

        if "mutexes" in report:
            for mutex in report["mutexes"].values():
                if mutex["is_artifact"] or mutex["is_ioc"]:
                    section = messages_section if mutex["verdict"] == "clean" else analysis_section
                    section.add_tag("dynamic.mutex", mutex["name"])

        if "registry_records" in report:
            for registry_record in report["registry_records"].values():
                if registry_record["is_artifact"] or registry_record["is_ioc"]:
                    section = messages_section if registry_record["verdict"] == "clean" else analysis_section
                    section.add_tag("dynamic.registry_key", registry_record["reg_key_name"])

    def _create_process_tree(
        self,
        analysis_section: ResultTextSection,
        messages_section: ResultTextSection,
        report: Dict,
    ) -> None:
        if "processes" not in report:
            messages_section.add_line("INFO: No process information available in the report")
            return

        def build_signatures(proc):
            if "verdict" in proc:
                verdict = proc["verdict"]
                if verdict == "malicious":
                    score = 1000
                elif verdict == "suspicious":
                    score = 500
                else:
                    score = 0
                for threat_name in proc.get("threat_names", []):
                    yield (threat_name, score)

        def build_process_tree(processes, origin_monitor_id=0):
            for proc in processes:
                if proc["origin_monitor_id"] == origin_monitor_id:
                    yield {
                        "process_pid": proc["os_pid"],
                        "process_name": proc.get("image_name", os.path.basename(proc.get("filename", ""))),
                        "command_line": proc.get("cmd_line", ""),
                        "signatures": dict(build_signatures(proc)),
                        "children": list(build_process_tree(processes, proc["monitor_id"]))
                    }

        processes = report["processes"].values()
        process_tree_section = ResultSection(
            "Process Tree",
            body_format=BODY_FORMAT.PROCESS_TREE,
            body=json.dumps(list(build_process_tree(processes)))
        )
        analysis_section.add_subsection(process_tree_section)

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
        screenshot_text: str,
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
            return image_section.add_image(output_file.name, screenshot_name, screenshot_text)

    def _iter_screenshots(
        self,
        api: VMRayRESTAPI,
        analysis_id: int,
    ) -> Any:
        try:
            for screenshot in self._download(
                api,
                file_endpoint=f"/rest/analysis/{analysis_id}/archive/screenshots/index.log",
            ).readlines():
                screenshot_data = screenshot.decode().strip().split(" | ")
                yield timedelta(milliseconds=int(screenshot_data[0])), screenshot_data[-1]
        except VMRayRESTAPIError as e:
            if e.status_code == 404:
                return
            raise
