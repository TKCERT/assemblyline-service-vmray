import io
import enum
import json
import hashlib
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

class VMRayVerdict(enum.StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NOT_AVAILABLE = "not_available"
    CLEAN = "clean"

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
        if self.vmray_debug_sample_id and request.task.depth == 0:  # only use debug sample for top-level submissions
            submission_results = submission_kit.get_submissions_from_sample_id(self.vmray_debug_sample_id)[-1:]
        else:
            submission_params = {
                "shareable": self.vmray_service_shareable,  # if the hash of the sample will be shared with VirusTotal
                "reanalyze": self.vmray_service_reanalyze,  # if a duplicate submission will create analysis jobs
                "max_jobs":  self.vmray_service_max_jobs,   # the maximum number of analysis jobs to create
                "user_config": json.dumps({"timeout": int(self.service_attributes.timeout / 2)}),  # 50% job timeout
            }
            if request.file_type.startswith("uri/"):
                submission_results = submission_kit.submit_url(request.file_name, params=submission_params)
            else:
                submission_results = submission_kit.submit_file(Path(request.file_path), params=submission_params)

        self.log.info(f"Retrieved {len(submission_results)} submission result(s) from VMRay, processing analyses")

        api = submission_kit._api
        for submission_result in submission_results:
            sample_id = submission_result._sample_id

            self.log.info(f"Downloading PDF report for sample #{sample_id}")
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
                    self.log.info(f"Downloading PDF report for analysis #{analysis_id}")
                    self._download_pdf_report_as_supplementary(
                        request=request,
                        api=api,
                        report_endpoint=f"/rest/analysis/{analysis_id}/archive/report/report.pdf",
                        supplementary_filename=f"VMRay_Analysis_{analysis_id}.pdf",
                        supplementary_description=analysis_name,
                    )

                analysis_section = ResultTextSection(analysis_name)
                request.result.add_section(analysis_section)

                analysis_verdict = analysis.get("analysis_verdict", "unknown")
                reason_code = analysis.get("analysis_verdict_reason_code", analysis.get("analysis_result_code"))
                reason_text = analysis.get("analysis_verdict_reason_description", analysis.get("analysis_result_str"))
                if reason_code and reason_text:
                    analysis_section.add_line(f"VERDICT: {analysis_verdict} ({reason_code}: {reason_text})")
                else:
                    analysis_section.add_line(f"VERDICT: {analysis_verdict}")

                verdict_sections = {analysis_verdict: analysis_section}
                for verdict in VMRayVerdict:
                    if verdict not in verdict_sections:
                        verdict_sections[verdict] = ResultTextSection(f"Other {verdict} results")
                    if verdict == VMRayVerdict.MALICIOUS:
                        verdict_sections[verdict].set_heuristic(4)
                    elif verdict == VMRayVerdict.SUSPICIOUS:
                        verdict_sections[verdict].set_heuristic(3)
                    elif verdict == VMRayVerdict.CLEAN and analysis_verdict == VMRayVerdict.CLEAN:
                        verdict_sections[verdict].set_heuristic(0)

                if analysis["analysis_analyzer_name"] in ("vmray", "vmray_web"):
                    self.log.info(f"Downloading screenshots for analysis #{analysis_id}")
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
                    self.log.info(f"Retrieving summary report for analysis #{analysis_id}")
                    report = json.load(submission_kit._api.get_report(analysis_id))
                except Exception:
                    self._log_exception(analysis_section, f"Could not get summary report for analysis #{analysis_id}")
                    continue

                try:
                    self.log.info(f"Converting report to result for analysis #{analysis_id}")
                    self._convert_report_to_result(request, analysis_section, verdict_sections, report)
                except Exception:
                    self._log_exception(analysis_section, f"Could not convert report for analysis #{analysis_id}")

                try:
                    self.log.info(f"Creating process tree for analysis #{analysis_id}")
                    self._create_process_tree(analysis_section, report)
                except Exception:
                    self._log_exception(analysis_section, f"Could not create process tree for analysis #{analysis_id}")

                if "extracted_files" in report and "files" in report and "filenames" in report:
                    self.log.info(f"Extracting files for analysis #{analysis_id}")
                    for extracted_file in report["extracted_files"].values():
                        file_record = self._follow_ref(report, extracted_file["ref_file"])
                        if not file_record["is_ioc"] or "archive_path" not in file_record:
                            continue
                        filename = os.path.basename(file_record["archive_path"])
                        filename_records = [self._follow_ref(report, ref) for ref in extracted_file["ref_filenames"]]
                        filenames = [fn_r["filename"] for fn_r in filename_records if "filename" in fn_r]
                        filenames.append(filename)
                        categories = ", ".join(extracted_file.get("categories", ["n/a"]))
                        try:
                            self._download_extracted_file(
                                request=request,
                                api=api,
                                analysis_id=analysis_id,
                                archive_path=file_record["archive_path"],
                                extracted_file_name="; ".join(filenames),
                                extracted_file_text=f"Extraction categories: {categories}",
                                hash_values=file_record["hash_values"],
                            )
                        except Exception:
                            self._log_exception(analysis_section, f"Could not download extracted file '{filename}'")

                if self.vmray_debug_add_json:
                    report_json = ResultJSONSection("Summary JSON", auto_collapse=True)
                    report_json.set_json(report)
                    analysis_section.add_subsection(report_json)

                for verdict_section in verdict_sections.values():
                    if verdict_section is not analysis_section and verdict_section.tags:
                        analysis_section.add_subsection(verdict_section)

    def _log_exception(self, section: ResultTextSection, message: str) -> None:
        self.log.exception(message)
        section.add_line(f"EXCEPTION: {message}")

    def _convert_report_to_result(
        self,
        request: ServiceRequest,
        analysis_section: ResultTextSection,
        verdict_sections: Dict[VMRayVerdict, ResultTextSection],
        report: Dict,
    ) -> None:
        if "remarks" in report:
            remarks = report["remarks"]
            for error in remarks.get("errors", []):
                analysis_section.add_line(f"ERROR: {error['message']}")
            for warning in remarks.get("warnings", []):
                analysis_section.add_line(f"WARNING: {warning['message']}")
            for info in remarks.get("infos", []):
                analysis_section.add_line(f"INFO: {info['message']}")

        if "mitre_attack" in report:
            mitre_attack = report["mitre_attack"]
            if "v4" in mitre_attack:
                techniques = mitre_attack["v4"].get("techniques", {}).values()
                for technique in techniques:
                    analysis_score = 0
                    vti_matches = [self._follow_ref(report, ref) for ref in technique["ref_vti_matches"]]
                    for vti in vti_matches:
                        analysis_score = max(analysis_score, vti["analysis_score"])
                    if analysis_score >= 4:
                        section = verdict_sections[VMRayVerdict.MALICIOUS]
                    elif analysis_score >= 2:
                        section = verdict_sections[VMRayVerdict.SUSPICIOUS]
                    else:
                        section = verdict_sections[VMRayVerdict.CLEAN]
                    if section.heuristic:
                        section.heuristic.add_attack_id(technique["technique_id"])

        if "anti_virus" in report:
            for av_engine in report["anti_virus"].values():
                av_matches = av_engine.get("matches", {}).values()
                for av in av_matches:
                    section = verdict_sections[av["verdict"]]
                    section.add_tag("av.virus_name", av["threat"]["name"])

        if "vti" in report:
            vti_matches = report["vti"].get("matches", {}).values()
            for vti in vti_matches:
                if vti["analysis_score"] >= 4:
                    section = verdict_sections[VMRayVerdict.MALICIOUS]
                elif vti["analysis_score"] >= 2:
                    section = verdict_sections[VMRayVerdict.SUSPICIOUS]
                else:
                    section = verdict_sections[VMRayVerdict.CLEAN]
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
                        section = verdict_sections[filename["verdict"]]
                        section.add_tag("file.name.extracted", original_filename["filename"])

        if "emails" in report:
            for email in report["emails"].values():
                if email["is_artifact"] or email["is_ioc"]:
                    section = verdict_sections[email["verdict"]]
                    section.add_tag("network.email.subject", email["subject"])

        if "email_addresses" in report:
            for email_address in report["email_addresses"].values():
                if email_address["is_artifact"] or email_address["is_ioc"]:
                    section = verdict_sections[email_address["verdict"]]
                    section.add_tag("network.email.address", email_address["email_address"])

        if "domains" in report:
            for domain in report["domains"].values():
                if domain["is_artifact"] or domain["is_ioc"]:
                    section = verdict_sections[domain["verdict"]]
                    section.add_tag("network.dynamic.domain", domain["domain"])

        if "ip_addresses" in report:
            for ip_address in report["ip_addresses"].values():
                if ip_address["is_artifact"] or ip_address["is_ioc"]:
                    section = verdict_sections[ip_address["verdict"]]
                    section.add_tag("network.dynamic.ip", ip_address["ip_address"])

        if "urls" in report:
            for url in report["urls"].values():
                if url["is_artifact"] or url["is_ioc"]:
                    section = verdict_sections[url["verdict"]]
                    section.add_tag("network.dynamic.uri", url["url"])
                if url["is_ioc"]:
                    url_categories = ", ".join(url.get("categories", ["n/a"]))
                    url_operations = ", ".join(url.get("operations", ["n/a"]))
                    url_sources = ", ".join(url.get("sources", ["n/a"]))
                    url_text = f"Categories: {url_categories}; Operations: {url_operations}; Sources: {url_sources}"
                    request.add_extracted_uri(url_text, url["url"], allow_dynamic_recursion=False)

        if "mutexes" in report:
            for mutex in report["mutexes"].values():
                if mutex["is_artifact"] or mutex["is_ioc"]:
                    section = verdict_sections[mutex["verdict"]]
                    section.add_tag("dynamic.mutex", mutex["name"])

        if "registry_records" in report:
            for registry_record in report["registry_records"].values():
                if registry_record["is_artifact"] or registry_record["is_ioc"]:
                    section = verdict_sections[registry_record["verdict"]]
                    section.add_tag("dynamic.registry_key", registry_record["reg_key_name"])

    def _create_process_tree(
        self,
        analysis_section: ResultTextSection,
        report: Dict,
    ) -> None:
        if "processes" not in report:
            analysis_section.add_line("INFO: No process information available in the report.")
            return

        def build_signatures(proc):
            if "verdict" in proc:
                verdict = proc["verdict"]
                if verdict == VMRayVerdict.MALICIOUS:
                    score = 1000
                elif verdict == VMRayVerdict.SUSPICIOUS:
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

    def _follow_ref(
        self,
        report: Dict[str, Any],
        ref: Dict[str, Any],
    ) -> Any:
        value = report
        for key in ref["path"]:
            value = value[key]
        return value

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
            mode="w+b",
            suffix=".pdf",
            prefix="vmray_report_",
            dir=self.working_directory,
            delete=False,
        ) as output_file:
            shutil.copyfileobj(self._download(api, report_endpoint), output_file)
            return request.add_supplementary(output_file.name, supplementary_filename, supplementary_description)

    def _download_archive_file(
        self,
        api: VMRayRESTAPI,
        analysis_id: int,
        archive_path: str,
        hash_values: Dict[str, str] = {},
    ) -> str:
        archive_file = self._download(
            api,
            file_endpoint=f"/rest/analysis/{analysis_id}/archive/{archive_path}",
        )
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            suffix=os.path.basename(archive_path),
            prefix=f"vmray_{os.path.dirname(archive_path)}_",
            dir=self.working_directory,
            delete=False,
        ) as output_file:
            shutil.copyfileobj(archive_file, output_file)
            for key, value in hash_values.items():
                if key.lower() not in hashlib.algorithms_available:
                    continue
                output_file.seek(0)
                if hashlib.file_digest(output_file, key).hexdigest() != value: # type: ignore
                    raise ValueError(f"Hash mismatch for extracted file '{archive_path}' using {key}")
            return output_file.name

    def _download_extracted_file(
        self,
        request: ServiceRequest,
        api: VMRayRESTAPI,
        analysis_id: int,
        archive_path: str,
        extracted_file_name: str,
        extracted_file_text: str,
        hash_values: Dict[str, str] = {},
    ):
        output_filename = self._download_archive_file(
            api,
            analysis_id,
            archive_path,
            hash_values=hash_values,
        )
        return request.add_extracted(output_filename, extracted_file_name, extracted_file_text)

    def _download_screenshot_into_image_section(
        self,
        request: ServiceRequest,
        image_section: ResultImageSection,
        api: VMRayRESTAPI,
        analysis_id: int,
        screenshot_name: str,
        screenshot_text: str,
    ):
        output_filename = self._download_archive_file(
            api,
            analysis_id,
            f"screenshots/{screenshot_name}"
        )
        return image_section.add_image(output_filename, screenshot_name, screenshot_text)

    def _iter_screenshots(
        self,
        api: VMRayRESTAPI,
        analysis_id: int,
    ) -> Any:
        try:
            screenshot_index =self._download(
                api,
                file_endpoint=f"/rest/analysis/{analysis_id}/archive/screenshots/index.log",
            )
            screenshot_index.auto_close = False
            for screenshot_line in io.TextIOWrapper(screenshot_index, encoding='utf-8').readlines():
                screenshot_data = screenshot_line.strip().split(" | ")
                yield timedelta(milliseconds=int(screenshot_data[0])), screenshot_data[-1]
        except VMRayRESTAPIError as e:
            if e.status_code == 404:
                return
            raise
