import enum
import ipaddress
from datetime import timedelta
from dateutil import parser
from typing import Any, Dict

from assemblyline_v4_service.common.result import (
    ResultSandboxSection,
    SandboxAnalysisMetadata,
    SandboxMachineMetadata,
    SandboxAttackItem,
    SandboxNetflowItem,
    SandboxNetworkDNS,
    SandboxNetworkHTTP,
    SandboxProcessItem,
    SandboxSignatureItem,
)

class VMRayIntegrityLevel(enum.IntEnum):
    SECURITY_MANDATORY_UNTRUSTED_RID = 0
    SECURITY_MANDATORY_LOW_RID = 1
    SECURITY_MANDATORY_MEDIUM_RID = 2
    SECURITY_MANDATORY_MEDIUM_PLUS_RID = 3
    SECURITY_MANDATORY_HIGH_RID = 4
    SECURITY_MANDATORY_SYSTEM_RID = 5
    SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 6
    SECURITY_MANDATORY_SECURE_PROCESS_RID = 7

class VMRayResult(object):
    def __init__(self, analysis, report, default_classification):
        self.analysis = analysis
        self.report = report
        self.default_classification = default_classification

    def _follow_ref(
        self,
        ref: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not ref:
            return {}
        value = self.report
        for key in ref["path"]:
            value = value[key]
        return value

    def set_analysis_information(self, sandbox_section: ResultSandboxSection):
        analysis_metadata = self.report.get("analysis_metadata", {})
        virtual_machine = self.report.get("virtual_machine", {})
        machine_metadata = SandboxMachineMetadata(
            ip=virtual_machine.get("ip_address"),
            hypervisor=self.analysis.get("analysis_vmhost_name"),
            hostname=virtual_machine.get("computer_name"),
            platform=virtual_machine.get("operating_system_type"),
            version=virtual_machine.get("kernel_version"),
            architecture=virtual_machine.get("architecture"),
        )
        start_time = parser.isoparse(analysis_metadata.get("creation_time"))
        run_time = timedelta(seconds=analysis_metadata.get("analysis_duration", 0))
        analysis_metadata = SandboxAnalysisMetadata(
            task_id=analysis_metadata.get("analysis_id"),
            start_time=start_time.isoformat(),
            end_time=(start_time + run_time).isoformat(),
            routing=None, # TODO: Add routing information if available
            window_size=None, # TODO: Add window size information if available
            machine_metadata=machine_metadata,
        )
        sandbox_section.set_analysis_information(
            sandbox_name=self.analysis.get("analysis_analyzer_name"),
            sandbox_version=self.analysis.get("analysis_analyzer_version"),
            analysis_metadata=analysis_metadata,
        )

    def add_processes(self, sandbox_section: ResultSandboxSection):
        analysis_metadata = self.report.get("analysis_metadata", {})
        start_time = parser.isoparse(analysis_metadata.get("creation_time"))
        processes = self.report.get("processes", {})
        for process in processes.values():
            lowest_timedelta = min(map(lambda region: region.get("timedelta"), process.get("regions", {}).values()))
            process_item = SandboxProcessItem(
                image=process.get("filename"),
                start_time=(start_time + timedelta(milliseconds=lowest_timedelta)).isoformat(),
                sources=[process.get("monitor_reason")],
                ppid=self._follow_ref(process.get("ref_parent_process")).get("os_pid"),
                pid=process.get("os_pid"),
                command_line=process.get("cmd_line"),
                end_time=None, # TODO: Add end time if available
                integrity_level=VMRayIntegrityLevel(process.get("integrity_level")).name,
                image_hash=self._follow_ref(process.get("ref_cmd_line_file")).get("hash_values", {}).get("sha256"),
                original_file_name=process.get("image_name"),
                safelisted=None, # TODO: Add safelisted information if available
                file_count=None, # TODO: Add file count information if available
                registry_count=None, # TODO: Add registry count information if available
            )
            sandbox_section.add_process(process_item)

    def add_netflows(self, sandbox_section: ResultSandboxSection):
        network = self.report.get("network", {})
        for protocol in ("tcp", "udp"):
            streams = network.get(protocol, {}).values()
            for stream in streams:
                connection = stream.get("connection", {})
                netflow_item = SandboxNetflowItem(
                    destination_ip=self._follow_ref(connection.get("ref_remote_ip_address")).get("ip_address"),
                    destination_port=connection.get("remote_port"),
                    transport_layer_protocol=protocol,
                    direction="outbound" if connection.get("is_client") else "inbound",
                    process=None, # TODO: Add process information if available
                    sources=[], # TODO: Add sources information if available
                    source_ip=self._follow_ref(connection.get("ref_local_ip_address")).get("ip_address"),
                    source_port=connection.get("local_port"),
                    time_observed=None, # TODO: Add time observed information if available
                    connection_type=None, # TODO: Add connection type information if available
                )
                for upper_protocol in stream.get("ref_upper_protocol_entries", []):
                    upper_stream = self._follow_ref(upper_protocol)
                    upper_type = upper_stream.get("_type")
                    if upper_type == "network.dns.query":
                        resolved_ips = []
                        resolved_domains = []
                        for answer in upper_stream.get("answers", []):
                            data = answer.get("data")
                            try:
                                ipaddress.ip_address(data)
                                resolved_ips.append(data)
                            except ValueError:
                                resolved_domains.append(data)
                        netflow_item.dns_details = SandboxNetworkDNS(
                            domain=upper_stream.get("name", ""),
                            lookup_type=upper_stream.get("type", "").upper(),
                            resolved_ips=resolved_ips,
                            resolved_domains=resolved_domains,
                        )
                    elif upper_type == "network.http.request":
                        response = upper_stream.get("responses", []).popdefault({})
                        request_headers = {h.get("name"): h.get("value") for h in upper_stream.get("headers", [])}
                        response_headers = {h.get("name"): h.get("value") for h in response.get("headers", [])}
                        netflow_item.http_details = SandboxNetworkHTTP(
                            request_uri=upper_stream.get("url", ""),
                            request_method=upper_stream.get("method"),
                            request_headers=request_headers,
                            response_headers=response_headers,
                            request_body=None, # TODO: Add request body information if available
                            response_status_code=response.get("status_code"),
                            response_body=None, # TODO: Add response body information if available
                            response_content_fileinfo=None, # TODO: Add response content file information
                            response_content_mimetype=None, # TODO: Add response content mimetype information
                        )
                sandbox_section.add_network_connection(netflow_item)

    def add_vti_signatures(self, sandbox_section: ResultSandboxSection):
        vti_pids = {}
        processes = self.report.get("processes", {}).values()
        for process in processes:
            for vti_match_ref in process.get("ref_vti_matches", []):
                vti_match_key = vti_match_ref.get("path")[-1]
                os_pid = process.get("os_pid")
                if vti_match_key in vti_pids:
                    vti_pids[vti_match_key].append(os_pid)
                else:
                    vti_pids[vti_match_key] = [os_pid]
        vti_matches = self.report.get("vti", {}).get("matches", {}).items()
        for vti_match_key, vti_match in vti_matches:
            attacks = []
            for mitre_ref in vti_match.get("ref_mitre_attack_techniques", []):
                mitre_item = self._follow_ref(mitre_ref)
                if mitre_item.get("_type") == "mitre_attack.v4.technique":
                    attack_item = SandboxAttackItem(
                        attack_id=mitre_item.get("technique_id", ""),
                        pattern=mitre_item.get("description", ""),
                        categories=mitre_item.get("tactics", []),
                    )
                    attacks.append(attack_item)
            vti_item = SandboxSignatureItem(
                name=vti_match.get("operation_desc"),
                type="VTI", # pyright: ignore[reportArgumentType]
                classification=self.default_classification,
                sources=[vti_match.get("technique_type")],
                attacks=attacks,
                actors=vti_match.get("classifications", None),
                malware_families=vti_match.get("threat_names", None),
                description=vti_match.get("technique_desc"),
                pid=vti_pids.get(vti_match_key),
                score=max(vti_match.get("analysis_score", 0), 0) * 250,
            )
            sandbox_section.add_signature(vti_item)

    def add_yara_signatures(self, sandbox_section: ResultSandboxSection):
        yara_matches = self.report.get("yara", {}).get("matches", {}).values()
        for yara_match in yara_matches:
            yara_item = SandboxSignatureItem(
                name=yara_match.get("rule_name"),
                type="YARA", # pyright: ignore[reportArgumentType]
                classification=self.default_classification,
                sources=[yara_match.get("ruleset_name")],
                attacks=None, # TODO: Add attacks information if available
                actors=yara_match.get("classifications", None),
                malware_families=yara_match.get("threat_names", None),
                description=yara_match.get("description"),
                pid=None, # TODO: Add pid information if available
                score=max(yara_match.get("vti_rule_score", 0), 0) * 250,
            )
            sandbox_section.add_signature(yara_item)

    def add_av_signatures(self, sandbox_section: ResultSandboxSection):
        anti_virus = self.report.get("anti_virus", {}).values()
        for av_engine in anti_virus:
            av_matches = av_engine.get("matches", {}).values()
            for av_match in av_matches:
                av_verdict = av_match.get("verdict").lower()
                if av_verdict == "malicious":
                    av_score = 1000
                elif av_verdict == "suspicious":
                    av_score = 500
                elif av_verdict == "clean":
                    av_score = 0
                else:
                    av_score = None
                av_item = SandboxSignatureItem(
                    name=av_match.get("threat", {}).get("classification"),
                    type="AV", # pyright: ignore[reportArgumentType]
                    classification=self.default_classification,
                    sources=[av_engine.get("engine", {}).get("engine_version")],
                    attacks=None, # TODO: Add attacks information if available
                    actors=None, # TODO: Add actors information if available
                    malware_families=[av_match.get("threat", {}).get("name", "n/a")],
                    description=av_match.get("verdict_reason_description"),
                    pid=None, # TODO: Add pid information if available
                    score=av_score,
                )
                sandbox_section.add_signature(av_item)

    def populate_sandbox_section(self, sandbox_section: ResultSandboxSection):
        self.set_analysis_information(sandbox_section)
        self.add_processes(sandbox_section)
        self.add_netflows(sandbox_section)
        self.add_vti_signatures(sandbox_section)
        self.add_yara_signatures(sandbox_section)
        self.add_av_signatures(sandbox_section)
