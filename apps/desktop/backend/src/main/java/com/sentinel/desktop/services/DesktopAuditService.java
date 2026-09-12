package com.sentinel.desktop.services;

import com.sentinel.desktop.entities.*;
import com.sentinel.desktop.repositories.ProjectRepository;
import com.sentinel.desktop.repositories.ScanRepository;
import com.sentinel.desktop.repositories.VulnerabilityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Service
public class DesktopAuditService {

    private static final Logger logger = LoggerFactory.getLogger(DesktopAuditService.class);

    private final ScanRepository scanRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ProjectRepository projectRepository;
    private final RestTemplate restTemplate;

    @Value("${python.backend.url:http://localhost:8000}")
    private String pythonBackendUrl;

    public DesktopAuditService(
            ScanRepository scanRepository,
            VulnerabilityRepository vulnerabilityRepository,
            ProjectRepository projectRepository) {
        this.scanRepository = scanRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.projectRepository = projectRepository;

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(5000);
        requestFactory.setReadTimeout(120000); // 2 min timeout for AI scan
        this.restTemplate = new RestTemplate(requestFactory);
    }

    public Scan startAudit(String sentinelUserId, String projectId) {
        Optional<Project> projectOpt = projectRepository.findBySentinelUserIdAndId(sentinelUserId, projectId);
        if (projectOpt.isEmpty()) {
            throw new IllegalArgumentException("Project not found: " + projectId);
        }

        Project project = projectOpt.get();

        Scan scan = Scan.builder()
                .id(UUID.randomUUID().toString())
                .project(project)
                .sentinelUserId(sentinelUserId)
                .status(ScanStatus.RUNNING)
                .startedAt(Instant.now())
                .createdAt(Instant.now())
                .build();

        scan = scanRepository.save(scan);

        final Scan activeScan = scan;

        // Execute scan asynchronously in background thread so API call returns immediately
        CompletableFuture.runAsync(() -> executePythonAudit(activeScan, project));

        return scan;
    }

    private void executePythonAudit(Scan scan, Project project) {
        try {
            String repoPathOrUrl = project.getLocalPath();
            if (repoPathOrUrl == null || repoPathOrUrl.isBlank()) {
                repoPathOrUrl = project.getHtmlUrl();
            }
            if (repoPathOrUrl == null || repoPathOrUrl.isBlank()) {
                repoPathOrUrl = "https://github.com/" + project.getRepositoryFullName();
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> requestPayload = Map.of(
                    "repo_url", repoPathOrUrl,
                    "branch", project.getDefaultBranch() != null ? project.getDefaultBranch() : "main"
            );

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestPayload, headers);
            String url = pythonBackendUrl + "/api/v1/audit/scan";

            logger.info("Triggering Python audit engine at {} for project {}", url, project.getRepositoryName());
            ResponseEntity<Map> response = restTemplate.postForEntity(url, entity, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map body = response.getBody();
                List<?> vulns = (List<?>) body.get("verified_vulnerabilities");

                if (vulns != null) {
                    for (Object obj : vulns) {
                        if (obj instanceof Map item) {
                            saveVulnerability(scan, item);
                        }
                    }
                }

                scan.setStatus(ScanStatus.COMPLETED);
                scan.setCompletedAt(Instant.now());
                scanRepository.save(scan);
                logger.info("Audit successfully completed for scan {}", scan.getId());
            } else {
                scan.setStatus(ScanStatus.FAILED);
                scan.setCompletedAt(Instant.now());
                scanRepository.save(scan);
                logger.error("Python audit returned error status: {}", response.getStatusCode());
            }
        } catch (Exception e) {
            logger.error("Error calling Python audit engine for scan {}", scan.getId(), e);
            scan.setStatus(ScanStatus.FAILED);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
        }
    }

    private void saveVulnerability(Scan scan, Map item) {
        try {
            Object titleVal = item.get("title");
            String title = titleVal != null ? String.valueOf(titleVal) : "Security Finding";

            Object sevVal = item.get("severity");
            String rawSeverity = sevVal != null ? String.valueOf(sevVal).toUpperCase() : "MEDIUM";

            Object fileVal = item.get("file_path");
            String filePath = fileVal != null ? String.valueOf(fileVal) : "unknown";

            Object cweVal = item.get("cwe_id");
            String cwe = cweVal != null ? String.valueOf(cweVal) : "CWE-20";

            Object toolVal = item.get("scanner_source");
            String tool = toolVal != null ? String.valueOf(toolVal) : "python-engine";

            Object rcVal = item.get("root_cause_analysis");
            String rootCause = rcVal != null ? String.valueOf(rcVal) : "";
            Object lineObj = item.get("line_number");
            Integer lineNumber = lineObj instanceof Number ? ((Number) lineObj).intValue() : 1;

            VulnerabilitySeverity severity;
            try {
                severity = VulnerabilitySeverity.valueOf(rawSeverity);
            } catch (Exception e) {
                severity = VulnerabilitySeverity.MEDIUM;
            }

            Vulnerability vulnerability = Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .scan(scan)
                    .sentinelUserId(scan.getSentinelUserId())
                    .title(title)
                    .severity(severity)
                    .description(rootCause)
                    .filePath(filePath)
                    .lineNumber(lineNumber)
                    .cwe(cwe)
                    .tool(tool)
                    .status(VulnerabilityStatus.OPEN)
                    .createdAt(Instant.now())
                    .build();

            vulnerabilityRepository.save(vulnerability);
        } catch (Exception e) {
            logger.error("Failed to parse and save vulnerability item", e);
        }
    }

    public Optional<Scan> getLatestScanForProject(String sentinelUserId, String projectId) {
        List<Scan> scans = scanRepository.findBySentinelUserIdAndProjectIdOrderByCreatedAtDesc(sentinelUserId, projectId);
        return scans.isEmpty() ? Optional.empty() : Optional.of(scans.get(0));
    }
}
