package com.sentinel.desktop.controllers;

import com.sentinel.desktop.entities.Scan;
import com.sentinel.desktop.entities.ScanStatus;
import com.sentinel.desktop.services.DesktopAuditService;
import com.sentinel.desktop.services.DesktopUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/projects")
public class LocalTestController {

    private final DesktopAuditService auditService;
    private final DesktopUserService userService;

    public LocalTestController(DesktopAuditService auditService, DesktopUserService userService) {
        this.auditService = auditService;
        this.userService = userService;
    }

    @PostMapping("/{projectId}/test/start")
    public ResponseEntity<?> startProjectTest(@PathVariable("projectId") String projectId) {
        String activeUserId = userService.getActiveSentinelUserId();
        try {
            Scan scan = auditService.startAudit(activeUserId, projectId);
            return ResponseEntity.ok(Map.of(
                    "id", scan.getId(),
                    "projectId", projectId,
                    "status", "RUNNING",
                    "currentStage", 1,
                    "message", "SentinelX Security Audit pipeline initialized."
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                    "message", e.getMessage()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "message", "Failed to start test machine: " + e.getMessage()
            ));
        }
    }

    @GetMapping("/{projectId}/test/status")
    public ResponseEntity<?> getProjectTestStatus(@PathVariable("projectId") String projectId) {
        String activeUserId = userService.getActiveSentinelUserId();
        Optional<Scan> latestScanOpt = auditService.getLatestScanForProject(activeUserId, projectId);

        if (latestScanOpt.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "id", "none",
                    "projectId", projectId,
                    "status", "WAITING",
                    "currentStage", 0,
                    "message", "No scan session recorded for project."
            ));
        }

        Scan scan = latestScanOpt.get();
        String frontendStatus = "WAITING";
        int stage = 0;

        if (scan.getStatus() == ScanStatus.RUNNING) {
            frontendStatus = "RUNNING";
            stage = 4; // Multi-agent scanning stage
        } else if (scan.getStatus() == ScanStatus.COMPLETED) {
            frontendStatus = "COMPLETED";
            stage = 10; // Final reporting stage
        } else if (scan.getStatus() == ScanStatus.FAILED) {
            frontendStatus = "FAILED";
            stage = 9;
        }

        return ResponseEntity.ok(Map.of(
                "id", scan.getId(),
                "projectId", projectId,
                "status", frontendStatus,
                "currentStage", stage,
                "message", "Scan status: " + scan.getStatus().name()
        ));
    }
}
