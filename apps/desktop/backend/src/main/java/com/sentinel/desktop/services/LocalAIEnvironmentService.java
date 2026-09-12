package com.sentinel.desktop.services;

import com.sentinel.desktop.dto.LocalAIStatusResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
public class LocalAIEnvironmentService {

    private final RestOperations restTemplate;

    @Value("${ollama.url:http://localhost:11434}")
    private String ollamaBaseUrl = "http://localhost:11434";

    public LocalAIEnvironmentService() {
        org.springframework.http.client.SimpleClientHttpRequestFactory requestFactory = new org.springframework.http.client.SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(5000);
        requestFactory.setReadTimeout(30000); // Allow up to 30 seconds for local Ollama LLM cold-start
        this.restTemplate = new RestTemplate(requestFactory);
    }

    // Constructor for testing with mock/custom RestOperations
    public LocalAIEnvironmentService(RestOperations restTemplate, String ollamaBaseUrl) {
        this.restTemplate = restTemplate;
        this.ollamaBaseUrl = ollamaBaseUrl;
    }

    public LocalAIStatusResponse checkEnvironment() {
        boolean ollamaInstalled = false;
        boolean ollamaRunning = false;
        boolean qwenInstalled = false;
        boolean qwenUsable = false;
        String qwenModel = "qwen2.5-coder:7b";
        String message;

        // CHECK 1: Query local Ollama API
        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(ollamaBaseUrl + "/api/tags", Map.class);
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                ollamaInstalled = true;
                ollamaRunning = true;

                // CHECK 2: Inspect returned models list
                List<?> models = (List<?>) response.getBody().get("models");
                if (models != null) {
                    for (Object obj : models) {
                        if (obj instanceof Map<?, ?> modelMap) {
                            String name = String.valueOf(modelMap.get("name"));
                            String modelField = String.valueOf(modelMap.get("model"));

                            if (matchesQwen25Coder7b(name) || matchesQwen25Coder7b(modelField)) {
                                qwenInstalled = true;

                                // Extract actual model name if available
                                if (name != null && !name.isBlank() && !name.equals("null")) {
                                    qwenModel = name;
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            ollamaRunning = false;
            // Check if ollama command is installed on system PATH even if service is down
            ollamaInstalled = checkOllamaBinaryInstalled();
        }

        // CHECK 3: Verify model usability with test prompt if running & installed
        if (ollamaRunning && qwenInstalled) {
            qwenUsable = testQwenModelUsability(qwenModel);
        }

        // READY LOGIC
        boolean ready = ollamaRunning && qwenInstalled && qwenUsable;

        if (ready) {
            message = "Local AI Engine is fully operational with " + qwenModel + ".";
        } else if (!ollamaInstalled && !ollamaRunning) {
            message = "Ollama is not installed on this system.";
        } else if (!ollamaRunning) {
            message = "Ollama is installed but is not currently running.";
        } else if (!qwenInstalled) {
            message = "Ollama is running, but required model qwen2.5-coder:7b is missing.";
        } else {
            message = "Qwen model is installed but Sentinel-X could not communicate with it.";
        }

        return new LocalAIStatusResponse(
                ollamaInstalled,
                ollamaRunning,
                qwenInstalled,
                qwenModel,
                qwenUsable,
                ready,
                message
        );
    }

    private boolean matchesQwen25Coder7b(String modelName) {
        if (modelName == null || modelName.isBlank() || modelName.equals("null")) {
            return false;
        }
        String lower = modelName.toLowerCase();
        // Accepts qwen2.5-coder:7b, qwen2.5-coder:7b-instruct, qwen2.5-coder (7B/7.6B variants)
        return lower.contains("qwen2.5-coder") || lower.contains("qwen2.5-coder:7b");
    }

    private boolean testQwenModelUsability(String modelName) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            Map<String, Object> requestPayload = Map.of(
                    "model", modelName,
                    "prompt", "Reply with exactly: SENTINEL_X_READY",
                    "stream", false
            );

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestPayload, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(ollamaBaseUrl + "/api/generate", entity, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                String responseText = String.valueOf(response.getBody().get("response"));
                return responseText != null && !responseText.isBlank();
            }
        } catch (Exception e) {
            // Model test invocation failed
            return false;
        }
        return false;
    }

    private boolean checkOllamaBinaryInstalled() {
        try {
            Process process = new ProcessBuilder("ollama", "--version").start();
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
