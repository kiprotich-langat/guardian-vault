/**
 * Guardian Vault - Execution Monitor
 * 
 * Monitors and validates:
 * - Shell commands before execution
 * - File system operations
 * - Network requests
 * - Skill installations
 */

export interface ExecutionContext {
  type: 'shell_command' | 'file_read' | 'file_write' | 'network_request' | 'skill_install';
  command?: string;
  filepath?: string;
  url?: string;
  skillName?: string;
  agentId: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface ExecutionResult {
  allowed: boolean;
  riskScore: number;
  violations: string[];
  action: 'allow' | 'block' | 'quarantine';
  reason: string;
  sanitizedCommand?: string;
}

/**
 * High-risk shell commands
 */
const HIGH_RISK_COMMANDS = [
  { pattern: /rm\s+-rf\s+(\/|~|\*|\.)/i, severity: 100, name: 'destructive_delete' },
  { pattern: /sudo\s+/i, severity: 90, name: 'privilege_escalation' },
  { pattern: /chmod\s+777/i, severity: 85, name: 'permission_override' },
  { pattern: /curl.*\|.*sh/i, severity: 100, name: 'curl_pipe_shell' },
  { pattern: /wget.*\|.*bash/i, severity: 100, name: 'wget_pipe_bash' },
  { pattern: /eval\s*\(/i, severity: 90, name: 'eval_execution' },
  { pattern: /exec\s*\(/i, severity: 90, name: 'exec_call' },
  { pattern: /base64\s+-d.*\|/i, severity: 85, name: 'base64_decode_pipe' },
  { pattern: /nc\s+-l/i, severity: 95, name: 'netcat_listener' },
  { pattern: /netcat/i, severity: 95, name: 'netcat_usage' },
  { pattern: /dd\s+if=/i, severity: 90, name: 'disk_write' },
  { pattern: /mkfs/i, severity: 100, name: 'filesystem_format' },
  { pattern: /fdisk/i, severity: 95, name: 'partition_modify' },
  { pattern: /:\(\)\{:\|:&\};:/i, severity: 100, name: 'fork_bomb' },
  { pattern: /crontab\s+-e/i, severity: 90, name: 'cron_modification' },
  { pattern: /systemctl/i, severity: 85, name: 'system_service_control' },
];

/**
 * Sensitive file paths
 */
const SENSITIVE_PATHS = [
  { pattern: /\.ssh\/id_rsa/i, severity: 100, name: 'ssh_private_key' },
  { pattern: /\.ssh\/id_ed25519/i, severity: 100, name: 'ssh_private_key' },
  { pattern: /\.env/i, severity: 90, name: 'environment_file' },
  { pattern: /\.aws\/credentials/i, severity: 100, name: 'aws_credentials' },
  { pattern: /\.config\/gcloud/i, severity: 100, name: 'gcloud_credentials' },
  { pattern: /wallet\.json/i, severity: 100, name: 'wallet_file' },
  { pattern: /keystore/i, severity: 95, name: 'keystore_file' },
  { pattern: /password/i, severity: 80, name: 'password_file' },
  { pattern: /secret/i, severity: 80, name: 'secret_file' },
  { pattern: /token/i, severity: 80, name: 'token_file' },
  { pattern: /\.npmrc/i, severity: 85, name: 'npm_credentials' },
  { pattern: /\.gitconfig/i, severity: 75, name: 'git_config' },
  { pattern: /SOUL\.md/i, severity: 95, name: 'soul_file' },
];

/**
 * Suspicious network patterns
 */
const SUSPICIOUS_NETWORKS = [
  { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/i, severity: 70, name: 'raw_ip_connection' },
  { pattern: /\.onion/i, severity: 85, name: 'tor_network' },
  { pattern: /pastebin\.com/i, severity: 75, name: 'pastebin_exfil' },
  { pattern: /ngrok\.io/i, severity: 80, name: 'ngrok_tunnel' },
  { pattern: /localtunnel\.me/i, severity: 80, name: 'localtunnel' },
];

export class ExecutionMonitor {
  /**
   * Monitor shell command execution
   */
  monitorCommand(context: ExecutionContext): ExecutionResult {
    if (context.type !== 'shell_command' || !context.command) {
      return {
        allowed: true,
        riskScore: 0,
        violations: [],
        action: 'allow',
        reason: 'Not a shell command'
      };
    }

    const command = context.command;
    const violations: string[] = [];
    let maxSeverity = 0;

    // Check for high-risk commands
    for (const { pattern, severity, name } of HIGH_RISK_COMMANDS) {
      if (pattern.test(command)) {
        violations.push(name);
        maxSeverity = Math.max(maxSeverity, severity);
      }
    }

    // Check for command chaining with dangerous commands
    const hasChaining = /[;&|]{1,2}/.test(command);
    if (hasChaining && violations.length > 0) {
      maxSeverity = Math.min(100, maxSeverity + 10);
      violations.push('command_chaining');
    }

    // Check for output redirection to sensitive locations
    if (/>\s*\/etc\//.test(command)) {
      violations.push('system_file_write');
      maxSeverity = Math.max(maxSeverity, 90);
    }

    // Check for background execution
    if (/&\s*$/.test(command)) {
      violations.push('background_execution');
      maxSeverity = Math.max(maxSeverity, 60);
    }

    const riskScore = maxSeverity;
    const action = this.determineAction(riskScore);

    return {
      allowed: action === 'allow',
      riskScore,
      violations,
      action,
      reason: violations.length > 0
        ? `Detected ${violations.length} violation(s): ${violations.join(', ')}`
        : 'Command appears safe'
    };
  }

  /**
   * Monitor file system operations
   */
  monitorFileAccess(context: ExecutionContext): ExecutionResult {
    if (!context.filepath) {
      return {
        allowed: true,
        riskScore: 0,
        violations: [],
        action: 'allow',
        reason: 'No filepath provided'
      };
    }

    const filepath = context.filepath;
    const violations: string[] = [];
    let maxSeverity = 0;

    // Check for sensitive file access
    for (const { pattern, severity, name } of SENSITIVE_PATHS) {
      if (pattern.test(filepath)) {
        violations.push(name);
        maxSeverity = Math.max(maxSeverity, severity);
      }
    }

    // Additional checks for write operations
    if (context.type === 'file_write') {
      // Writing to system directories
      if (/^\/(etc|bin|usr\/bin|sbin|usr\/sbin|boot)\//.test(filepath)) {
        violations.push('system_directory_write');
        maxSeverity = Math.max(maxSeverity, 95);
      }

      // Writing to startup scripts
      if (/\/(rc\.local|profile|bashrc|zshrc)$/.test(filepath)) {
        violations.push('startup_script_modification');
        maxSeverity = Math.max(maxSeverity, 90);
      }
    }

    const riskScore = maxSeverity;
    const action = this.determineAction(riskScore);

    return {
      allowed: action === 'allow',
      riskScore,
      violations,
      action,
      reason: violations.length > 0
        ? `File access violation: ${violations.join(', ')}`
        : 'File access appears safe'
    };
  }

  /**
   * Monitor network requests
   */
  monitorNetworkRequest(context: ExecutionContext): ExecutionResult {
    if (context.type !== 'network_request' || !context.url) {
      return {
        allowed: true,
        riskScore: 0,
        violations: [],
        action: 'allow',
        reason: 'Not a network request'
      };
    }

    const url = context.url;
    const violations: string[] = [];
    let maxSeverity = 0;

    // Check for suspicious network patterns
    for (const { pattern, severity, name } of SUSPICIOUS_NETWORKS) {
      if (pattern.test(url)) {
        violations.push(name);
        maxSeverity = Math.max(maxSeverity, severity);
      }
    }

    // Check for non-HTTPS in sensitive contexts
    if (/^http:\/\//i.test(url) && !url.includes('localhost')) {
      violations.push('insecure_http');
      maxSeverity = Math.max(maxSeverity, 60);
    }

    // Check for data URLs (potential exfiltration)
    if (/^data:/i.test(url)) {
      violations.push('data_url');
      maxSeverity = Math.max(maxSeverity, 70);
    }

    const riskScore = maxSeverity;
    const action = this.determineAction(riskScore);

    return {
      allowed: action === 'allow',
      riskScore,
      violations,
      action,
      reason: violations.length > 0
        ? `Network request violation: ${violations.join(', ')}`
        : 'Network request appears safe'
    };
  }

  /**
   * Monitor skill installation
   */
  monitorSkillInstall(context: ExecutionContext): ExecutionResult {
    if (context.type !== 'skill_install' || !context.skillName) {
      return {
        allowed: true,
        riskScore: 0,
        violations: [],
        action: 'allow',
        reason: 'Not a skill installation'
      };
    }

    // TODO: Check against community-vetted skill registry
    // For now, allow all but log for review
    return {
      allowed: true,
      riskScore: 30, // Medium risk until verified
      violations: [],
      action: 'quarantine', // Requires manual review
      reason: 'Skill installation requires verification'
    };
  }

  /**
   * Sanitize a command by removing dangerous parts
   */
  sanitizeCommand(command: string): string {
    let sanitized = command;

    // Remove pipe to shell
    sanitized = sanitized.replace(/\|\s*(sh|bash|zsh|fish)/gi, '');

    // Remove command chaining
    sanitized = sanitized.replace(/[;&|]{2}/g, '');

    // Remove background execution
    sanitized = sanitized.replace(/&\s*$/g, '');

    return sanitized.trim();
  }

  /**
   * Determine action based on risk score
   */
  private determineAction(riskScore: number): 'allow' | 'block' | 'quarantine' {
    if (riskScore >= 85) return 'block';
    if (riskScore >= 60) return 'quarantine';
    return 'allow';
  }

  /**
   * Get statistics on monitored executions
   */
  getStatistics(): {
    totalMonitored: number;
    blocked: number;
    quarantined: number;
    allowed: number;
  } {
    // TODO: Implement statistics tracking
    return {
      totalMonitored: 0,
      blocked: 0,
      quarantined: 0,
      allowed: 0
    };
  }
}

// Export patterns for testing
export { HIGH_RISK_COMMANDS, SENSITIVE_PATHS, SUSPICIOUS_NETWORKS };