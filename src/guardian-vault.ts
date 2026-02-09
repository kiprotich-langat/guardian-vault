/**
 * Guardian Vault - Core System
 * 
 * Main orchestrator that integrates:
 * - Prompt Analyzer
 * - Execution Monitor
 * - Walrus Audit Logger
 * - Seal Credential Vault
 * - Recovery Engine
 */

import { PromptAnalyzer, PromptContext, AnalysisResult } from './analyzer/prompt-analyzer';
import { ExecutionMonitor, ExecutionContext, ExecutionResult } from './analyzer/execution-monitor';
import { WalrusClient, WalrusConfig, AuditLogEntry, WALRUS_TESTNET_CONFIG } from './storage/walrus-client';
import { SealVault, SealConfig } from './storage/seal-vault';

export interface GuardianVaultConfig {
  suiPrivateKey: string;
  suiWalletAddress: string;
  anthropicApiKey?: string;
  walrusConfig?: Partial<WalrusConfig>;
  sealConfig?: SealConfig;
  enableDashboard?: boolean;
  dashboardPort?: number;
  riskThresholds?: {
    block: number;
    quarantine: number;
  };
}

export interface SecurityEvent {
  id: string;
  timestamp: number;
  eventType: 'prompt_analyzed' | 'command_monitored' | 'file_access' | 'network_request' | 'credential_accessed' | 'threat_blocked';
  agentId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'allowed' | 'blocked' | 'quarantined';
  details: any;
}

export class GuardianVault {
  private config: GuardianVaultConfig;
  private promptAnalyzer: PromptAnalyzer;
  private executionMonitor: ExecutionMonitor;
  private walrusClient: WalrusClient;
  private sealVault: SealVault;
  private events: SecurityEvent[] = [];
  private isInitialized: boolean = false;

  constructor(config: GuardianVaultConfig) {
    this.config = config;
    
    // Initialize components
    this.promptAnalyzer = new PromptAnalyzer(config.anthropicApiKey);
    this.executionMonitor = new ExecutionMonitor();
    this.sealVault = new SealVault(config.sealConfig);
    
    // Configure Walrus client
    const walrusConfig: WalrusConfig = {
      ...WALRUS_TESTNET_CONFIG,
      ...config.walrusConfig,
      walletPrivateKey: config.suiPrivateKey,
    } as WalrusConfig;
    
    this.walrusClient = new WalrusClient(walrusConfig);
  }

  /**
   * Initialize Guardian Vault
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      console.log('[GuardianVault] Already initialized');
      return;
    }

    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    Guardian Vault v1.0                        ║');
    console.log('║          Autonomous Security for OpenClaw Agents              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');

    console.log('[GuardianVault] Initializing components...');

    try {
      // Initialize Walrus client
      await this.walrusClient.initialize();
      console.log('✓ Walrus client initialized');

      // Initialize Seal vault
      console.log('✓ Seal vault initialized');

      // Load default credentials if provided
      if (this.config.anthropicApiKey) {
        await this.sealVault.storeCredential(
          'anthropic_api_key',
          this.config.anthropicApiKey,
          { agentId: 'system' }
        );
        console.log('✓ Anthropic API key stored securely');
      }

      this.isInitialized = true;
      console.log('\n[GuardianVault] ✓ Ready to protect agents!\n');
    } catch (error) {
      console.error('[GuardianVault] Initialization failed:', error);
      throw error;
    }
  }

  /**
   * Analyze a prompt before it reaches OpenClaw
   */
  async analyzePrompt(context: PromptContext): Promise<AnalysisResult> {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    console.log(`\n[GuardianVault] Analyzing prompt from ${context.source}...`);

    const result = await this.promptAnalyzer.analyze(context);

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'prompt_analyzed',
      agentId: context.agentId,
      severity: this.getSeverity(result.riskScore),
      action: result.action === 'allow' ? 'allowed' : result.action === 'block' ? 'blocked' : 'quarantined',
      details: {
        source: context.source,
        riskScore: result.riskScore,
        threatSignatures: result.threatSignatures,
        reason: result.reason
      }
    });

    // If blocked, log to console
    if (result.action === 'block') {
      console.log(`\n⚠️  THREAT BLOCKED`);
      console.log(`Risk Score: ${result.riskScore}/100`);
      console.log(`Reason: ${result.reason}`);
      console.log(`Threats: ${result.threatSignatures.join(', ')}\n`);
    } else if (result.action === 'quarantine') {
      console.log(`\n⚠️  QUARANTINED FOR REVIEW`);
      console.log(`Risk Score: ${result.riskScore}/100`);
      console.log(`Reason: ${result.reason}\n`);
    } else {
      console.log(`✓ Prompt allowed (Risk: ${result.riskScore}/100)`);
    }

    return result;
  }

  /**
   * Monitor command execution
   */
  monitorCommand(command: string, agentId: string): ExecutionResult {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    const context: ExecutionContext = {
      type: 'shell_command',
      command,
      agentId,
      timestamp: Date.now()
    };

    const result = this.executionMonitor.monitorCommand(context);

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'command_monitored',
      agentId,
      severity: this.getSeverity(result.riskScore),
      action: result.allowed ? 'allowed' : 'blocked',
      details: {
        command,
        riskScore: result.riskScore,
        violations: result.violations,
        reason: result.reason
      }
    });

    if (!result.allowed) {
      console.log(`\n⚠️  COMMAND BLOCKED`);
      console.log(`Command: ${command}`);
      console.log(`Risk Score: ${result.riskScore}/100`);
      console.log(`Violations: ${result.violations.join(', ')}\n`);
    }

    return result;
  }

  /**
   * Monitor file access
   */
  monitorFileAccess(filepath: string, operation: 'read' | 'write', agentId: string): ExecutionResult {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    const context: ExecutionContext = {
      type: operation === 'read' ? 'file_read' : 'file_write',
      filepath,
      agentId,
      timestamp: Date.now()
    };

    const result = this.executionMonitor.monitorFileAccess(context);

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'file_access',
      agentId,
      severity: this.getSeverity(result.riskScore),
      action: result.allowed ? 'allowed' : 'blocked',
      details: {
        filepath,
        operation,
        riskScore: result.riskScore,
        violations: result.violations,
        reason: result.reason
      }
    });

    if (!result.allowed) {
      console.log(`\n⚠️  FILE ACCESS BLOCKED`);
      console.log(`File: ${filepath}`);
      console.log(`Operation: ${operation}`);
      console.log(`Risk Score: ${result.riskScore}/100\n`);
    }

    return result;
  }

  /**
   * Monitor network request
   */
  monitorNetworkRequest(url: string, agentId: string): ExecutionResult {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    const context: ExecutionContext = {
      type: 'network_request',
      url,
      agentId,
      timestamp: Date.now()
    };

    const result = this.executionMonitor.monitorNetworkRequest(context);

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'network_request',
      agentId,
      severity: this.getSeverity(result.riskScore),
      action: result.allowed ? 'allowed' : 'blocked',
      details: {
        url,
        riskScore: result.riskScore,
        violations: result.violations,
        reason: result.reason
      }
    });

    if (!result.allowed) {
      console.log(`\n⚠️  NETWORK REQUEST BLOCKED`);
      console.log(`URL: ${url}`);
      console.log(`Risk Score: ${result.riskScore}/100\n`);
    }

    return result;
  }

  /**
   * Store a credential securely
   */
  async storeCredential(name: string, value: string, agentId: string): Promise<string> {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    const credential = await this.sealVault.storeCredential(name, value, {
      agentId,
      rotationSchedule: 90 // 90 days default
    });

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'credential_accessed',
      agentId,
      severity: 'low',
      action: 'allowed',
      details: {
        operation: 'store',
        credentialName: name
      }
    });

    console.log(`✓ Credential stored: ${name}`);
    return credential.id;
  }

  /**
   * Retrieve a credential
   */
  async retrieveCredential(nameOrId: string, agentId: string): Promise<string | null> {
    if (!this.isInitialized) {
      throw new Error('GuardianVault not initialized. Call initialize() first.');
    }

    // Try by ID first, then by name
    let value = await this.sealVault.retrieveCredential(nameOrId, agentId);
    if (!value) {
      value = await this.sealVault.retrieveCredentialByName(nameOrId, agentId);
    }

    // Log to Walrus
    this.logSecurityEvent({
      eventType: 'credential_accessed',
      agentId,
      severity: 'medium',
      action: value ? 'allowed' : 'blocked',
      details: {
        operation: 'retrieve',
        credentialNameOrId: nameOrId,
        success: !!value
      }
    });

    return value;
  }

  /**
   * Log security event to Walrus
   */
  private logSecurityEvent(event: Omit<SecurityEvent, 'id' | 'timestamp'>): void {
    const securityEvent: SecurityEvent = {
      id: this.generateEventId(),
      timestamp: Date.now(),
      ...event
    };

    // Store in memory
    this.events.push(securityEvent);

    // Send to Walrus
    const auditLogEntry: Omit<AuditLogEntry, 'hash'> = {
      timestamp: securityEvent.timestamp,
      eventType: securityEvent.eventType,
      agentId: securityEvent.agentId,
      details: {
        ...securityEvent.details,
        action: securityEvent.action
      }
    };

    this.walrusClient.addAuditLog(auditLogEntry);
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Get severity level from risk score
   */
  private getSeverity(riskScore: number): 'low' | 'medium' | 'high' | 'critical' {
    if (riskScore >= 85) return 'critical';
    if (riskScore >= 70) return 'high';
    if (riskScore >= 50) return 'medium';
    return 'low';
  }

  /**
   * Get recent security events
   */
  getRecentEvents(limit: number = 10): SecurityEvent[] {
    return this.events.slice(-limit);
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    totalEvents: number;
    threatsBlocked: number;
    itemsQuarantined: number;
    credentialsStored: number;
    walrusStats: any;
    vaultStats: any;
  } {
    const threatsBlocked = this.events.filter(e => e.action === 'blocked').length;
    const itemsQuarantined = this.events.filter(e => e.action === 'quarantined').length;

    return {
      totalEvents: this.events.length,
      threatsBlocked,
      itemsQuarantined,
      credentialsStored: this.sealVault.listCredentials().length,
      walrusStats: this.walrusClient.getStatistics(),
      vaultStats: this.sealVault.getStatistics()
    };
  }

  /**
   * Flush audit logs to Walrus immediately
   */
  async flushAuditLogs(): Promise<void> {
    await this.walrusClient.flushBatch();
    console.log('✓ Audit logs flushed to Walrus');
  }

  /**
   * Shutdown Guardian Vault gracefully
   */
  async shutdown(): Promise<void> {
    console.log('\n[GuardianVault] Shutting down...');
    
    // Flush remaining logs
    await this.walrusClient.shutdown();
    
    console.log('[GuardianVault] Shutdown complete');
  }
}

// Export all types
export type { PromptContext, AnalysisResult } from './analyzer/prompt-analyzer';
export type { ExecutionContext, ExecutionResult } from './analyzer/execution-monitor';
export type { WalrusConfig, AuditLogEntry, AuditLogBatch, SnapshotMetadata } from './storage/walrus-client';
export type { SealConfig, EncryptedCredential, CredentialMetadata } from './storage/seal-vault';
