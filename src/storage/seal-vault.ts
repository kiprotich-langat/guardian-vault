/**
 * Guardian Vault - Seal Encryption Client
 * 
 * Handles encrypted credential storage using Sui's Seal protocol.
 * Credentials are encrypted before being stored on Walrus.
 */

import * as crypto from 'crypto';

export interface SealConfig {
  publicKey: string;
  privateKey: string;
}

export interface EncryptedCredential {
  id: string;
  name: string;
  encryptedValue: string;
  iv: string; // Initialization vector
  createdAt: number;
  lastAccessed?: number;
  walrusBlobId?: string;
  rotationSchedule?: number; // Days until rotation
}

export interface CredentialMetadata {
  id: string;
  name: string;
  createdAt: number;
  lastAccessed?: number;
  rotationSchedule?: number;
}

export class SealVault {
  private config: SealConfig;
  private credentials: Map<string, EncryptedCredential>;
  private accessLog: Array<{ credentialId: string; timestamp: number; agentId: string }>;
  
  constructor(config?: SealConfig) {
    // Generate keys if not provided
    this.config = config || this.generateKeys();
    this.credentials = new Map();
    this.accessLog = [];
  }

  /**
   * Generate encryption keys
   */
  private generateKeys(): SealConfig {
    // In production, use Seal's key generation
    // For now, generate local RSA keys as placeholder
    
    // Generate 32-byte key for AES-256
    const key = crypto.randomBytes(32).toString('hex');
    
    return {
      publicKey: key,
      privateKey: key // In real Seal, these would be different
    };
  }

  /**
   * Store a credential securely
   */
  async storeCredential(
    name: string,
    value: string,
    options: {
      rotationSchedule?: number;
      agentId: string;
    }
  ): Promise<EncryptedCredential> {
    const id = crypto.randomBytes(16).toString('hex');
    const iv = crypto.randomBytes(16);
    
    // Encrypt the credential using AES-256-CBC
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      Buffer.from(this.config.privateKey.substring(0, 32)),
      iv
    );
    
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const credential: EncryptedCredential = {
      id,
      name,
      encryptedValue: encrypted,
      iv: iv.toString('hex'),
      createdAt: Date.now(),
      rotationSchedule: options.rotationSchedule
    };
    
    this.credentials.set(id, credential);
    
    console.log(`[SealVault] Stored credential: ${name} (ID: ${id})`);
    
    return credential;
  }

  /**
   * Retrieve and decrypt a credential
   */
  async retrieveCredential(
    id: string,
    agentId: string
  ): Promise<string | null> {
    const credential = this.credentials.get(id);
    
    if (!credential) {
      console.error(`[SealVault] Credential not found: ${id}`);
      return null;
    }
    
    // Log access
    this.accessLog.push({
      credentialId: id,
      timestamp: Date.now(),
      agentId
    });
    
    // Update last accessed time
    credential.lastAccessed = Date.now();
    
    // Decrypt using AES-256-CBC
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(this.config.privateKey.substring(0, 32)),
      Buffer.from(credential.iv, 'hex')
    );
    
    let decrypted = decipher.update(credential.encryptedValue, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    console.log(`[SealVault] Retrieved credential: ${credential.name} by agent ${agentId}`);
    
    return decrypted;
  }

  /**
   * Retrieve credential by name
   */
  async retrieveCredentialByName(
    name: string,
    agentId: string
  ): Promise<string | null> {
    for (const [id, credential] of this.credentials.entries()) {
      if (credential.name === name) {
        return this.retrieveCredential(id, agentId);
      }
    }
    
    console.error(`[SealVault] Credential not found: ${name}`);
    return null;
  }

  /**
   * Rotate a credential (change its value)
   */
  async rotateCredential(
    id: string,
    newValue: string,
    agentId: string
  ): Promise<boolean> {
    const credential = this.credentials.get(id);
    
    if (!credential) {
      console.error(`[SealVault] Credential not found for rotation: ${id}`);
      return false;
    }
    
    // Store old credential for audit
    const oldCredential = { ...credential };
    
    // Encrypt new value with new IV
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      Buffer.from(this.config.privateKey.substring(0, 32)),
      iv
    );
    
    let encrypted = cipher.update(newValue, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Update credential
    credential.encryptedValue = encrypted;
    credential.iv = iv.toString('hex');
    credential.lastAccessed = Date.now();
    
    console.log(`[SealVault] Rotated credential: ${credential.name} (ID: ${id}) by agent ${agentId}`);
    
    return true;
  }

  /**
   * Delete a credential
   */
  async deleteCredential(id: string, agentId: string): Promise<boolean> {
    const credential = this.credentials.get(id);
    
    if (!credential) {
      return false;
    }
    
    this.credentials.delete(id);
    
    console.log(`[SealVault] Deleted credential: ${credential.name} (ID: ${id}) by agent ${agentId}`);
    
    return true;
  }

  /**
   * List all credentials (metadata only, not values)
   */
  listCredentials(): CredentialMetadata[] {
    const metadata: CredentialMetadata[] = [];
    
    for (const credential of this.credentials.values()) {
      metadata.push({
        id: credential.id,
        name: credential.name,
        createdAt: credential.createdAt,
        lastAccessed: credential.lastAccessed,
        rotationSchedule: credential.rotationSchedule
      });
    }
    
    return metadata;
  }

  /**
   * Get credentials that need rotation
   */
  getCredentialsNeedingRotation(): CredentialMetadata[] {
    const now = Date.now();
    const needsRotation: CredentialMetadata[] = [];
    
    for (const credential of this.credentials.values()) {
      if (credential.rotationSchedule) {
        const daysSinceCreation = (now - credential.createdAt) / (1000 * 60 * 60 * 24);
        
        if (daysSinceCreation >= credential.rotationSchedule) {
          needsRotation.push({
            id: credential.id,
            name: credential.name,
            createdAt: credential.createdAt,
            lastAccessed: credential.lastAccessed,
            rotationSchedule: credential.rotationSchedule
          });
        }
      }
    }
    
    return needsRotation;
  }

  /**
   * Get access log for a credential
   */
  getAccessLog(credentialId?: string): Array<{ credentialId: string; timestamp: number; agentId: string }> {
    if (credentialId) {
      return this.accessLog.filter(log => log.credentialId === credentialId);
    }
    return this.accessLog;
  }

  /**
   * Export credentials for backup (encrypted)
   */
  async exportVault(): Promise<string> {
    const vaultData = {
      config: {
        publicKey: this.config.publicKey
        // Private key is never exported
      },
      credentials: Array.from(this.credentials.entries()),
      exportedAt: Date.now()
    };
    
    return JSON.stringify(vaultData, null, 2);
  }

  /**
   * Import credentials from backup
   */
  async importVault(backupData: string): Promise<number> {
    try {
      const vaultData = JSON.parse(backupData);
      
      let imported = 0;
      for (const [id, credential] of vaultData.credentials) {
        this.credentials.set(id, credential);
        imported++;
      }
      
      console.log(`[SealVault] Imported ${imported} credentials`);
      return imported;
    } catch (error) {
      console.error('[SealVault] Failed to import vault:', error);
      return 0;
    }
  }

  /**
   * Get vault statistics
   */
  getStatistics(): {
    totalCredentials: number;
    needingRotation: number;
    totalAccesses: number;
    oldestCredential?: Date;
    newestCredential?: Date;
  } {
    let oldest: number | undefined;
    let newest: number | undefined;
    
    for (const credential of this.credentials.values()) {
      if (!oldest || credential.createdAt < oldest) {
        oldest = credential.createdAt;
      }
      if (!newest || credential.createdAt > newest) {
        newest = credential.createdAt;
      }
    }
    
    return {
      totalCredentials: this.credentials.size,
      needingRotation: this.getCredentialsNeedingRotation().length,
      totalAccesses: this.accessLog.length,
      oldestCredential: oldest ? new Date(oldest) : undefined,
      newestCredential: newest ? new Date(newest) : undefined
    };
  }

  /**
   * Clear all credentials (use with caution!)
   */
  clearAll(): void {
    this.credentials.clear();
    this.accessLog = [];
    console.log('[SealVault] Cleared all credentials');
  }
}

/**
 * Common credential types
 */
export const CredentialTypes = {
  ANTHROPIC_API_KEY: 'anthropic_api_key',
  SUI_PRIVATE_KEY: 'sui_private_key',
  OPENAI_API_KEY: 'openai_api_key',
  GITHUB_TOKEN: 'github_token',
  AWS_ACCESS_KEY: 'aws_access_key',
  AWS_SECRET_KEY: 'aws_secret_key',
  DATABASE_URL: 'database_url',
  SMTP_PASSWORD: 'smtp_password',
  WALLET_PRIVATE_KEY: 'wallet_private_key',
  CUSTOM: 'custom'
};