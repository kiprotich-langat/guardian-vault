// Guardian Vault - Threat Pattern Governance Contract
// 
// This smart contract enables decentralized governance of threat patterns.
// Community members can propose new threat patterns, vote on them,
// and approved patterns are automatically distributed to all Guardian Vault instances.

module guardian_vault::threat_governance {
    use sui::table::{Self, Table};
    use sui::event;
    use std::string::{Self, String};

    // Error codes
    const E_NOT_AUTHORIZED: u64 = 0;
    const E_ALREADY_VOTED: u64 = 2;
    const E_VOTING_CLOSED: u64 = 3;
    const E_PROPOSAL_NOT_PASSED: u64 = 4;
    const E_ALREADY_EXECUTED: u64 = 5;

    // Proposal status
    const STATUS_ACTIVE: u8 = 0;
    const STATUS_PASSED: u8 = 1;
    const STATUS_REJECTED: u8 = 2;
    const STATUS_EXECUTED: u8 = 3;

    /// Main governance registry
    public struct GovernanceRegistry has key {
        id: UID,
        admin: address,
        proposal_count: u64,
        voting_period_ms: u64,
        quorum_threshold: u64,
        approval_threshold: u64,
        threat_patterns: Table<u64, ThreatPattern>,
    }

    /// Threat pattern definition
    public struct ThreatPattern has store, copy, drop {
        id: u64,
        name: String,
        pattern: String,
        description: String,
        severity: u8,
        category: String,
        created_by: address,
        created_at: u64,
        active: bool,
    }

    /// Proposal for new threat pattern
    public struct ThreatProposal has key {
        id: UID,
        proposal_id: u64,
        pattern: ThreatPattern,
        proposer: address,
        created_at: u64,
        voting_ends_at: u64,
        votes_for: u64,
        votes_against: u64,
        voters: Table<address, bool>,
        status: u8,
        executed: bool,
    }

    /// Voting token (represents voting power)
    public struct VotingToken has key, store {
        id: UID,
        power: u64,
    }

    // ========================================================================
    // Events
    // ========================================================================

    public struct ProposalCreated has copy, drop {
        proposal_id: u64,
        proposer: address,
        pattern_name: String,
        severity: u8,
    }

    public struct VoteCast has copy, drop {
        proposal_id: u64,
        voter: address,
        support: bool,
        voting_power: u64,
    }

    public struct ProposalExecuted has copy, drop {
        proposal_id: u64,
        pattern_id: u64,
        pattern_name: String,
    }

    public struct ThreatPatternActivated has copy, drop {
        pattern_id: u64,
        name: String,
        severity: u8,
    }

    public struct ThreatPatternDeactivated has copy, drop {
        pattern_id: u64,
        name: String,
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the governance registry
    fun init(ctx: &mut TxContext) {
        let registry = GovernanceRegistry {
            id: object::new(ctx),
            admin: ctx.sender(),
            proposal_count: 0,
            voting_period_ms: 7 * 24 * 60 * 60 * 1000, // 7 days
            quorum_threshold: 10,
            approval_threshold: 66,
            threat_patterns: table::new(ctx),
        };
        transfer::share_object(registry);
    }

    // ========================================================================
    // Proposal Management
    // ========================================================================

    /// Create a new threat pattern proposal
    public fun propose_threat_pattern(
        registry: &mut GovernanceRegistry,
        name: vector<u8>,
        pattern: vector<u8>,
        description: vector<u8>,
        severity: u8,
        category: vector<u8>,
        ctx: &mut TxContext
    ) {
        let proposal_id = registry.proposal_count;
        registry.proposal_count = registry.proposal_count + 1;

        let threat_pattern = ThreatPattern {
            id: proposal_id,
            name: string::utf8(name),
            pattern: string::utf8(pattern),
            description: string::utf8(description),
            severity,
            category: string::utf8(category),
            created_by: ctx.sender(),
            created_at: ctx.epoch_timestamp_ms(),
            active: false,
        };

        let pattern_name_copy = threat_pattern.name;

        let proposal = ThreatProposal {
            id: object::new(ctx),
            proposal_id,
            pattern: threat_pattern,
            proposer: ctx.sender(),
            created_at: ctx.epoch_timestamp_ms(),
            voting_ends_at: ctx.epoch_timestamp_ms() + registry.voting_period_ms,
            votes_for: 0,
            votes_against: 0,
            voters: table::new(ctx),
            status: STATUS_ACTIVE,
            executed: false,
        };

        event::emit(ProposalCreated {
            proposal_id,
            proposer: ctx.sender(),
            pattern_name: pattern_name_copy,
            severity,
        });

        transfer::share_object(proposal);
    }

    /// Vote on a proposal
    public fun vote(
        proposal: &mut ThreatProposal,
        voting_token: &VotingToken,
        support: bool,
        ctx: &mut TxContext
    ) {
        let voter = ctx.sender();
        let current_time = ctx.epoch_timestamp_ms();

        // Check voting is still open
        assert!(current_time < proposal.voting_ends_at, E_VOTING_CLOSED);
        assert!(proposal.status == STATUS_ACTIVE, E_VOTING_CLOSED);

        // Check hasn't voted yet
        assert!(!proposal.voters.contains(voter), E_ALREADY_VOTED);

        // Record vote
        proposal.voters.add(voter, support);

        if (support) {
            proposal.votes_for = proposal.votes_for + voting_token.power;
        } else {
            proposal.votes_against = proposal.votes_against + voting_token.power;
        };

        event::emit(VoteCast {
            proposal_id: proposal.proposal_id,
            voter,
            support,
            voting_power: voting_token.power,
        });
    }

    /// Finalize voting and determine outcome
    public fun finalize_proposal(
        registry: &GovernanceRegistry,
        proposal: &mut ThreatProposal,
        ctx: &mut TxContext
    ) {
        let current_time = ctx.epoch_timestamp_ms();

        // Check voting period has ended
        assert!(current_time >= proposal.voting_ends_at, E_VOTING_CLOSED);
        assert!(proposal.status == STATUS_ACTIVE, E_ALREADY_EXECUTED);

        let total_votes = proposal.votes_for + proposal.votes_against;
        
        let quorum_reached = total_votes > 0;

        if (quorum_reached) {
            let approval_percentage = (proposal.votes_for * 100) / total_votes;
            
            if (approval_percentage >= registry.approval_threshold) {
                proposal.status = STATUS_PASSED;
            } else {
                proposal.status = STATUS_REJECTED;
            };
        } else {
            proposal.status = STATUS_REJECTED;
        };
    }

    /// Execute an approved proposal
    public fun execute_proposal(
        registry: &mut GovernanceRegistry,
        proposal: &mut ThreatProposal,
        _ctx: &mut TxContext
    ) {
        // Check proposal passed
        assert!(proposal.status == STATUS_PASSED, E_PROPOSAL_NOT_PASSED);
        assert!(!proposal.executed, E_ALREADY_EXECUTED);

        // Add threat pattern to registry
        let pattern_id = proposal.pattern.id;
        let mut pattern = proposal.pattern;
        pattern.active = true;

        let pattern_name = pattern.name;

        registry.threat_patterns.add(pattern_id, pattern);

        proposal.executed = true;
        proposal.status = STATUS_EXECUTED;

        event::emit(ProposalExecuted {
            proposal_id: proposal.proposal_id,
            pattern_id,
            pattern_name,
        });

        event::emit(ThreatPatternActivated {
            pattern_id,
            name: pattern_name,
            severity: pattern.severity,
        });
    }

    // ========================================================================
    // Pattern Management
    // ========================================================================

    /// Deactivate a threat pattern (admin only)
    public fun deactivate_pattern(
        registry: &mut GovernanceRegistry,
        pattern_id: u64,
        ctx: &mut TxContext
    ) {
        assert!(ctx.sender() == registry.admin, E_NOT_AUTHORIZED);

        let pattern = registry.threat_patterns.borrow_mut(pattern_id);
        pattern.active = false;

        event::emit(ThreatPatternDeactivated {
            pattern_id,
            name: pattern.name,
        });
    }

    /// Reactivate a threat pattern (admin only)
    public fun reactivate_pattern(
        registry: &mut GovernanceRegistry,
        pattern_id: u64,
        ctx: &mut TxContext
    ) {
        assert!(ctx.sender() == registry.admin, E_NOT_AUTHORIZED);

        let pattern = registry.threat_patterns.borrow_mut(pattern_id);
        pattern.active = true;

        event::emit(ThreatPatternActivated {
            pattern_id,
            name: pattern.name,
            severity: pattern.severity,
        });
    }

    // ========================================================================
    // Voting Token Management
    // ========================================================================

    /// Mint voting token (for demo - in production, this would be restricted)
    public fun mint_voting_token(
        power: u64,
        ctx: &mut TxContext
    ) {
        let token = VotingToken {
            id: object::new(ctx),
            power,
        };
        transfer::transfer(token, ctx.sender());
    }

    // ========================================================================
    // View Functions
    // ========================================================================

    /// Get total number of proposals
    public fun get_proposal_count(registry: &GovernanceRegistry): u64 {
        registry.proposal_count
    }

    /// Get voting thresholds
    public fun get_thresholds(registry: &GovernanceRegistry): (u64, u64) {
        (registry.quorum_threshold, registry.approval_threshold)
    }

    /// Get proposal status
    public fun get_proposal_status(proposal: &ThreatProposal): (u8, u64, u64) {
        (proposal.status, proposal.votes_for, proposal.votes_against)
    }

    // ========================================================================
    // Admin Functions
    // ========================================================================

    /// Update voting parameters (admin only)
    public fun update_voting_parameters(
        registry: &mut GovernanceRegistry,
        voting_period_ms: u64,
        quorum_threshold: u64,
        approval_threshold: u64,
        ctx: &mut TxContext
    ) {
        assert!(ctx.sender() == registry.admin, E_NOT_AUTHORIZED);
        
        registry.voting_period_ms = voting_period_ms;
        registry.quorum_threshold = quorum_threshold;
        registry.approval_threshold = approval_threshold;
    }

    /// Transfer admin rights
    public fun transfer_admin(
        registry: &mut GovernanceRegistry,
        new_admin: address,
        ctx: &mut TxContext
    ) {
        assert!(ctx.sender() == registry.admin, E_NOT_AUTHORIZED);
        registry.admin = new_admin;
    }
}
