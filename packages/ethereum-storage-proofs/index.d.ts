export type Hex = `0x${string}`;
export type Scope = "l1" | "account" | "storage" | "threshold" | "batch";
export type Root = [string, string, string, string];
export interface RPCProof {
  storageHash: Hex;
  storageProof?: { key: Hex; value: Hex; proof: Hex[] }[];
  address?: Hex;
  nonce?: Hex;
  balance?: Hex;
  codeHash?: Hex;
  accountProof?: Hex[];
}
export interface ProofEnvelope {
  stateRoot?: Hex;
  proof: RPCProof;
}
export interface Node {
  bytes: number[];
  length: number;
  is_extension: boolean;
}
export interface StorageValue {
  value: number[];
  value_length: number;
}
export interface Account {
  address: number[];
  nonce: number[];
  nonce_length: number;
  balance: number[];
  balance_length: number;
  storage_hash: Root;
  code_hash: Root;
}
export interface AccountWitness {
  state_root: Root;
  account: Account;
  account_nodes: Node[];
  account_count: number;
}
export interface StorageWitness {
  storage_root: Root;
  slot_key: number[];
  value: StorageValue;
  storage_nodes: Node[];
  storage_count: number;
}
export interface PrepareOptions {
  accountDepth?: number;
  accountBytes?: number;
  storageDepth?: number;
  storageBytes?: number;
  /** storageProof entry; required when the input holds several entries. */
  slotIndex?: number;
}
export interface Path {
  indices: number[];
  count: number;
}
export interface BatchWitness {
  root: Root;
  slot_keys: number[][];
  values: StorageValue[];
  nodes: Node[];
  node_count: number;
  paths: Path[];
}
export interface Bucket {
  nodes: Node[];
  count: number;
}
export type Buckets = [number, number, number, number];
export interface MixedWitness {
  root: Root;
  slot_keys: number[][];
  values: StorageValue[];
  small: Bucket;
  medium: Bucket;
  large: Bucket;
  full: Bucket;
  paths: Path[];
}
export interface PathProfile {
  version: 1;
  scope: Exclude<Scope, "batch">;
  mode: "general" | "hashed";
  account: number[];
  storage: number[];
}
export interface BatchBase {
  version: 1;
  scope: "batch";
  slots: number;
  depth: number;
  parsing?: "path" | "shared";
}
export interface UniformProfile extends BatchBase {
  layout?: "uniform";
  nodes: number;
  bytes: number;
}
export interface MixedProfile extends BatchBase {
  layout: "mixed";
  buckets: Buckets;
}
export interface ReceiptProfile {
  version: 1;
  scope: "receipt";
  depth: number;
  node_bytes: number;
  leaf_bytes: number;
  max_logs: number;
}
export interface EventProfile extends Omit<ReceiptProfile, "scope"> {
  scope: "event";
  data_bytes: number;
}
export type Profile =
  | PathProfile
  | UniformProfile
  | MixedProfile
  | ReceiptProfile
  | EventProfile
  | AbsenceProfile;
export interface Shape {
  lengths: number[];
  hasEmbedded: boolean;
}
export interface Inspection {
  version: 1;
  scope: Scope;
  account: Shape;
  storage: Shape[];
  shared: Shape;
}
export interface Cost {
  nodeHashPermutations: number;
  nodeBytes: number;
}
export interface CatalogueEntry {
  id: string;
  profile: Profile;
  fallback?: boolean;
}
export interface Catalogue {
  version: 1;
  profiles: CatalogueEntry[];
}
export const BYTE_CAPACITIES: number[];
export function prepare(
  input: ProofEnvelope,
  opts?: PrepareOptions,
): Promise<AccountWitness & StorageWitness>;
export function prepareAccount(
  input: ProofEnvelope,
  opts?: PrepareOptions,
): Promise<AccountWitness>;
export function prepareStorage(
  input: ProofEnvelope,
  opts?: PrepareOptions,
): Promise<StorageWitness>;
export function encodePath(
  proof: Uint8Array[],
  key: Uint8Array,
  bytes: number,
  depth: number,
  /** Names the path in capacity errors, for example "account" or "storage". */
  label?: string,
): { nodes: Node[]; count: number };
/** Entry index; without slotIndex the list must hold exactly one entry. */
export function selectSlotIndex(entries: unknown[], slotIndex?: number): number;
export function prepareBatchStorage(
  input: ProofEnvelope,
  opts?: {
    slots?: number;
    nodeCapacity?: number;
    pathDepth?: number;
    nodeBytes?: number;
  },
): Promise<BatchWitness>;
export function prepareMixedBatch(
  input: ProofEnvelope,
  opts: { slots?: number; buckets: Buckets; pathDepth?: number },
): Promise<MixedWitness>;
export function inspectProof(
  input: ProofEnvelope,
  opts?: { scope?: Scope; slotIndex?: number },
): Promise<Inspection>;
export interface Headroom {
  /** Extra 532-byte positions appended to each recommended path. */
  extraDepth?: number;
  /** Make every recommended position 532 bytes. */
  fullWidth?: boolean;
}
export function recommendProfile(
  info: Inspection,
  headroom?: Headroom,
): Profile;
export function validateProfile(p: unknown): Profile;
export function fitsProfile(info: Inspection, p: Profile): boolean;
/** Why p cannot take the inspected proof, or null when it fits. */
export function profileMisfit(info: Inspection, p: Profile): string | null;
export function profileCost(p: Profile): Cost;
export function selectProfile(
  info: Inspection,
  catalogue: Catalogue,
): CatalogueEntry & { cost: Cost };
export interface RecursiveProof {
  verification_key: string[];
  proof: string[];
}
export interface L1Claim {
  state_root: Root;
  address: number[];
  slot_key: number[];
  value: number[];
}
export interface AccountClaim {
  state_root: Root;
  address: number[];
  storage_root: Root;
}
export interface StorageClaim {
  storage_root: Root;
  slot_key: number[];
  value: number[];
}
export interface ThresholdClaim {
  storage_root: Root;
  slot_key: number[];
  minimum: number[];
}
export interface BatchClaim {
  storage_root: Root;
  slot_keys: number[][];
  values: number[][];
}
export interface RecursiveProofExport {
  format_version: 2;
  protocol: {
    aztec_tag: "v6.0.0";
    noir_commit: "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7";
    transcript: "Poseidon2";
    proof_type: 6;
  };
  profile: Profile;
  /** Preserved version-2 wire field; contains the recursive proof and key. */
  certificate: RecursiveProof;
  expected:
    | L1Claim
    | AccountClaim
    | StorageClaim
    | ThresholdClaim
    | BatchClaim
    | ReceiptClaim
    | EventClaim
    | StorageZeroClaim
    | AccountAbsentClaim
    | L1ZeroClaim;
  /** bb's hash of the producer key. Untrusted: the prover's claim, not a policy. */
  producer_vk_hash: string;
  statement: string;
}
/** Structural validation only; does not cryptographically verify or authorize anything.
 * expectedVkHash, taken from the caller's own policy, must equal producer_vk_hash. */
export function checkRecursiveProofExport(
  bundle: unknown,
  options?: { expectedVkHash?: string },
): RecursiveProofExport;

export interface ToolOptions {
  python?: string;
  onLog?: (text: string, stream: "stdout" | "stderr") => void;
}
export interface ProfileResult {
  directory: string;
  profile: Profile;
}
export interface PreparationResult {
  directory: string;
  witnessPath: string;
  claim: RecursiveProofExport["expected"];
  preparation: {
    profile: Profile;
    claim: RecursiveProofExport["expected"];
    scope: string;
  };
}
export interface ProofResults {
  profile: Profile;
  native_proof_verified: true;
  recursive_proof_verified?: true;
  vk_hash: string;
  statement: string;
  [key: string]: unknown;
}
export interface RecursiveProofResult {
  directory: string;
  recursive_proofPath: string;
  bundle: RecursiveProofExport;
  results: ProofResults;
}
export interface LinkedResult {
  directory: string;
  proofPath: string;
  verificationKeyPath: string;
  publicInputsPath: string;
  results: {
    recursive_proof_verified: true;
    mismatched_storage_root_rejected?: true;
    [key: string]: unknown;
  };
}
export class ToolError extends Error {
  script: string;
  exitCode: number | string;
  stdout: string;
  stderr: string;
}
export function generateProfile(
  profile: Profile,
  output: string,
  tools?: ToolOptions,
): Promise<ProfileResult>;
export function autoProfile(
  options: ToolOptions & {
    input: string;
    output: string;
    scope?: Scope;
    catalogue?: string;
    /** storageProof entry; required when the input holds several entries. */
    slotIndex?: number;
  } & Headroom,
): Promise<
  ProfileResult & {
    selection: {
      inspection: Inspection;
      slotIndex?: number;
      recommended: Profile;
      selected?: CatalogueEntry & { cost: Cost };
      policy: string;
    };
  }
>;
export function prepareCircuit(
  options: ToolOptions & {
    profile: string;
    input: string;
    output: string;
    minimum?: bigint;
    execute?: boolean;
    cache?: string;
    /** storageProof entry; required when the input holds several entries. */
    slotIndex?: number;
  },
): Promise<PreparationResult>;
export function proveRecursiveProof(
  options: ToolOptions & {
    profile: string;
    input: string;
    output: string;
    bb: string;
    bbSha256?: string;
    /** Aztec release tag of a --bb-sha256 build not recorded in toolchain.json. */
    aztecTag?: string;
    minimum?: bigint;
    recursiveCheck?: boolean;
    cache?: string;
    /** storageProof entry; required when the input holds several entries. */
    slotIndex?: number;
  },
): Promise<RecursiveProofResult>;
export function proveLinkedRecursiveProofs(
  options: ToolOptions & {
    app: string;
    user: string;
    /** Authorised app producer key hash from the caller's policy. */
    appVkHash: string;
    /** Authorised user producer key hash from the caller's policy. */
    userVkHash: string;
    output: string;
    bb: string;
    bbSha256?: string;
    mode?: "storage" | "threshold" | "batch" | "storage_zero";
    negativeChecks?: boolean;
  },
): Promise<LinkedResult>;

export interface ReceiptLog {
  address: Hex;
  topics: Hex[];
  data: Hex;
}
export interface RpcReceipt {
  type?: Hex;
  root?: Hex;
  status?: Hex;
  cumulativeGasUsed: Hex;
  logsBloom: Hex;
  logs: ReceiptLog[];
}
export interface ReceiptProofInput {
  receiptsRoot: Hex;
  transactionIndex: string;
  receipt: Hex;
  proof: Hex[];
  logIndex?: number;
}
export interface ReceiptInfo {
  receiptType: number;
  hasPostState: boolean;
  status: boolean;
  postState: Hex;
  cumulativeGasUsed: string;
  logs: ReceiptLog[];
}
export interface ReceiptOptions {
  depth?: number;
  nodeBytes?: number;
  leafBytes?: number;
  maxLogs?: number;
}
export interface ReceiptClaim {
  receipts_root: Root;
  transaction_index: string;
  receipt_type: number;
  has_post_state: boolean;
  status: boolean;
  post_state: number[];
  cumulative_gas_used: string;
}
export interface EventClaim {
  receipts_root: Root;
  transaction_index: string;
  log_index: number;
  emitter: number[];
  topics: number[][];
  topic_count: number;
  data_hash: Root;
  data_length: number;
}
export interface ReceiptWitness {
  receipts_root: Root;
  transaction_index: string;
  nodes: Node[];
  count: number;
  leaf: number[];
  leaf_length: number;
}
export interface EventWitness extends ReceiptWitness {
  log_index: number;
  expected: {
    emitter: number[];
    topics: number[][];
    topic_count: number;
    data: number[];
    data_length: number;
  };
}
export function encodeRpcReceipt(receipt: RpcReceipt): Hex;
export function decodeReceipt(encoded: Hex): ReceiptInfo;
/** First Byzantium block on Ethereum mainnet. */
export const MAINNET_BYZANTIUM_BLOCK: bigint;
export interface BuildReceiptProofOptions {
  /**
   * The authenticated header's receiptsRoot. The reconstructed root must equal it.
   * null opts out for a synthetic trie whose root the caller authenticates itself.
   */
  expectedReceiptsRoot: Hex | null;
  /** With byzantiumBlock: require a post-state root before it and a status from it. */
  blockNumber?: bigint | string | number;
  byzantiumBlock?: bigint | string | number;
}
export function buildReceiptProof(
  receipts: Hex[],
  transactionIndex: bigint | string | number,
  options: BuildReceiptProofOptions,
): Promise<ReceiptProofInput>;
export function inspectReceiptProof(input: ReceiptProofInput): Promise<{
  depth: number;
  nodeBytes: number;
  leafBytes: number;
  maxLogs: number;
  dataBytes: number;
}>;
export function prepareReceipt(
  input: ReceiptProofInput,
  options?: ReceiptOptions,
): Promise<{ witness: ReceiptWitness; claim: ReceiptClaim }>;
export function prepareEvent(
  input: ReceiptProofInput,
  options?: ReceiptOptions & { logIndex?: number; dataBytes?: number },
): Promise<{ witness: EventWitness; claim: EventClaim }>;

export interface AbsenceBase {
  version: 1;
  depth: number;
  node_bytes: number;
  terminal_bytes: number;
}
export type AbsenceProfile =
  | (AbsenceBase & { scope: "storage_zero" | "account_absent" })
  | (AbsenceBase & {
      scope: "l1_zero";
      account_depth: number;
      account_bytes: number;
    });
export interface AbsenceOptions {
  depth?: number;
  nodeBytes?: number;
  terminalBytes?: number;
  slotIndex?: number;
}
export interface AbsenceWitness {
  nodes: Node[];
  count: number;
  terminal: number[];
  terminal_length: number;
  kind: number;
}
export interface StorageZeroClaim {
  storage_root: Root;
  slot_key: number[];
}
export interface AccountAbsentClaim {
  state_root: Root;
  address: number[];
}
export interface L1ZeroClaim extends AccountAbsentClaim {
  slot_key: number[];
}
export const EMPTY_TRIE_ROOT: Hex;
export function prepareStorageZero(
  input: ProofEnvelope,
  options?: AbsenceOptions,
): Promise<{ witness: AbsenceWitness; claim: StorageZeroClaim }>;
export function prepareAccountAbsent(
  input: ProofEnvelope,
  options?: AbsenceOptions,
): Promise<{ witness: AbsenceWitness; claim: AccountAbsentClaim }>;
export function prepareL1Zero(
  input: ProofEnvelope,
  options?: AbsenceOptions & PrepareOptions,
): Promise<{
  witness: AbsenceWitness & {
    account: Account;
    account_nodes: Node[];
    account_count: number;
  };
  claim: L1ZeroClaim;
}>;

export function inspectAbsenceProof(
  input: ProofEnvelope,
  options?: {
    scope?: "storage_zero" | "account_absent" | "l1_zero";
    slotIndex?: number;
  },
): Promise<AbsenceProfile>;

/** Optional live transport. Roots/finality remain application policy. */
export interface FetchProofOptions {
  rpcUrl: string;
  address: Hex;
  slots?: Hex[];
  /** A hex block number or latest/earliest/safe/finalized; defaults to finalized. */
  block?: Hex | "latest" | "earliest" | "safe" | "finalized";
  timeoutMs?: number;
  fetch?: (
    url: string,
    init: {
      method: string;
      headers: Record<string, string>;
      body: string;
      signal: AbortSignal;
    },
  ) => Promise<{ ok: boolean; json(): Promise<unknown> }>;
}
export function fetchProof(options: FetchProofOptions): Promise<
  ProofEnvelope & {
    stateRoot: Hex;
    block: { number: Hex; hash: Hex };
  }
>;
