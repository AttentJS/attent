import { memoryIdentityStore } from "../../src/identity/store.js";
import { memoryRevocationStore } from "../../src/revocation/index.js";
import { memoryAuditSink } from "../../src/audit/sink.js";
import { describeAuditSinkContract, describeIdentityStoreContract, describeRevocationStoreContract } from "./contract.js";

describeIdentityStoreContract("in-memory", memoryIdentityStore);
describeRevocationStoreContract("in-memory", memoryRevocationStore);
describeAuditSinkContract("in-memory", memoryAuditSink);
