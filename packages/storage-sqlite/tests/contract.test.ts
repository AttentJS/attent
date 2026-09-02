import { afterEach } from "vitest";
import type Database from "better-sqlite3";
import {
  describeAuditSinkContract,
  describeIdentityStoreContract,
  describeRevocationStoreContract,
} from "../../../tests/adapters/contract.js";
import { openAttentDatabase, sqliteAuditSink, sqliteIdentityStore, sqliteRevocationStore } from "../src/index.js";

/** Runs the same adapter-conformance suites the in-memory stores pass (tests/adapters/memory.contract.test.ts) against the SQLite adapters, so a future adapter runs the exact same suite. */

const openDbs: Database.Database[] = [];

function freshDb(): Database.Database {
  const db = openAttentDatabase(":memory:");
  openDbs.push(db);
  return db;
}

afterEach(() => {
  while (openDbs.length > 0) {
    openDbs.pop()!.close();
  }
});

describeIdentityStoreContract("sqlite", () => sqliteIdentityStore(freshDb()));
describeRevocationStoreContract("sqlite", () => sqliteRevocationStore(freshDb()));
describeAuditSinkContract("sqlite", () => sqliteAuditSink(freshDb()));
