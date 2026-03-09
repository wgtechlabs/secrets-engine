/**
 * Tests for machine identity normalization and compatibility candidates.
 */

import { describe, expect, test } from "bun:test";
import type { NetworkInterfaceInfo } from "node:os";
import { getMachineIdentityProfile } from "../src/platform.ts";

function createInterface(mac: string, internal = false): NetworkInterfaceInfo {
  return {
    address: "192.168.1.10",
    netmask: "255.255.255.0",
    family: "IPv4",
    mac,
    internal,
    cidr: "192.168.1.10/24",
  };
}

describe("getMachineIdentityProfile", () => {
  test("builds a canonical identity from the sorted MAC set", () => {
    const profile = getMachineIdentityProfile({
      host: "workstation",
      username: "waren",
      interfaces: {
        WiFi: [createInterface("BB:BB:BB:BB:BB:BB")],
        Ethernet: [createInterface("AA:AA:AA:AA:AA:AA")],
      },
    });

    expect(profile.canonical).toBe(
      "workstation:aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb:waren",
    );
    expect(profile.macs).toEqual(["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]);
  });

  test("keeps canonical identity stable across adapter ordering changes", () => {
    const first = getMachineIdentityProfile({
      host: "workstation",
      username: "waren",
      interfaces: {
        WiFi: [createInterface("BB:BB:BB:BB:BB:BB")],
        Ethernet: [createInterface("AA:AA:AA:AA:AA:AA")],
      },
    });

    const second = getMachineIdentityProfile({
      host: "workstation",
      username: "waren",
      interfaces: {
        Ethernet: [createInterface("AA:AA:AA:AA:AA:AA")],
        WiFi: [createInterface("BB:BB:BB:BB:BB:BB")],
      },
    });

    expect(second.canonical).toBe(first.canonical);
    expect(second.candidates).toEqual(first.candidates);
  });

  test("includes legacy single-MAC candidates for older stores", () => {
    const profile = getMachineIdentityProfile({
      host: "workstation",
      username: "waren",
      interfaces: {
        WiFi: [createInterface("BB:BB:BB:BB:BB:BB")],
        Ethernet: [createInterface("AA:AA:AA:AA:AA:AA")],
      },
    });

    expect(profile.candidates).toContain("workstation:aa:aa:aa:aa:aa:aa:waren");
    expect(profile.candidates).toContain("workstation:bb:bb:bb:bb:bb:bb:waren");
  });
});
