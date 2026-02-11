import {
  resolveTxt,
  resolveHostToIPs,
  resolveMxToIPs,
} from "./dns-operations.js";
import { getZone, updateZone } from "./autodns-client.js";
import { colors } from "../utils/helpers.js";
import { logger } from "../utils/logger.js";

/**
 * Query SPF record for a domain
 * @param {string} domain - Domain to query
 * @returns {Promise<string|null>} SPF record or null
 */
export async function getSPFRecord(domain) {
  try {
    const records = await resolveTxt(domain);
    const spfRecords = records
      .map((record) => record.join(""))
      .filter((record) => record.startsWith("v=spf1"));

    return spfRecords.length > 0 ? spfRecords[0] : null;
  } catch (error) {
    if (error.code === "ENODATA" || error.code === "ENOTFOUND") {
      return null;
    }
    throw error;
  }
}

/**
 * Recursively resolve all SPF includes and flatten them
 * @param {string} spfRecord - SPF record to flatten
 * @param {Set<string>} visited - Set of already visited domains
 * @param {number} depth - Current recursion depth
 * @returns {Promise<object>} Object with mechanisms and modifiers arrays
 */
export async function resolveSpfIncludes(
  spfRecord,
  visited = new Set(),
  depth = 0,
) {
  // Prevent infinite loops and limit recursion depth
  if (depth > 10) {
    logger.warn({ depth }, "Max SPF recursion depth reached");
    return { mechanisms: [], modifiers: [] };
  }

  const mechanisms = [];
  const modifiers = [];

  // Parse SPF record
  const parts = spfRecord.split(/\s+/);

  for (const part of parts) {
    if (part === "v=spf1") {
      continue; // Skip version
    }

    if (part.startsWith("include:")) {
      const includeDomain = part.substring(8);

      // Prevent circular includes
      if (visited.has(includeDomain)) {
        logger.warn({ domain: includeDomain }, "Circular SPF include detected");
        continue;
      }

      visited.add(includeDomain);

      try {
        const includeSpf = await getSPFRecord(includeDomain);
        if (includeSpf) {
          // Recursively resolve this include
          const resolved = await resolveSpfIncludes(
            includeSpf,
            visited,
            depth + 1,
          );
          mechanisms.push(...resolved.mechanisms);
          modifiers.push(...resolved.modifiers);
        } else {
          logger.warn(
            { domain: includeDomain },
            "Could not resolve SPF for include",
          );
        }
      } catch (error) {
        logger.warn(
          { domain: includeDomain, error: error.message },
          "Error resolving SPF include",
        );
      }
    } else if (part.startsWith("redirect=")) {
      modifiers.push(part);
    } else if (
      part === "all" ||
      part.startsWith("-all") ||
      part.startsWith("~all") ||
      part.startsWith("+all") ||
      part.startsWith("?all")
    ) {
      modifiers.push(part);
    } else if (part === "a" || part === "mx") {
      // Skip plain 'a' or 'mx' - they're domain-contextual and should only
      // be in each domain's own SPF record, not in shared includes
      logger.debug(
        { mechanism: part },
        "Skipping plain a/mx mechanism during flattening",
      );
    } else if (part.startsWith("a:")) {
      const hostname = part.substring(2);
      try {
        const ips = await resolveHostToIPs(hostname);
        mechanisms.push(...ips);
      } catch (error) {
        logger.warn(
          { hostname, error: error.message },
          "Could not resolve A record",
        );
        mechanisms.push(part);
      }
    } else if (part.startsWith("mx:")) {
      const domain = part.substring(3);
      try {
        const ips = await resolveMxToIPs(domain);
        mechanisms.push(...ips);
      } catch (error) {
        logger.warn({ domain, error: error.message }, "Could not resolve MX");
        mechanisms.push(part);
      }
    } else {
      // Keep other mechanisms as-is (ip4, ip6, etc.)
      mechanisms.push(part);
    }
  }

  return { mechanisms, modifiers };
}

/**
 * Split mechanisms into chunks to stay under DNS TXT string limit
 * DNS TXT records have a 255-character limit per string. To avoid automatic
 * splitting in the middle of values, we limit each chunk to ~240 chars.
 * @param {string[]} mechanisms - Array of SPF mechanisms
 * @param {number} maxChunkSize - Maximum size per chunk in bytes (default 240)
 * @returns {string[][]} Array of mechanism chunks
 */
export function splitMechanismsIntoChunks(mechanisms, maxChunkSize = 240) {
  const chunks = [];
  let currentChunk = [];
  let currentSize = 8; // Start with "v=spf1 " (7 chars + space)

  for (const mechanism of mechanisms) {
    const mechanismSize = mechanism.length + 1; // +1 for space

    // If adding this mechanism would exceed the limit, start a new chunk
    if (currentSize + mechanismSize > maxChunkSize && currentChunk.length > 0) {
      chunks.push([...currentChunk]);
      currentChunk = [];
      currentSize = 8; // Reset for new chunk
    }

    currentChunk.push(mechanism);
    currentSize += mechanismSize;
  }

  // Add the last chunk if it has any mechanisms
  if (currentChunk.length > 0) {
    chunks.push(currentChunk);
  }

  return chunks;
}

/**
 * Build flattened SPF record by resolving all includes
 * Now splits large records into multiple chunks to avoid DNS UDP fragmentation
 * @param {string} baseSpfRecord - Base SPF record to flatten
 * @returns {Promise<object>} Object with mainRecord and optional chunkRecords array
 */
export async function buildFlattenedSpfRecord(baseSpfRecord) {
  console.log(`\nResolving SPF includes from: ${baseSpfRecord}`);

  const resolved = await resolveSpfIncludes(baseSpfRecord);

  // Remove duplicates
  const uniqueMechanisms = [...new Set(resolved.mechanisms)];
  const uniqueModifiers = [...new Set(resolved.modifiers)];

  // Get the 'all' modifier to add at the end
  const allModifier = uniqueModifiers.find((m) => m.includes("all"));
  const otherModifiers = uniqueModifiers.filter((m) => !m.includes("all"));

  // Combine mechanisms and non-all modifiers
  const allParts = [...uniqueMechanisms, ...otherModifiers];

  // Build final SPF record (single record for backward compatibility check)
  const flattenedSpf = ["v=spf1", ...allParts, allModifier]
    .filter(Boolean)
    .join(" ");

  console.log(`Flattened SPF: ${flattenedSpf}`);
  console.log(`Length: ${flattenedSpf.length} bytes`);
  console.log(
    `Original mechanisms: ${resolved.mechanisms.length}, ` +
      `Unique: ${uniqueMechanisms.length}`,
  );

  // Check if we need to split the record (255 char DNS TXT string limit)
  if (flattenedSpf.length > 240) {
    console.log(
      `${colors.yellow}⚠${colors.reset} SPF record exceeds 240 bytes, splitting into chunks...`,
    );

    // Split mechanisms into chunks
    const chunks = splitMechanismsIntoChunks(allParts);

    console.log(`Split into ${chunks.length} chunks:\n`);
    const chunkRecords = chunks.map((chunk, index) => {
      // Use ~all (softfail) in chunks - the main record has the final policy
      const record = ["v=spf1", ...chunk, "~all"].join(" ");
      console.log(`  Chunk ${index + 1}: ${record.length} bytes`);
      return record;
    });

    // Main record will include all chunks plus the final 'all' modifier
    // Note: includes will be relative (_spf1, _spf2, etc.) and will be made FQDNs
    // when actually updating the zone
    const includeStatements = chunks.map((_, i) => `include:_spf${i + 1}`);
    const mainRecord = ["v=spf1", ...includeStatements, allModifier]
      .filter(Boolean)
      .join(" ");

    console.log(`\nMain record: ${mainRecord} (${mainRecord.length} bytes)\n`);

    return {
      mainRecord,
      chunkRecords,
      needsSplit: true,
    };
  }

  console.log(
    `${colors.green}✓${colors.reset} SPF record fits within DNS TXT limit\n`,
  );

  return {
    mainRecord: flattenedSpf,
    chunkRecords: [],
    needsSplit: false,
  };
}

/**
 * Update domain's SPF record
 * @param {string} domainName - Domain name
 * @param {string} spfValue - New SPF value
 * @returns {Promise<object>} Update result
 */
export async function updateDomainSPFRecord(domainName, spfValue) {
  try {
    // Get current zone data
    const zoneInfo = await getZone(domainName);

    if (
      !zoneInfo.data ||
      !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0
    ) {
      throw new Error("Invalid zone data received");
    }

    const zone = zoneInfo.data[0];

    // Find existing SPF TXT record or create new one
    let recordFound = false;
    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    // Guard: Apex CNAME conflicts with any other record
    const hasApexCname = zone.resourceRecords.some(
      (rr) => rr.type === "CNAME" && (rr.name === "" || rr.name === "@"),
    );
    if (hasApexCname) {
      throw new Error(
        "Apex has a CNAME record; cannot add/update " +
          "SPF TXT at zone apex due to DNS constraints",
      );
    }

    for (const record of zone.resourceRecords) {
      // SPF record is a TXT record with empty name for the domain itself
      if (
        record.type === "TXT" &&
        (record.name === "" || record.name === "@") &&
        record.value &&
        record.value.startsWith("v=spf1")
      ) {
        // Update existing SPF record
        record.value = spfValue;
        record.ttl = 300;
        recordFound = true;
        break;
      }
    }

    if (!recordFound) {
      // Add new SPF record
      zone.resourceRecords.push({
        name: "",
        type: "TXT",
        value: spfValue,
        ttl: 300,
      });
    }

    // Update the zone
    const updateResult = await updateZone(domainName, zone);
    return updateResult;
  } catch (error) {
    console.error(
      `  ${colors.red}✗${colors.reset} ` +
        `Failed to update SPF for ${domainName}`,
    );
    throw error;
  }
}

/**
 * Update the main SPF TXT record and create chunk records if needed
 * @param {string} recordName - Full record name (e.g., _spf.example.com)
 * @param {object} spfData - SPF data object with mainRecord, chunkRecords, needsSplit
 * @returns {Promise<object>} Update result
 */
export async function updateMainSPFRecord(recordName, spfData) {
  let { mainRecord, chunkRecords, needsSplit } = spfData;

  // Extract the zone name and record prefix
  const parts = recordName.split(".");
  const zoneName = parts.slice(-2).join(".");
  const recordPrefix = parts.slice(0, -2).join(".");

  // Update includes in mainRecord to use FQDNs (e.g., _spf1.diebasis.de)
  if (needsSplit) {
    mainRecord = mainRecord.replace(
      /include:_spf(\d+)/g,
      `include:_spf$1.${zoneName}`,
    );
  }

  logger.info(
    { record: recordName, value: mainRecord },
    "Updating main SPF record",
  );
  console.log(`\nUpdating DNS record: ${recordName}`);
  console.log(`New value: ${mainRecord}\n`);

  try {
    // Get current zone data
    const zoneInfo = await getZone(zoneName);

    if (
      !zoneInfo.data ||
      !Array.isArray(zoneInfo.data) ||
      zoneInfo.data.length === 0
    ) {
      console.error("Full zone response:", JSON.stringify(zoneInfo, null, 2));
      throw new Error("Invalid zone data received");
    }

    const zone = zoneInfo.data[0];

    if (!zone.resourceRecords) {
      zone.resourceRecords = [];
    }

    // Remove any non-TXT records with the same name FIRST to prevent AutoDNS validation issues
    // (e.g., if _spf has both TXT and A records, keep only the TXT)
    zone.resourceRecords = zone.resourceRecords.filter((record) => {
      if (record.name === recordPrefix && record.type !== "TXT") {
        logger.debug(
          { name: record.name, type: record.type },
          "Removing non-TXT record at SPF record name",
        );
        console.log(
          `  ${colors.yellow}⚠${colors.reset} Removed ${record.type} record ${recordPrefix}.${zoneName}`,
        );
        return false;
      }
      return true;
    });

    // If we need to split, create chunk records and update the main record separately
    if (needsSplit && chunkRecords.length > 0) {
      console.log(`Creating ${chunkRecords.length} SPF chunk records...`);

      // First, update ONLY the changes needed for chunks (remove main record from update)
      const zonesForChunkUpdate = JSON.parse(JSON.stringify(zone)); // Deep copy

      // Remove the main SPF record from this update to avoid API validation issues
      zonesForChunkUpdate.resourceRecords =
        zonesForChunkUpdate.resourceRecords.filter(
          (record) => !(record.type === "TXT" && record.name === recordPrefix),
        );

      for (let i = 0; i < chunkRecords.length; i++) {
        const chunkName = `${recordPrefix}${i + 1}`;
        const chunkValue = chunkRecords[i];

        // Find existing chunk record or prepare for creation
        let chunkFound = false;
        for (let j = 0; j < zonesForChunkUpdate.resourceRecords.length; j++) {
          if (
            zonesForChunkUpdate.resourceRecords[j].type === "TXT" &&
            zonesForChunkUpdate.resourceRecords[j].name === chunkName
          ) {
            zonesForChunkUpdate.resourceRecords[j].value = chunkValue;
            zonesForChunkUpdate.resourceRecords[j].ttl = 300;
            chunkFound = true;
            console.log(
              `  ${colors.green}✓${colors.reset} Updated ${chunkName}.${zoneName}`,
            );
            break;
          }
        }

        if (!chunkFound) {
          zonesForChunkUpdate.resourceRecords.push({
            name: chunkName,
            type: "TXT",
            value: chunkValue,
            ttl: 300,
          });
          console.log(
            `  ${colors.green}✓${colors.reset} Created ${chunkName}.${zoneName}`,
          );
        }
      }

      // Remove old chunk records that are no longer needed
      const expectedChunks = new Set(
        Array.from(
          { length: chunkRecords.length },
          (_, i) => `${recordPrefix}${i + 1}`,
        ),
      );

      zonesForChunkUpdate.resourceRecords =
        zonesForChunkUpdate.resourceRecords.filter((record) => {
          if (
            record.type === "TXT" &&
            record.name.startsWith(recordPrefix) &&
            /\d+$/.test(record.name) &&
            !expectedChunks.has(record.name)
          ) {
            console.log(
              `  ${colors.yellow}⚠${colors.reset} Removed old chunk ${record.name}.${zoneName}`,
            );
            return false;
          }
          return true;
        });

      // Update zone with chunk records ONLY (without the main SPF record)
      logger.debug(
        { zone: zoneName, chunks: chunkRecords.length },
        "Updating zone with SPF chunks",
      );
      try {
        await updateZone(zoneName, zonesForChunkUpdate);
        logger.debug({ zone: zoneName }, "SPF chunks updated successfully");
      } catch (chunkError) {
        logger.error(
          { zone: zoneName, error: chunkError.message },
          "Failed to update SPF chunks",
        );
        throw chunkError;
      }

      // Wait for chunk records to be processed by the API before creating the main record
      console.log("Waiting for DNS API to process chunk records...");
      await new Promise((resolve) => setTimeout(resolve, 3000));

      // Now update the main SPF record in a completely separate zone update
      logger.debug(
        { zone: zoneName, record: recordPrefix },
        "Preparing to update main SPF record",
      );
      const freshZoneInfo = await getZone(zoneName);
      if (
        !freshZoneInfo.data ||
        !Array.isArray(freshZoneInfo.data) ||
        freshZoneInfo.data.length === 0
      ) {
        throw new Error("Invalid zone data received on refresh");
      }

      const freshZone = freshZoneInfo.data[0];
      if (!freshZone.resourceRecords) {
        freshZone.resourceRecords = [];
      }

      // Find and update/create the main TXT record
      let recordFound = false;
      for (let i = 0; i < freshZone.resourceRecords.length; i++) {
        if (
          freshZone.resourceRecords[i].type === "TXT" &&
          freshZone.resourceRecords[i].name === recordPrefix
        ) {
          freshZone.resourceRecords[i] = {
            name: recordPrefix,
            type: "TXT",
            value: mainRecord,
            ttl: 300,
          };
          recordFound = true;
          logger.debug(
            { record: recordPrefix },
            "Updated existing main SPF record",
          );
          break;
        }
      }

      if (!recordFound) {
        console.log(
          `No existing TXT record found for ${recordName}, creating new...`,
        );
        freshZone.resourceRecords.push({
          name: recordPrefix,
          type: "TXT",
          value: mainRecord,
          ttl: 300,
        });
        logger.debug({ record: recordPrefix }, "Creating new main SPF record");
      }

      // Update the zone with the full record set (including chunks and main)
      const updateResult = await updateZone(zoneName, freshZone);

      if (updateResult.status?.type === "SUCCESS") {
        console.log(
          `${colors.green}✓${colors.reset} Successfully updated ${recordName}`,
        );
      } else {
        console.log(
          `${colors.red}✗${colors.reset} Update may have failed, check response above`,
        );
      }

      return updateResult;
    }

    // No splitting needed - update the main SPF record directly
    logger.debug(
      { zone: zoneName, record: recordPrefix },
      "Updating main SPF record (no split needed)",
    );

    // Find and update/create the main TXT record
    let recordFound = false;
    for (let i = 0; i < zone.resourceRecords.length; i++) {
      if (
        zone.resourceRecords[i].type === "TXT" &&
        zone.resourceRecords[i].name === recordPrefix
      ) {
        zone.resourceRecords[i] = {
          name: recordPrefix,
          type: "TXT",
          value: mainRecord,
          ttl: 300,
        };
        recordFound = true;
        logger.debug(
          { record: recordPrefix },
          "Updated existing main SPF record",
        );
        break;
      }
    }

    if (!recordFound) {
      console.log(
        `No existing TXT record found for ${recordName}, creating new...`,
      );
      zone.resourceRecords.push({
        name: recordPrefix,
        type: "TXT",
        value: mainRecord,
        ttl: 300,
      });
      logger.debug({ record: recordPrefix }, "Creating new main SPF record");
    }

    // Update the zone
    const updateResult = await updateZone(zoneName, zone);

    if (updateResult.status?.type === "SUCCESS") {
      console.log(
        `${colors.green}✓${colors.reset} Successfully updated ${recordName}`,
      );
    } else {
      console.log(
        `${colors.red}✗${colors.reset} Update may have failed, check response above`,
      );
    }

    return updateResult;
  } catch (error) {
    console.error(
      `${colors.red}✗${colors.reset} Failed to update ${recordName}`,
    );
    console.error("Error details:", error.message);
    throw error;
  }
}
