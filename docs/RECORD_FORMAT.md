# MedicineGuard Canonical Record Serialization Specification
**Document ID:** MG-SPEC-001  
**Version:** 1.0 (Format Identifier: `MG01`)  
**Audience:** Cryptographic implementers, C/WASM developers, JavaScript client engineers  

---

## 1. Overview and Rationale

In cryptographic Merkle Tree verification, every node hash is computed from the exact binary representation of its input data. If two independent systems (e.g., a C/WebAssembly engine in the manufacturer's dashboard and a JavaScript scanner on a customer's smartphone) serialize the same logical medicine record using different field orders, character encodings, spacing, or whitespace delimiters, the resulting SHA-256 leaf hashes will diverge completely due to the **avalanche effect**.

To guarantee **100% deterministic, cross-platform leaf hashing**, MedicineGuard defines the **MG01 Canonical Binary Serialization Standard**.

---

## 2. Medicine Record Logical Structure

Each medicine unit record contains five mandatory UTF-8 text fields:

| Field Index | Field Name | Data Type | Description | Example Value |
|---|---|---|---|---|
| 0 | `batch_id` | String (ASCII/UTF-8) | Unique batch registration identifier | `"BATCH101"` |
| 1 | `unit_id` | String (ASCII/UTF-8) | Unique unit identifier within the batch | `"MED00001"` |
| 2 | `medicine_name` | String (UTF-8) | Commercial medicine name and dosage | `"Paracetamol 500mg"` |
| 3 | `manufacturing_date` | String (`YYYY-MM-DD`) | Date of production (ISO 8601 calendar) | `"2026-11-13"` |
| 4 | `expiry_date` | String (`YYYY-MM-DD`) | Expiration date (ISO 8601 calendar) | `"2028-11-13"` |

### Validation Constraints
1. **Non-Null & Non-Empty:** All five fields must be present and contain at least one non-whitespace character.
2. **Date Format:** Manufacturing and expiry dates must strictly follow `YYYY-MM-DD` (10 ASCII characters).
3. **No Trailing Null Terminators:** In the binary stream, strings are stored without the C null terminator (`\0`).

---

## 3. Canonical Binary Layout

The serialized stream consists of a 4-byte ASCII header followed by the 5 fields encoded in strict sequence. Each field is prefixed by a **4-byte unsigned big-endian integer** indicating its byte length.

```
┌──────────┬────────────────┬──────────────────────────┬───┬────────────────┬──────────────────────────┐
│ Magic    │ Length Field 0 │ UTF-8 Bytes Field 0      │...│ Length Field 4 │ UTF-8 Bytes Field 4      │
│ (4 bytes)│ (4 bytes BE)   │ (L_0 bytes)              │   │ (4 bytes BE)   │ (L_4 bytes)              │
├──────────┼────────────────┼──────────────────────────┼───┼────────────────┼──────────────────────────┤
│ "MG01"   │ len(batch_id)  │ batch_id                 │...│ len(exp_date)  │ expiry_date              │
└──────────┴────────────────┴──────────────────────────┴───┴────────────────┴──────────────────────────┘
```

### Detailed Byte Offset Breakdown

1. **Format Identifier (Bytes 0..3):**
   - Value: `0x4D, 0x47, 0x30, 0x31` (ASCII string `"MG01"`).
   - Rejection rule: If the first 4 bytes do not match `MG01`, parsing immediately aborts.

2. **Field 0 — `batch_id`:**
   - Length (4 bytes, Big-Endian): $L_{\text{batch}} = \text{byte length}$.
   - Payload ($L_{\text{batch}}$ bytes): Exact UTF-8 bytes.

3. **Field 1 — `unit_id`:**
   - Length (4 bytes, Big-Endian): $L_{\text{unit}} = \text{byte length}$.
   - Payload ($L_{\text{unit}}$ bytes): Exact UTF-8 bytes.

4. **Field 2 — `medicine_name`:**
   - Length (4 bytes, Big-Endian): $L_{\text{name}} = \text{byte length}$.
   - Payload ($L_{\text{name}}$ bytes): Exact UTF-8 bytes.

5. **Field 3 — `manufacturing_date`:**
   - Length (4 bytes, Big-Endian): $L_{\text{mfg}} = 10$ (`0x00, 0x00, 0x00, 0x0A`).
   - Payload ($L_{\text{mfg}}$ bytes): Exact ASCII bytes (e.g., `"2026-11-13"`).

6. **Field 4 — `expiry_date`:**
   - Length (4 bytes, Big-Endian): $L_{\text{exp}} = 10$ (`0x00, 0x00, 0x00, 0x0A`).
   - Payload ($L_{\text{exp}}$ bytes): Exact ASCII bytes (e.g., `"2028-11-13"`).

### Formula for Total Serialized Size
$$\text{Total Size} = 4 + \sum_{i=0}^4 (4 + L_i) = 24 + L_{\text{batch}} + L_{\text{unit}} + L_{\text{name}} + L_{\text{mfg}} + L_{\text{exp}}$$

---

## 4. Concrete Hex Dump Example

Consider the record:
- `batch_id`: `"BATCH101"` (8 bytes)
- `unit_id`: `"MED00001"` (8 bytes)
- `medicine_name`: `"Aspirin"` (7 bytes)
- `manufacturing_date`: `"2026-11-13"` (10 bytes)
- `expiry_date`: `"2028-11-13"` (10 bytes)

$$\text{Total Size} = 24 + 8 + 8 + 7 + 10 + 10 = 67 \text{ bytes}$$

### Hexadecimal Stream:
```hex
Offset   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII
0000     4D 47 30 31 00 00 00 08 42 41 54 43 48 31 30 31  MG01....BATCH101
0010     00 00 00 08 4D 45 44 30 30 30 30 31 00 00 00 07  ....MED00001....
0020     41 73 70 69 72 69 6E 00 00 00 0A 32 30 32 36 2D  Aspirin....2026-
0030     31 31 2D 31 33 00 00 00 0A 32 30 32 38 2D 31 31  11-13....2028-11
0040     2D 31 33                                         -13
```

---

## 5. JavaScript Implementation Reference for Phase 2

In Phase 2, JavaScript running in the browser will construct the exact same byte buffer using `TextEncoder` and `DataView`:

```javascript
function serializeMedicineRecord(record) {
    const encoder = new TextEncoder();
    const bBatch = encoder.encode(record.batchId);
    const bUnit  = encoder.encode(record.unitId);
    const bName  = encoder.encode(record.medicineName);
    const bMfg   = encoder.encode(record.manufacturingDate);
    const bExp   = encoder.encode(record.expiryDate);

    const totalLen = 4 + (4 + bBatch.length) + (4 + bUnit.length) + 
                     (4 + bName.length) + (4 + bMfg.length) + (4 + bExp.length);

    const buffer = new Uint8Array(totalLen);
    const view = new DataView(buffer.buffer);
    let offset = 0;

    // Header "MG01"
    buffer.set([0x4D, 0x47, 0x30, 0x31], offset);
    offset += 4;

    function writeField(fieldBytes) {
        view.setUint32(offset, fieldBytes.length, false); // Big-Endian
        offset += 4;
        buffer.set(fieldBytes, offset);
        offset += fieldBytes.length;
    }

    writeField(bBatch);
    writeField(bUnit);
    writeField(bName);
    writeField(bMfg);
    writeField(bExp);

    return buffer;
}
```

This guarantees bit-for-bit compatibility between client JavaScript and the C WebAssembly engine.
