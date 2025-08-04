# pvashark

Wireshark Lua script plugin packet dissector for PV Access protocol

Builds on work by mdavidsaver in https://github.com/mdavidsaver/cashark

This repo extends support to all PVData and Normative Data Types.

## Implementation Highlights

- **Bit-Based Type Analysis**: Type codes are analyzed using bitwise operations rather than hex value lookups
- **Field Registry System**: Sophisticated caching system for type definitions using request_id partitioning  
- **Simple BitSet Expansion**: Automatic inclusion of direct non-complex children when complex fields are set
- **Enhanced Display Format**: Standardized field format with type annotations and registry references

The implementation follows the user preferences for FieldDesc formatting: `field_name (0xHH: type_name)` with clear hierarchical display and registry ID annotations.

# Decoding EPICS PVAccess — Wire Protocol Specification

This document describes the PVAccess wire protocol used by EPICS 7 for process variable communication (PV Access). The protocol supports complex structured data types called Normative Types (NT) and provides more sophisticated data handling than traditional Channel Access.

**Key Protocol Features:**
- **Structured Data**: Supports complex nested data structures beyond simple scalars
- **Type Introspection**: Self-describing data with cached type definitions
- **Efficient Updates**: Partial updates using ChangedBitSet to send only modified fields
- **Normative Types**: Standard data structures (NTScalar, NTArray, etc.) for interoperability

> **Scope**  
> • TLS framing (if used) is opaque for this document.  
> • Control‑layer messages (flag bit 0 = 1) and application messages (flag bit 0 = 0) are both included.  
> • Byte offsets are **little‑endian unless the _byte‑order_ flag bit (bit 7) is 1**.

---

## 1. Transport Layer

- Runs over TCP (default port 5075) or TLS (default port 5076)
- Multiple PVA messages can be packed into TCP segments
- Messages may span multiple TCP segments
- Segmentation is rare; if used, each segment may include up‑front padding so that the *first byte of the payload* is 8‑byte aligned

---

## 2. Common Message Header (8 bytes)

| Offset | Size | Field            | Meaning                                                                 |
|-------:|-----:|------------------|-------------------------------------------------------------------------|
|      0 |    1 | **Magic**        | Always `0xCA`                                                           |
|      1 |    1 | **Version**      | Protocol version (PVXS uses _2_)                                        |
|      2 |    1 | **Flags**        | See *Flag bits* table below                                             |
|      3 |    1 | **Command**      | Opcode (e.g. `0x07` = Create Channel)                                   |
|      4 |    4 | **PayloadSize**  | 32‑bit payload length (application msg) or control value (control msg)  |

### Flag bits (byte 2)

| Bit | Name / Meaning                                                 |
|----:|----------------------------------------------------------------|
|   0 | **Control** (`1`) vs **Application** (`0`)                     |
| 1‑3 | Reserved (0)                                                   |
| 4‑5 | Segmentation (`00` single, `01` first, `11` middle, `10` last) |
|   6 | **Direction** — `0` = client→server, `1` = server→client       |
|   7 | **Byte Order** — `0` = little‑endian, `1` = big‑endian         |

---

## 3. Control Messages (flag bit 0 = 1)

|  Cmd | Name (PVXS)                 | Notes / Payload source                     |
|-----:|-----------------------------|--------------------------------------------|
| `00` | **Mark Total Bytes Sent**   | Header `PayloadSize` = running‑byte‑count  |
| `01` | **Acknowledge Total Bytes** | Header `PayloadSize` = confirmed count     |
| `02` | **Set Byte Order**          | Byte‑order flag in header is authoritative |
| `03` | **Echo Request**            | Header `PayloadSize` = arbitrary token     |
| `04` | **Echo Response**           | Mirrors token back                         |

No additional payload body follows these 8‑byte headers.

---

## 4. Application Messages (flag bit 0 = 0)

### 4.1 Discovery

|  Cmd | Direction     | Name                | Payload (summary)                                                        |
|-----:|---------------|---------------------|--------------------------------------------------------------------------|
| `00` | S → C (UDP)   | **Beacon**          | GUID, seq‑ID, change‑ctr, addr, port, proto string, *opt.* status struct |
| `03` | C → S         | **Search Request**  | seq‑ID, flags, reply‑addr/port, proto list, *N×*{inst‑ID, PV name}       |
| `04` | S → C         | **Search Response** | server GUID, seq‑ID, addr, port, proto, *found*, list (inst‑IDs)         |
| `16` | Forwarder → S | **Origin Tag**      | IPv6 address of original receiver (16 B)                                 |

#### 4.1.1 BEACON Message Example

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Beacon (0x00)
   ├─ Payload Size: 45
   ├─ GUID: 12 bytes (server identifier)
   ├─ Beacon sequence#: 5
   ├─ Beacon change count: 2
   ├─ Address: 16 bytes (IPv6 address)
   ├─ Port: 5075
   └─ Transport Protocol: "tcp"
```

#### 4.1.2 Client SEARCH Request Examples

**SEARCH with TCP protocol:**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Search Request (0x03)
   ├─ Payload Size: 52
   ├─ Search Sequence #: 1234
   ├─ Mask: 0x81
   │  ├─ Reply: Required (1)
   │  └─ Reply: Unicast (1)
   ├─ Address: 16 bytes (reply address)
   ├─ Port: 5075
   ├─ Transport Protocol: "tcp"
   ├─ PV Count: 2
   ├─ CID: 100
   ├─ Name: "PV:temperature"
   ├─ CID: 101
   └─ Name: "PV:pressure"
```

**SEARCH with TLS protocol:**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x80
   │  ├─ Direction: client (0)
   │  ├─ Byte order: MSB (1)
   │  └─ Message type: Application (0)
   ├─ Command: Search Request (0x03)
   ├─ Payload Size: 48
   ├─ Search Sequence #: 1718185572
   ├─ Mask: 0x80
   │  ├─ Reply: Optional (0)
   │  └─ Reply: Unicast (1)
   ├─ Address: 16 bytes (all zeros)
   ├─ Port: 59615
   ├─ Transport Protocols: 2 entries
   │  ├─ Transport Protocol: "tls"
   │  └─ Transport Protocol: "tcp"
   ├─ PV Count: 1
   ├─ CID: 305419896
   └─ Name: "TESTPV"
```

#### 4.1.3 Server SEARCH RESPONSE with TLS

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Search Response (0x04)
   ├─ Payload Size: 47
   ├─ GUID: 12 bytes (server identifier)
   ├─ Search Sequence #: 1235
   ├─ Address: 16 bytes (server address)
   ├─ Port: 5076
   ├─ Transport Protocol: "tls"
   ├─ Found: True
   └─ CID: 102 (found PV)
```

### 4.2 Connection / Security

|  Cmd | Dir          | Name                      | Purpose                              |
|-----:|--------------|---------------------------|--------------------------------------|
| `01` | S→C then C→S | **Connection Validation** | Negotiate buffer sizes & auth method |
| `05` | Either       | **AuthNZ**                | Extra auth hand‑shake frames         |
| `06` | S→C          | **ACL Change** _(rare)_   | Dynamic permission update            |
| `09` | C→S          | **Connection Validated**  | Final "auth OK/FAIL" status          |

#### 4.2.1 Client CONNECTION VALIDATION with AUTHZ

**Without X.509 (simple authentication):**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Connection Validation (0x01)
   ├─ Payload Size: 38
   ├─ Client Queue Size: 16384
   ├─ Client Introspection registry size: 512
   ├─ Client QoS: 0x0000
   ├─ AuthZ Flags: 0x01
   └─ AuthZ Entry 1
      ├─ AuthZ account: "controls"
      └─ AuthZ method: "ca"
```

**With X.509 (certificate authentication):**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Connection Validation (0x01)
   ├─ Payload Size: 67
   ├─ Client Queue Size: 16384
   ├─ Client Introspection registry size: 512
   ├─ Client QoS: 0x0000
   ├─ AuthZ Flags: 0x02
   ├─ AuthZ Entry 1
   │  ├─ AuthZ name: "operator"
   │  └─ AuthZ method: "ca"
   └─ AuthZ Entry 2
      └─ AuthZ method: "x509"
```

#### 4.2.2 Server CONNECTION VALIDATED with AUTHZ

**Without X.509 (simple authentication success):**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Connection Validated (0x09)
   ├─ Payload Size: 28
   ├─ Status: OK (0xFF)
   ├─ AuthZ Flags: 0x01
   └─ AuthZ Entry 1
      ├─ AuthZ name: "anonymous"
      └─ AuthZ method: "ca"
```

**With X.509 (certificate authentication success):**

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Connection Validated (0x09)
   ├─ Payload Size: 45
   ├─ Status: OK (0xFF)
   ├─ AuthZ method: "x509"
   ├─ AuthZ host: "server.facility.org"
   ├─ AuthZ authority: "CA=facility.org"
   ├─ AuthZ isTLS: 1
   ├─ AuthZ Flags: 0x02
   ├─ AuthZ Elem-cnt: 1
   └─ AuthZ Entry 1
      └─ AuthZ method: "x509"
```

### 4.3 Channel Lifecycle

|  Cmd | Dir       | Name                | Key fields in body                                       |
|-----:|-----------|---------------------|----------------------------------------------------------|
| `07` | C→S / S→C | **Create Channel**  | N× {clientCID, PV name} → {clientCID, serverCID, status} |
| `08` | Either    | **Destroy Channel** | serverCID, clientCID                                     |
| `0F` | C→S       | **Destroy Request** | serverCID, requestID                                     |
| `15` | C→S       | **Cancel Request**  | serverCID, requestID                                     |

#### 4.3.1 Client CREATE_CHANNEL Request

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Create Channel (0x07)
   ├─ Payload Size: 35
   ├─ CID: 202
   └─ Name: "PV:pressure"
```

#### 4.3.2 Server CREATE_CHANNEL Response

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Create Channel (0x07)
   ├─ Payload Size: 17
   ├─ Client Channel ID: 201
   ├─ Server Channel ID: 1005
   └─ Status: OK (0xFF)
```

### 4.4 Channel Operations 
|  Cmd | Purpose                        | Description                                                                                  |
|-----:|--------------------------------|----------------------------------------------------------------------------------------------|
| `02` | **Echo** (app‑layer)           | Raw user bytes echoed back by peer                                                           |
| `0A` | **Channel Get**                | `INIT` → type info, <br>`EXEC` → `ChangedBitSet` + data                                      |
| `0B` | **Channel Put**                | `INIT` → type info, <br>`EXEC` → data                                                        |
| `0C` | **Channel Put‑Get**            | Combined put args → result data                                                              |
| `0D` | **Monitor**                    | `INIT` <br>`UPDATE` (`ChangedBitSet` + data) ... <br>client `ACK`s with special sub‑cmd bits |
| `0E` | **Channel Array**              | `INIT`; sub‑cmd `0x00` `PUT`, `0x40` `GET`, `0x80` `SET‑LEN`                                 |
| `10` | **Channel Process**            | Fire record processing                                                                       |
| `11` | **Get Field**                  | Ask for introspection type of (sub‑)field                                                    |
| `12` | **Message** (server notices)   | {`requestID`, `severity`, `string`}                                                          |
| `13` | **Multiple Data** (deprecated) | Not emitted by PVXS                                                                          |
| `14` | **RPC**                        | `INIT` then {`args` → `results`}                                                             |

sub‑commands are in **byte 0** of payload.  Most channel operations use the following sub-commands: 
- `0x08`: INIT
- `0x00`: EXEC 
- `0x10`: DESTROY

#### 4.4.1 Client GET (INIT) NTScalar Double

**Wireshark Display:**

> Note here that the type ID's are shown with `→ 1` notation

```
└─ Process Variable Access
   ├─ Magic: 0xca
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Command: Channel Get (0x0A)
   │  ├─ Size: 487
   │  └─ Request ID: 2154848337
   ├─ Sub-command: 0x08
   ├─ Status: OK (0xff)
   └─ PVData Introspection
      └─ value (0x80: NTScalar) → 1
         ├─ value (0x43: double)
         ├─ alarm (0x80: alarm_t) → 2
         │  ├─ severity (0x22: int32_t)
         │  ├─ status (0x22: int32_t)
         │  └─ message (0x60: string)
         ├─ timeStamp (0x80: struct) → 3
         │  ├─ secondsPastEpoch (0x23: int64_t)
         │  ├─ nanoseconds (0x22: int32_t)
         │  └─ userTag (0x22: int32_t)
         ├─ display (0x80: struct) → 4
         │  ├─ limitLow (0x43: double)
         │  ├─ limitHigh (0x43: double)
         │  ├─ description (0x60: string)
         │  ├─ units (0x60: string)
         │  ├─ precision (0x22: int32_t)
         │  └─ form (0x80: enum_t) → 5
         │     ├─ index (0x22: int32_t)
         │     └─ choices[] (0x68: string[])
         ├─ control (0x80: control_t) → 6
         │  ├─ limitLow (0x43: double)
         │  ├─ limitHigh (0x43: double)
         │  └─ minStep (0x43: double)
         └─ valueAlarm (0x80: valueAlarm_t) → 7
            ├─ active (0x00: bool)
            ├─ lowAlarmLimit (0x43: double)
            ├─ lowWarningLimit (0x43: double)
            ├─ highWarningLimit (0x43: double)
            ├─ highAlarmLimit (0x43: double)
            ├─ lowAlarmSeverity (0x22: int32_t)
            ├─ lowWarningSeverity (0x22: int32_t)
            ├─ highWarningSeverity (0x22: int32_t)
            ├─ highAlarmSeverity (0x22: int32_t)
            └─ hysteresis (0x20: int8_t)

```

#### 4.4.2 Client GET Simple Scalar Byte

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Channel Get (0x0A)
   ├─ Payload Size: 10
   ├─ Server Channel ID: 1006
   ├─ Request ID: 1002
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ Status: OK (0xFF)
   ├─ BitSet: 0 (full value)
   └─ PVData
      └─ value (0x24: uint8_t): 42
```

#### 4.4.3 Client PUT Simple Scalar Integer

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x00
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Channel Put (0x0B)
   ├─ Payload Size: 13
   ├─ Request ID: 1003
   ├─ Server Channel ID: 1007
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ BitSet: 0 bytes (full value update)
   └─ PVData
      └─ value (0x22: int32_t): 1234
```

---

## 5. Status & Error Model

Every **response** (and many unsolicited server messages) carry a *pvStatus* structure:

| Field   | Type   | Notes                               |
|---------|--------|-------------------------------------|
| code    | int32  | `0` OK, `-11` == "cancelled" (etc.) |
| message | string | Optional human text                 |
| stack   | string | Optional server stack trace         |

For successful Get/Monitor updates the status header is often omitted (implicit *OK*).

---

## 6. PVData Payload Representation

All application messages whose payload carries data (or introspection) use the **PVData serialization format**. PVData consists of two layers that can appear together or separately:

1. **Type descriptor** (**FieldDesc tree**) – one‑time hierarchical description of the structure and element types.
2. **Value data** (**PVField values**) – an ordered stream of the actual runtime values, encoded according to the descriptor.

Either layer may be omitted when the peer already caches that information (see the *type cache* rules below).


### 6.1 Variable‑length primitives used everywhere

| Name         | Purpose                  | Encoding rule                                                                                          |
|--------------|--------------------------|--------------------------------------------------------------------------------------------------------|
| **Size**     | Element or String length | 3-tier encoding: 1 byte (0x00-0xFE), 5 bytes (0xFF + 4-byte), or 13 bytes (0xFF + 0x7FFFFFFF + 8-byte) |
| **Selector** | Union element index      | Same as *Size* but value `0xFF` → *empty* union                                                        |
| **BitSet**   | "changed‑fields" bitmap  | *Size* (#bytes) followed by packed little‑endian bytes of the bitmap                                   |

#### 6.1.1 Size Encoding Details

The **Size** encoding uses a 3-tier scheme to efficiently represent values from 0 to 2^63-1:

| First byte on wire                   | Total bytes on wire | Value range represented                   | Notes                                                                                              |
|--------------------------------------|---------------------|-------------------------------------------|----------------------------------------------------------------------------------------------------|
| `0x00` … `0xFE`                      | 1 byte              | 0 – 254                                   | Value is the byte itself                                                                           |
| `0xFF` + 4-byte N                    | 5 bytes             | 255 – 2,147,483,646                       | N is signed 32-bit little-endian; MUST be < 2^31-1                                                 |
| `0xFF` + `0x7FFFFFFF` + <br>8-byte L | 13 bytes            | 2,147,483,647 – 9,223,372,036,854,775,807 | The 4-byte sentinel `0x7FFFFFFF` says "size continues in 64-bit". L is signed 64-bit little-endian |

**Key points:**
- All meta-types (BitSet, union selector, etc.) that are "encoded as a Size" inherit this same 3-tier scheme
- `0xFF 0xFF 0x00 0x00 0x00 0x00` indicates an empty Union in a Union Selector

> *Strings* use **Size + UTF‑8 bytes**.  
> *Arrays* use **Size + payload elements**.

### 6.2 Encoding Rules

* 16‑, 32‑, 64‑bit scalars follow the negotiated byte order.
* **Strings** – Size field + UTF‑8 bytes (no NUL terminator).
* **Arrays** – Size (#elements) followed by packed elements (unless otherwise noted for _Search_ 16‑bit counts).
* **BitSet** – Size (#bytes), then packed little‑endian bytes of the bitmap.

Alignment: Except for segmentation padding, structures are packed; there is **no implicit padding** between successive fields.

---

## 7. Introspection

### 7.1 Why introspection exists

PVAccess allows arbitrary, nested pvData structures. To avoid resending the same type description every time,
the sender assigns a 16‑bit type‑ID and sends the full description, once. Later messages can refer to the same
type with the much shorter "ID‑only" form. 

The rules are normative: a sender must send the full form before the first `ID‑only` reference, and the mapping is per connection and per direction.

> **Type Code Processing**: 
> - Values < `0xDF` (`TYPE_CODE_RAW`) are direct `fieldDesc` bytes analyzed using bit operations
> - Values ≥ `0xDF` are special introspection codes that reference the Field Registry system 

| Lead byte(s)                        | Name                     | Payload that follows                                                                |
|-------------------------------------|--------------------------|-------------------------------------------------------------------------------------|
| `0xFF`                              | `TYPE_CODE_NULL`         | Nothing. Means "no introspection here (and no user data that would need it)".       |
| `0xFE` `<id>`                       | `TYPE_CODE_ONLY_ID`      | 2‑byte id                                                                           | 
| `0xFD` `<id>` `<FieldDesc>`         | `TYPE_CODE_FULL_WITH_ID` | 2‑byte id then the complete FieldDesc tree.                                         | 
| `0xFC` `<id>` `<tag>` `<FieldDesc>` | `TYPE_CODE_TAGGED_ID`    | As above plus a 32‑bit tag used only on lossy transports.                           |
| `0x00` ... `0xDF`                   | `TYPE_CODE_RAW`          | Stand‑alone FieldDesc with no ID (rare in TCP; mainly inside Variant‑Union values). |

#### 7.1.1 Where each form is seen in PVAccess messages

##### 7.1.1.1  `INIT` responses (server → client)

| Command                  | Message                    | Field that carries introspection                 | Typical first send                          | 
|--------------------------|----------------------------|--------------------------------------------------|---------------------------------------------|
| Channel GET              | channelGetResponseInit     | pvStructureIF                                    | TYPE_CODE_FULL_WITH_ID                      | 
| Channel PUT              | channelPutResponseInit     | pvPutStructureIF                                 | TYPE_CODE_FULL_WITH_ID                      |
| Channel PUT‑GET          | channelPutGetResponseInit  | pvPutStructureIF, pvGetStructureIF               | TYPE_CODE_FULL_WITH_ID                      |
| Channel MONITOR          | channelMonitorResponseInit | pvStructureIF                                    | TYPE_CODE_FULL_WITH_ID                      | 
| Channel ARRAY            | channelArrayResponseInit   | pvArrayIF                                        | TYPE_CODE_FULL_WITH_ID                      | 
| Channel PROCESS          | channelProcessResponseInit | (none – only status)                             |                                             |
| Get‑Field (command 0x11) | channelGetFieldResponse    | subFieldIF                                       | TYPE_CODE_FULL_WITH_ID or TYPE_CODE_ONLY_ID | 
| Beacon / Validation      | serverStatusIF, etc.       | May be NULL_TYPE_CODE if server sends no status. |                                             |


- Complex payloads start with a **FieldDesc tree** that fully describes the `PVStructure` or `PVScalarArray` layout.  
- The descriptors are **interned** per connection; both sides cache them by integer `<id>` to avoid resending.  
- Whenever a sender wishes to refer to an already‑sent layout, it can send the compact `TYPE_CODE_ONLY_ID` form instead of repeating the full tree.

##### 7.1.1.2  Data responses (`GET`, `MONITOR` updates, `ARRAY` slices…)

Once the type has been established, data‑bearing messages include no introspection at all.
They start directly with:

```text
BitSet changedBitSet   // `GET` & `MONITOR`
PVField valueData      // encoded per FieldDesc already cached
(optional BitSet overrunBitSet)
```

> For these messages we must look up the cached `FieldDesc` using the `type‑ID` that was assigned in the corresponding `INIT` step.  
> Then we will know the field name and type (so how many bytes to pull and how to display them).  
> The bit-set will show us what fields to get from the cached info and therefore how to decode the bytes that follow.   

##### 7.1.1.3 Requests originating from the client

If the client needs to embed a pvRequest structure (e.g., filter options), it follows the same rules: send `TYPE_CODE_FULL_WITH_ID` the first time, then `TYPE_CODE_ONLY_ID` in subsequent identical requests.

##### 7.1.1.4 Bitsets

Bitsets are encoded with a size in bytes followed by the actual bytes of the bitset. They represent a depth-first traversal
of the PVData with LSB-first bit ordering within each byte. See Section 9 for detailed BitSet processing logic. 

## 8. TypeCode System

Each node in a **FieldDesc tree** begins with **one opaque byte** called a `TypeCode`.
The PVA dissector determines field types by examining specific bit patterns within this byte rather than relying on exact hex value lookups.

### 8.1 Type Code Classification

The implementation uses bit masking operations to classify type codes into several categories:

**Special Introspection Type Codes** (handled first):
```lua
TYPE_CODE_NULL = 0xFF           -- NULL_TYPE: null field
TYPE_CODE_ONLY_ID = 0xFE        -- TYPE_CODE_ONLY_ID: 0xFE + ID (2 bytes)  
TYPE_CODE_FULL_WITH_ID = 0xFD   -- TYPE_CODE_FULL_WITH_ID: 0xFD + ID (2 bytes) + FieldDesc
TYPE_CODE_TAGGED_ID = 0xFC      -- FULL_TAGGED_ID: 0xFC + ID (2 bytes) + tag
TYPE_CODE_RAW = 0xDF            -- Boundary for raw FieldDesc
```

**Field Type Classification** (for codes < 0xDF):
The dissector uses bit operations to determine the field kind:

| Bit Pattern | Kind    | Detection Function                  |
|-------------|---------|-------------------------------------|
| `000xxxxx`  | Boolean | `bit.band(type_code, 0xE0) == 0x00` |
| `001xxxxx`  | Integer | `bit.band(type_code, 0xE0) == 0x20` |
| `010xxxxx`  | Float   | `bit.band(type_code, 0xE0) == 0x40` |
| `011xxxxx`  | String  | `bit.band(type_code, 0xE0) == 0x60` |
| `100xxxxx`  | Complex | `bit.band(type_code, 0xE0) == 0x80` |

### 8.2 TypeCode Bit Layout

Every **FieldDesc** byte (< 0xDF) uses the following bit layout:

```
b7 b6 b5 b4 b3 b2 b1 b0
└─┬────┘ └─┬─┘ └─┬────┘
  │        │     └─────→ Kind‑specific details
  │        └───────────→ Array (00=Scalar, 01=Variable, 10=Bounded, 11=Fixed)
  └────────────────────→ Kind (000=Bool, 001=Int, 010=Float, 011=String, 100=Complex)
```

### 8.3 Type-Specific Bit Analysis

**Integer Types** (when `kind == 001`):

```
 001  b4 b3 b2  b1 b0
└─┬─┘ └─┬─┘ └┬┘ └─┬─┘
  │     │    │    └─→ Size (00=8bit, 01=16bit, 10=32bit, 11=64bit)
  │     │    └──────→ Sign (0=signed, 1=unsigned)
  │     └───────────→ Array
  └─────────────────→ Int
```

**Float Types** (when `kind == 010`):

```
 010  b4 b3 b2 b1 b0
└─┬─┘ └─┬─┘ └─┬───┘
  │     │     └─────→ Size (10=32bit float, 11=64bit double)
  │     └───────────→ Array
  └─────────────────→ Floating point
```

**Complex Types** (when `kind == 100`):

```
 100  b4 b3 b2 b1 b0
└─┬─┘ └─┬─┘ └─┬───┘
  │     │     └─────→ Variant (000=struct, 001=union, 010=any, 011=bounded_string)
  │     └───────────→ Array
  └─────────────────→ Complex
```

### 8.4 Field Registry and Type Caching

The dissector implements a sophisticated **Field Registry** system to cache type definitions:

**Registry Structure**:
```lua
FieldRegistry = {
    data = {},    -- map of request_id -> field_id -> Field
    roots = {}    -- map of request_id -> root Field
}
```

**Special Type Code Processing**:
1. **`TYPE_CODE_FULL_WITH_ID` (0xFD)**: Decode full field definition and store with ID
2. **`TYPE_CODE_ONLY_ID` (0xFE)**: Retrieve cached field definition by ID
3. **`TYPE_CODE_NULL` (0xFF)**: Null field (skip)
4. **Raw FieldDesc** (< 0xDF): Direct field definition

### 8.5 Standard Type Codes (Common Examples)

Some common type codes decode as:

**0x22 (int32_t)**:
```
 b7  b6  b5    b4  b3    b2  b1  b0
  0   0   1     0   0     0   1   0    = 0x22
┌───────────┐ ┌───────┐  ┌─┐ ┌───────┐
│  001=Int  │ │00=Scal│  │0│ │10=32b │
└───────────┘ └───────┘  └─┘ └───────┘
   Integer     Scalar   Signed  32-bit
```

**0x43 (double)**:
```
 b7  b6  b5    b4  b3    b2  b1  b0
  0   1   0     0   0     0   1   1    = 0x43
┌───────────┐ ┌───────┐ ┌───────────┐
│ 010=Float │ │00=Scal│ │ 011=64bit │
└───────────┘ └───────┘ └───────────┘
   Float      Scalar     Double
```

**0x80 (struct)**:
```
 b7  b6  b5    b4  b3    b2  b1  b0
  1   0   0     0   0     0   0   0    = 0x80
┌───────────┐ ┌───────┐ ┌───────────┐
│100=Complex│ │00=Scal│ │000=struct │
└───────────┘ └───────┘ └───────────┘
   Complex    Scalar     Struct
```

**0x88 (struct[])**:
```
 b7  b6  b5    b4  b3    b2  b1  b0
  1   0   0     0   1     0   0   0    = 0x88
┌───────────┐ ┌───────┐ ┌───────────┐
│100=Complex│ │01=Var │ │000=struct │
└───────────┘ └───────┘ └───────────┘
   Complex    Variable   Struct
               Array
```

### 8.6 Field Display Format

Fields are displayed using a standardized format implemented in the `formatField` function:

**Format**: `field_name (0xHH: type_name)`

Where:
- `field_name`: Field name or "value" if unspecified
- `0xHH`: Hexadecimal type code  
- `type_name`: Resolved type name (with Normative Type abbreviations)

**Examples**:
```
value (0x22: int32_t)
alarm (0x80: alarm_t) → 2
timeStamp[] (0x88: time_t[])
choices (0x68: string[])
```

**Type ID Annotations**:
- `→ N`: Field definition stored in registry with ID N

### 8.7 Implementation Details: Type Code Processing

The PVA dissector implements a multi-stage type code analysis system:

**Stage 1: Special Type Code Detection**
```lua
-- Check for special introspection codes first
if isNull(type_code) then return nil end
if isOnlyId(type_code) then 
    -- Retrieve from Field Registry
    field = FieldRegistry:getField(request_id, field_id)
end
if isFullWithId(type_code) then
    -- Decode and store in Field Registry  
    field = FieldRegistry:addField(name, field_desc, type_id, len, parent_field, request_id, field_id)
end
```

**Stage 2: Bit-Based Field Analysis** (for raw FieldDesc < 0xDF)
```lua
-- Extract field kind using upper 3 bits
local kind = bit.band(type_code, 0xE0)
-- Extract array information using bits 4-3  
local array_type = bit.band(type_code, 0x18)
-- Extract type-specific details using lower bits
local details = bit.band(type_code, 0x07)
```

**Stage 3: Field Registry Management**
- Complex fields trigger recursive sub-field processing
- All fields are indexed depth-first for BitSet correlation
- Type definitions are cached per request_id to avoid re-transmission

**Stage 4: Wireshark Display Integration**
- Field names formatted as `field_name (0xHH: type_name)`
- Registry annotations: `→ N` (store), `← N` (retrieve)
- Automatic Normative Type abbreviation (e.g., "NTScalar" vs "epics:nt/NTScalar:1.0")

---

## 9. BitSet Processing and Field Selection

### 9.1 BitSet Processing Logic

The dissector implements straightforward bitset processing with simple expansion rules for complex fields.

**BitSet Expansion Logic**:
```lua
function FieldRegistry:fillOutIndexes(request_id, bitset_str)
    -- For each set bit representing a complex field:
    -- Force all direct non-complex subfields to be included
end
```

**Rule**: When a bit is set that corresponds to a complex field (structure), 
all subfields (recursively) of that structure are automatically forced to be included.

**Bit Ordering**: Bits are processed in depth-first order with LSBit-first within each byte:
```
Input bytes:                        0                         1                         2                         3
Input bit positions:   [00 01 02 03 04 05 06 07] [08 09 10 11 12 13 14 15] [16 17 18 19 20 21 22 23] [24 25 26 27 28 29 30 31]
                                    │                         │                         │                         │
Maps to output bits:   "07 06 05 04 03 02 01 00" "15 14 13 12 11 10 09 08" "23 22 21 20 19 18 17 16" "31 30 29 28 27 26 25 24"
                                    │                         │                         │                         │
Byte order in string:               0                         1                         2                         3
```

### 9.2 Field Indexing

Fields are indexed using depth-first traversal starting from index 0 (root field):

```text
0 root (NTScalar)
1 ├─ value (double)
2 ├─ alarm (structure)
3 │  ├─ severity (int32_t)
4 │  ├─ status (int32_t) 
5 │  └─ message (string)
6 ├─ timeStamp (structure)
7 │  ├─ secondsPastEpoch (int64_t)
8 │  ├─ nanoseconds (int32_t)
9 │  └─ userTag (int32_t)
. ├─ display        (structure)
  │  ├ 
  │
. ├─ control        (structure)
  │  ├ 
  │
. ├─ valueAlarm     (structure)
  │  ├ 
  │
```

**Simple BitSet Expansion**: When bit 2 (alarm struct) is set, the dissector automatically forces inclusion of bits 3-5 (severity, status, message) since they are direct non-complex children of the alarm structure.

### 9.3 Wireshark Display Integration

**BitSet Display**:
```
└─ Changed BitSet (1 byte): 010000100
```

Shows received bitset. In this example (reading bits from left to right), 
 - bit 0 (root) not set so no children are forced 
 - bit 1 (value) indicates that value is included 
 - bit 6 (timeStamp struct) forces sub-fields (secondsPastEpoch, nanoseconds, userTag) to be included.

> note that we have not shown the bits for the display, control, etc.

---

## 10. ChangedBitSet (Monitor, Get replies)

For partial‑update messages a **BitSet** precedes the value stream.
The *n*‑th bit set to `1` means "member *n* has been updated and its PVField appears in the payload".
Unset bits indicate that the receiver should reuse its cached copy of that member.
Bit numbering matches the depth‑first order of the `FieldDesc` tree.

When a complex field (structure) bit is set, all its direct non-complex subfields are automatically included.
If you wanted only individual `nanoseconds`, you would set bit 8 specifically.

### 10.1 Example of exchange using BitSet

#### 10.1.1  `MONITOR INIT` (introspection only)

```text
-- 8‑byte header -------------------------------------------------------
CA 02 40 0D   34 00 00 00       # magic, ver, flags=0x40(server‑msg), cmd, size
-- payload ------------------------------------------------------------
2A 00 00 00                     # requestID   (0x2A)
08                              # subcommand  0x08  = INIT
FF                              # Status      0xFF  = OK (no text)
FD 01 00                        # TYPE_CODE_FULL_WITH_ID, id = 1   (little‑endian)
80                              # FieldDesc lead‑byte: structure, scalar
15 "epics:nt/NTScalar:1.0"      # typeID (Size+UTF‑8)
09                              # member count = 9
   05 "value"   21              # double  (lead‑byte 0x21)
   05 "alarm"   FD 02 00 83 …   # TYPE_CODE_FULL_WITH_ID id=2  (alarm_t schema)
   09 "timeStamp" FD 03 00 83…  # TYPE_CODE_FULL_WITH_ID id=3  (timeStamp_t)
   07 "display" FD 04 00 83…    # etc.
   ...
```

The whole NTScalar description is sent once; the dissector must cache every (id → FieldDesc) found.

Wireshark display required:

```text
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0) 
   │  └─ Message type: Application (0)
   ├─ Command: MONITOR (0x0D)
   ├─ Payload Size: 52
   ├─ Server Channel ID: 1
   ├─ Sub-command: 0x08
   │  ├─ Init: Yes (1)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ Status: OK (0xFF)
   ├─ Cached Field ID: (0x0001)
   └─ PVData Introspection
      └─ value (0x80: NTScalar)
         ├─ value (0x43: double)
         ├─ alarm (0x80: alarm_t)
         │  ├─ severity (0x22: int32_t)
         │  ├─ status (0x22: int32_t)
         │  └─ message (0x60: string)
         ├─ timeStamp (0x80: time_t)
         │  ├─ secondsPastEpoch (0x23: int64_t)
         │  ├─ nanoseconds (0x22: int32_t)
         │  └─ userTag (0x22: int32_t)
```

#### 10.1.1.2 MONITOR data message (only value + `timeStamp` changed)

```text
-- header --------------------------------------------------------------
CA 02 40 0D   26 00 00 00       # payload is now 0x26 bytes
-- payload -------------------------------------------------------------
2A 00 00 00                     # requestID   (same as before)
00                              # subcommand  0x00  = DATA
01 41                           # changedBitSet
                                #   Size=1 byte, mask=01000001 (simplified)
                                #                            ^bit0 (value)
                                #                      ^bit6 (timeStamp)
40 9C C6 F7 6E 58 2D 40         # value = 12.345 (IEEE754 little‑endian)
00 00 00 00 00 60 EE 5E         # secondsPastEpoch = 1 599 999 000
00 40 27 09                     # nanoseconds      = 150 000 000
00 00 00 00                     # userTag          = 0
00                              # overrunBitSet Size=0  (no overruns)
```

We use the Request ID to look up the FieldDesc structure.  This contains the individual type IDs of the fields
indexed from 0, .. N-1.  And so we can directly use the bitmask to pull the correct field definitions.

Note: In this example all fields in timeStamp are provided because bit 6 (timeStamp struct) is set in the
`ChangedBitSet`, which forces all direct non-complex subfields (secondsPastEpoch, nanoseconds, userTag) to be included. 
Additionally, the value field is included due to bit 0 being set.

In Wireshark this should show as follows:

```text
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0) 
   │  └─ Message type: Application (0)
   ├─ Command: MONITOR (0x0D)
   ├─ Payload Size: 38
   ├─ Server Channel ID: 1
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ Status: OK (0xFF)
   ├─ Retrieved Field ID: (0x0001)
   └─ PVData
      ├─ Changed BitSet (1 byte): 01000010
      └─ value (0x80: NTScalar)
         ├─ value (0x43: double): 12.345
         └─ timeStamp (0x80: time_t)
            ├─ secondsPastEpoch (0x23: int64_t): 1599999000
            ├─ nanoseconds (0x22: int32_t): 150000000
            └─ userTag (0x22: int32_t): 0
```


---

## 11. Protocol Flow Example

### 11.1 MONITOR Request Flow

1. Client sends MONITOR request with channel ID
2. Server responds with MONITOR-INIT (subcommand 0x08) containing introspection data
3. Server sends monitor updates (subcommand 0x00) with ChangedBitSet + changed values

### 11.2 MONITOR-INIT Response Structure

In a channel monitor INIT response (subcommand 0x08), the payload layout is:

```
int32   requestID
byte    subcommand (=0x08)
Status  status        <-- 0xFF means OK, no strings follow
Field   pvStructureIF <-- only present when status==OK/WARNING
```

**Key differences from monitor updates:**
- **No ChangedBitSet** in MONITOR-INIT responses
- ChangedBitSet is only sent in regular monitor update messages (subcommand 0x00)


## 12. Normative Types (NT) — Reference Structures

The EPICS **Normative Types Specification** defines a library of standard PVStructure layouts that tools can rely on.
Below are the core NT definitions (all field names *case‑sensitive*).

### 12.1 Common auxiliary sub‑types

| Name (`id`)   | Structure layout                                                                                                    |
|---------------|---------------------------------------------------------------------------------------------------------------------|
| **alarm_t**   | `int32 severity`, `int32 status`, `string message`                                                                  |
| **time_t**    | `int64 secondsPastEpoch`, `int32 nanoseconds`, `int32 userTag`                                                      |
| **display_t** | `double limitLow`, `double limitHigh`, `double displayLow`, `double displayHigh`, `string units`, `int32 precision` |

### 12.2 Primary normative types

| Type name         | Mandatory fields                                                                                               | Optional fields                                                                                        |
|-------------------|----------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **NTScalar**      | `scalar_t value`                                                                                               | `string descriptor`, `alarm_t alarm`, <br>`time_t timeStamp`, `display_t display`, `control_t control` |
| **NTScalarArray** | `scalar_t[] value`                                                                                             | same optionals as NTScalar                                                                             |
| **NTEnum**        | `string[] choices`, `int32 index`                                                                              | `string descriptor`, `alarm_t alarm`, `time_t timeStamp`                                               |
| **NTMatrix**      | `double[] value`, `int32[] dim`                                                                                | `alarm_t`, `time_t`, `display_t`                                                                       |
| **NTNameValue**   | `string[] name`, `any[] value`                                                                                 | —                                                                                                      |
| **NTTable**       | `string[] labels`, `any[][] value`                                                                             | —                                                                                                      |
| **NTURI**         | `string scheme`, `string authority`, `string path`, `string query`                                             | —                                                                                                      |
| **NTNDArray**     | `uint8[] value`, `dimension_t[] dimension`,<br> `time_t timeStamp`, `alarm_t alarm`, `attribute_t[] attribute` | many others (uniqueID, codec, ... see spec)                                                            |
| **NTAttribute**   | `string name`, `any value`, `string tags`                                                                      | `alarm_t`, `time_t`                                                                                    |
| **NTHistogram**   | `double[] ranges`, `double[] value`                                                                            | `descriptor/alarm/timeStamp/display`                                                                   |
| **NTAggregate**   | `double[] aggValue`, `string[] aggrName`                                                                       | …                                                                                                      |

> Each "_t" reference above is itself a structure defined in the spec and serialized using the same rules (TypeDesc + value).

### 12.3 NTScalar Wire Format Example

An NTScalar structure would be encoded as:

| Description                          | Protocol                       | ...                | ...                       |
|--------------------------------------|--------------------------------|--------------------|---------------------------|
| TypeCode: struct                     | `0x80`                         |                    |                           |
| Type ID (Size=22 + UTF-8 string)     | `0x16` `epics:nt/NTScalar:1.0` |                    |                           |
| Field count: 6 fields                |                                | `0x06`             |                           |
| Field name (Size=5 + UTF-8 string)   |                                | `0x05` `value`     |                           |
| Field type: uint32_t                 |                                | `0x26`             |                           |
| Field name (Size=5 + UTF-8 string)   |                                | `0x05` `alarm`     |                           |
| Field type: struct                   |                                | `0x80`             |                           |
| Type ID:                             |                                | `0x07` `alarm_t`   |                           |
| Field count: 3 fields                |                                |                    | `0x03`                    |
| Field name (Size=8 + UTF-8 string)   |                                |                    | `0x08` `severity`         |
| Field type: int32_t                  |                                |                    | `0x22`                    |
| Field name (Size=6 + UTF-8 string)   |                                |                    | `0x06` `status`           |
| Field type: int32_t                  |                                |                    | `0x22`                    |
| Field name (Size=7 + UTF-8 string)   |                                |                    | `0x07` `message`          |
| Field type: string                   |                                |                    | `0x60`                    |
| Field name (Size=9 + UTF-8 string)   |                                | `0x09` `timeStamp` |                           |
| Field type: struct                   |                                | `0x80`             |                           |
| Type ID (Size=6 + UTF-8 string)      |                                | `0x06` `time_t`    |                           |
| Field count: 3 fields                |                                |                    | `0x03`                    |
| Field name (Size=17 + UTF-8 string)  |                                |                    | `0x11` `secondsPastEpoch` |
| Field type: int64_t                  |                                |                    | `0x23`                    |
| Field name (Size=11 + UTF-8 string)  |                                |                    | `0x0B` `nanoseconds`      |
| Field type: int32_t                  |                                |                    | `0x22`                    |
| Field name (Size=7 + UTF-8 string)   |                                |                    | `0x07` `userTag`          |
| Field type: int32_t                  |                                |                    | `0x22`                    |
| etc - (descriptor, display, control) |                                |                    |                           |

**Wireshark Display:**
```
└─ PVData Introspection
   └─ value (0x80: NTScalar)
      ├─ value (0x43: double)
      ├─ alarm (0x80: alarm_t)
      │  ├─ severity (0x22: int32_t)
      │  ├─ status (0x22: int32_t)
      │  └─ message (0x60: string)
      ├─ timeStamp (0x80: time_t)
      │  ├─ secondsPastEpoch (0x23: int64_t)
      │  ├─ nanoseconds (0x22: int32_t)
      │  └─ userTag (0x22: int32_t)
```

Normative‑type instances declare themselves by sending a `FieldDesc` whose **top‑level ID string** equals the NT name (e.g. `"epics:nt/NTScalar:1.0"`) so that generic GUIs can recognise and render them automatically.

### 12.4 Key Points

- **NTScalar value field**: Can contain either a scalar OR an array (scalar_t can be any basic type or array type)
- **Arrays are fundamental**: Arrays are a core part of the protocol, not an extension
- **EPICS Epoch**: 1990-01-01 00:00:00 UTC for timeStamp calculations

---

## 13. Array Support

Arrays are fundamental to PVA protocol design. All basic types can be arrays:
- `byte[]`, `int[]`, `double[]`, `string[]`, etc.
- Arrays include Size information
- Arrays are encoded as Size (#elements) + packed elements

---

## 14. Inter‑operability Notes

* The dissector supports all standard PVA array types: variable, bounded, and fixed arrays. Array types are determined by bits 4-3 of the TypeCode using bitwise operations.
* A single TCP connection may carry **multiple cached type trees**; each tree is keyed by the server‑assigned *TypeCache ID* (16‑bit).
* **ChangedBitSet + value** pairs are always aligned directly after the status field—there is no padding beyond the segmentation rules described in Section 1.
* Scalar values are transmitted in **native IEEE**; PVAccess performs no NaN canonicalisation—dissectors should preserve bit‑patterns.

---

## 15. Command Reference

### 15.1 Complete Command Code Table

| Hex | Name                       | Description                    |
|----:|----------------------------|--------------------------------|
|  00 | Beacon                     | Server beacon message          |
|  01 | Connection Validation      | Connection validation          |
|  02 | Echo (application)         | Echo request/response          |
|  03 | Search Request             | Search for channel names       |
|  04 | Search Response            | Response to search request     |
|  05 | AuthNZ                     | Authentication/authorization   |
|  06 | ACL Change                 | Access control list change     |
|  07 | Create Channel             | Create channel request         |
|  08 | Destroy Channel            | Destroy channel request        |
|  09 | Connection Validated       | Connection validation response |
|  0A | Channel Get                | Get request                    |
|  0B | Channel Put                | Put request                    |
|  0C | Channel Put‑Get            | Put-get request                |
|  0D | Monitor                    | Monitor request (subscription) |
|  0E | Channel Array              | Array put request              |
|  0F | Destroy Request            | Destroy request                |
|  10 | Channel Process            | Process request                |
|  11 | Get Field                  | Get field request              |
|  12 | Message (server → client)  | Generic message                |
|  13 | Multiple Data (deprecated) | Multiple data message          |
|  14 | RPC                        | Remote procedure call          |
|  15 | Cancel Request             | Cancel request                 |
|  16 | Origin Tag                 | Origin tag                     |

---

## References

1. EPICS 7 Process Variable Access Protocol Specification
2. EPICS Normative Types Specification
3. PVAccessCPP source code (GitHub: epics-base/PVAccessCPP)
4. EPICS Base 7 Channel Access vs PV Access comparison
5. Captured network traffic analysis (July 2025)
6. PVXS Protocol Documentation (GitHub: epics-base/pvxs)
7. PVXS Source Implementation (epics-base/pvxs)

```
