# pvashark

Wireshark Lua script plugin packet disector for PV Access protocol

Builds on work by mdagidaver in https://github.com/mdavidsaver/cashark

This repo extends support to all PVData, and Normative Data Types.

# EPICS PVAccess — Wire Protocol Specification

This document describes the PVAccess wire protocol used by EPICS 7 for process variable communication (PV Access). The protocol supports complex structured data types called Normative Types (NT) and provides more sophisticated data handling than traditional Channel Access.

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
      ├─ AuthZ name: "CN=client.facility.org"
      ├─ AuthZ method: "x509"
      └─ AuthZ response: "certificate_valid"
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
|  Cmd | Purpose                        | Description                                                                               |
|-----:|--------------------------------|-------------------------------------------------------------------------------------------|
| `02` | **Echo** (app‑layer)           | Raw user bytes echoed back by peer                                                        |
| `0A` | **Channel Get**                | INIT → type info, exec → ChangedBitSet + data                                             |
| `0B` | **Channel Put**                | INIT → type info, exec → data                                                             |
| `0C` | **Channel Put‑Get**            | Combined put args → result data                                                           |
| `0D` | **Monitor**                    | INIT then stream of updates (ChangedBitSet + data); client ACKs with special sub‑cmd bits |
| `0E` | **Channel Array**              | INIT; sub‑cmd `0x00` PUT, `0x40` GET, `0x80` SET‑LEN                                      |
| `10` | **Channel Process**            | Fire record processing                                                                    |
| `11` | **Get Field**                  | Ask for introspection type of (sub‑)field                                                 |
| `12` | **Message** (server notices)   | {requestID, severity, string}                                                             |
| `13` | **Multiple Data** (deprecated) | Not emitted by PVXS                                                                       |
| `14` | **RPC**                        | INIT then {args → results}                                                                |

sub‑commands are in **byte 0** of payload.  Most channel operations use the following sub-commands: 
- `0x08`: INIT
- `0x00`: EXEC 
- `0x10`: DESTROY

#### 4.4.1 Client GET NTScalar Double

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
   ├─ Payload Size: 9
   ├─ Server Channel ID: 1005
   ├─ Operation ID: 1001
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   └─ value (0x0E: NTScalar)
      ├─ value (0x0B: float64): 
      ├─ alarm (0x0D: alarm_t) 
      │  ├─ severity (0x04: int32_t): 
      │  ├─ status (0x04: int32_t):  
      │  └─ message (0x0C: string):  
      └─ timeStamp (0x0D: time_t) 
         ├─ secondsPastEpoch (0x05: int64_t): 
         ├─ nanoseconds: (0x04: int32_t): 
         └─ userTag (0x04: int32_t): 
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
   ├─ Operation ID: 1002
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ Status: OK (0xFF)
   ├─ BitSet: 0 bytes (full value)
   └─ value (0x06: uint8_t): 42
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
   └─ value (0x04: int32_t): 1234
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

| Name         | Purpose                  | Encoding rule                                                                                                        |
|--------------|--------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Size**     | Element or string length | 1 byte if `<254`; byte `0xFE` then 32‑bit LE length if `≥254`; byte `0xFF` may be used by Java to mean *null* string |
| **Selector** | Union element index      | Same as *Size* but value `0xFF` → *empty* union                                                                      |
| **BitSet**   | "changed‑fields" bitmap  | *Size* (#bytes) followed by packed little‑endian bytes of the bitmap                                                 |

> *Strings* use **Size + UTF‑8 bytes**.  
> *Arrays* use **Size + payload elements**.

### 6.2 Encoding Rules

* 8‑, 16‑, 32‑, 64‑bit scalars follow the negotiated byte order.
* **Strings** – Size field + UTF‑8 bytes (no NUL terminator).
* **Arrays** – Size (#elements) followed by packed elements (unless otherwise noted for _Search_ 16‑bit counts).
* **BitSet** – Size (#bytes), then packed little‑endian bytes of the bitmap.

Alignment: Except for segmentation padding, structures are packed; there is **no implicit padding** between successive fields.

---

## 7. Introspection (Type Descriptors = FieldDesc)

Complex payloads start with a **FieldDesc tree** that fully describes the PVStructure or PVScalarArray layout.  
The descriptors are **interned** per connection; both sides cache them by integer **IF‑ID** to avoid resending.  
Whenever a sender wishes to refer to an already‑sent layout it can send the compact "`<<int id>>`" form instead of repeating the full tree.

### 7.1 TypeCode System

Each node in a **FieldDesc tree** begins with **one opaque byte** `TypeCode`.
The PVXS implementation maps these bytes exactly to the EPICS pvData enumeration:

#### 7.1.1 Standard Type Codes

|   Code | Kind             | Array code | Size | Description                       |
|-------:|------------------|-----------:|------|-----------------------------------|
| `0x00` | **null**         |          — | 0    | Special terminator                |
| `0x01` | **bool**         |     `0x11` | 1    | Boolean (0/1)                     |
| `0x02` | **int8_t**       |     `0x12` | 1    | Signed 8‑bit integer              |
| `0x03` | **int16_t**      |     `0x13` | 2    | Signed 16‑bit integer             |
| `0x04` | **int32_t**      |     `0x14` | 4    | Signed 32‑bit integer             |
| `0x05` | **int64_t**      |     `0x15` | 8    | Signed 64‑bit integer             |
| `0x06` | **uint8_t**      |     `0x16` | 1    | Unsigned 8‑bit integer            |
| `0x07` | **uint16_t**     |     `0x17` | 2    | Unsigned 16‑bit integer           |
| `0x08` | **uint32_t**     |     `0x18` | 4    | Unsigned 32‑bit integer           |
| `0x09` | **uint64_t**     |     `0x19` | 8    | Unsigned 64‑bit integer           |
| `0x0A` | **float32**      |     `0x1A` | 4    | IEEE‑754 32‑bit float             |
| `0x0B` | **float64**      |     `0x1B` | 8    | IEEE‑754 64‑bit double            |
| `0x0C` | **string**       |     `0x1C` | var  | UTF‑8 encoded string              |
| `0x0D` | **structure**    |     `0x2D` | —    | Composite structure               |
| `0x0E` | **union**        |     `0x2E` | —    | Discriminated union               |
| `0x0F` | **any**          |     `0x2F` | —    | "variant *any*" type              |
| `0x20` | **structure []** |          — | —    | StructArray (array of structures) |
| `0x21` | **union []**     |          — | —    | UnionArray                        |
| `0x22` | **any []**       |          — | —    | AnyArray                          |

> **Note**: The PVXS TypeCode class enumerates exactly these constants (see `src/type.cpp`).


### 7.2 FieldDesc Tree Encoding

The FieldDesc tree describes the structure of data fields. Each node follows this pattern:

| # | Field                 | Scalar | Struct/Union | Arrays | Content                             |
|---|-----------------------|--------|--------------|--------|-------------------------------------|
| 0 | **TypeCode**          | ✓      | ✓            | ✓      | 1 byte indicating the field type    |
| 1 | **Type ID**           |        | ✓            |        | String identifier for the type      |
| 1 | **Element Type**      |        |              | ✓      | Single FieldDesc for array elements |
| 2 | **Field Count**       |        | ✓            |        | Number of sub-fields (Size-encoded) |
| 3 | **Field Definitions** |        | ✓            |        | Repeated: field name + FieldDesc    |
|   | ...                   |        | ...          |        | ...                                 |

**Where:**
- **TypeCode**: Single byte from the standard type codes (0x00-0x22)
- **Type ID**: Optional string name for the structure or union type
- **Field Count**: Variable-length size indicating number of members
- **Field Definitions**: For each member: field name (string) + nested FieldDesc
- **Element Type**: For arrays: single FieldDesc describing the element type

#### 7.2.2 Encoding Examples

**Leaf Node (Scalar):**

| Description       | Protocol |
|-------------------|----------|
| TypeCode: int32_t | `0x04`   |

**Wireshark Display:**
```
└─ value (0x04: int32_t)
```

**Simple Structure:**

| Description                        | Protocol | ...                | ... |
|------------------------------------|----------|--------------------|-----|
| TypeCode: structure                | `0x0D`   | `0x08` `MyStruct`  |     |
| Type ID (Size=8 + UTF-8 string)    |          | `0x02`             |     |
| Field count: 2 fields              |          | `0x06` `field1`    |     |
| Field name (Size=6 + UTF-8 string) |          | `0x04`             |     |
| Field type: int32_t                |          | `0x06` `field2`    |     |
| Field name (Size=6 + UTF-8 string) |          | `0x0B`             |     |
| Field type: float64                |          |                    |     |

**Wireshark Display:**
```
└─ value (0x0D: MyStruct)
   ├─ field1 (0x04: int32_t):
   └─ field2 (0x0B: float64):
```

**Union:**

| Description                         | Protocol | ...                | ... |
|-------------------------------------|----------|--------------------|-----|
| TypeCode: union                     | `0x0E`   | `0x07` `MyUnion`   |     |
| Type ID (Size=7 + UTF-8 string)     |          | `0x02`             |     |
| Choice count: 2 choices             |          | `0x07` `choice1`   |     |
| Choice name (Size=7 + UTF-8 string) |          | `0x04`             |     |
| Choice type: int32_t                |          | `0x07` `choice2`   |     |
| Choice name (Size=7 + UTF-8 string) |          | `0x0C`             |     |
| Choice type: string                 |          |                    |     |

**Wireshark Display:**
```
└─ value (0x0E: MyUnion)
   ├─ choice1 (0x04: int32_t):
   └─ choice2 (0x0C: string):
```

**Nested Structure:**

| Description                        | Protocol            | ...               | ...               |
|------------------------------------|---------------------|-------------------|-------------------|
| TypeCode: structure                | `0x0D`              |                   |                   |
| Type ID (Size=9 + UTF-8 string)    | `0x09` `Container`  |                   |                   |
| Field count: 2 fields              |                     | `0x02`            |                   |
| Field name (Size=5 + UTF-8 string) |                     | `0x05` `value`    |                   |
| Field type: int32_t                |                     | `0x04`            |                   |
| Field name (Size=5 + UTF-8 string) |                     | `0x05` `alarm`    |                   |
| Field type: structure (nested)     |                     | `0x0D`            |                   |
| Type ID (Size=7 + UTF-8 string)    |                     | `0x07` `alarm_t`  |                   |
| Field count: 3 fields              |                     |                   | `0x03`            |
| Field name (Size=8 + UTF-8 string) |                     |                   | `0x08` `severity` |
| Field type: int32_t                |                     |                   | `0x04`            |
| Field name (Size=6 + UTF-8 string) |                     |                   | `0x06` `status`   |
| Field type: int32_t                |                     |                   | `0x04`            |
| Field name (Size=7 + UTF-8 string) |                     |                   | `0x07` `message`  |
| Field type: string                 |                     |                   | `0x0C`            |

**Wireshark Display:**
```
└─ value (0x0D: Container)
   ├─ value (0x04: int32_t):
   └─ alarm (0x0D: alarm_t)
      ├─ severity (0x04: int32_t):
      ├─ status (0x04: int32_t):
      └─ message (0x0C: string):
```

**Structure Array:**

| Description                        | Protocol | ...               |
|------------------------------------|----------|-------------------|
| TypeCode: structure array          | `0x20`   |                   |
| Element type: structure            | `0x0D`   | `0x05` `Point`    |
| Type ID (Size=5 + UTF-8 string)    |          | `0x02`            |
| Field count: 2 fields              |          | `0x01` `x`        |
| Field name (Size=1 + UTF-8 string) |          | `0x04`            |
| Field type: int32_t                |          | `0x01` `y`        |
| Field name (Size=1 + UTF-8 string) |          | `0x04`            |
| Field type: int32_t                |          |                   |

**Wireshark Display:**
```
└─ value (0x20: Point[])
   ├─ x (0x04: int32_t):
   └─ y (0x04: int32_t):
```

#### 7.2.3 Tree Traversal

Nodes are serialized **depth‑first**; receivers rebuild the hierarchy recursively.

FieldDesc trees are:
- **Serialized depth-first**: Children before siblings
- **Parsed recursively**: Receivers rebuild the hierarchy
- **Cached by connection**: Each connection maintains its own type cache

#### 7.2.4 Type‑cache shortcuts

To avoid re‑sending large type trees, PVXS supports the pvAccess **type‑cache op‑codes**:
- *`0xFD key FieldDesc`* → *store in cache*
- *`0xFE key`* → *reuse cached tree* (key is 16‑bit)

These are handled transparently by PVXS (`from_wire()` in `dataencode.cpp`) and rarely appear in user captures.

---

## 8. Value (PVField) Serialization

Given a `FieldDesc` the **value stream** that immediately follows is:

| Type class                | Wire encoding (per element)                                                              |
|---------------------------|------------------------------------------------------------------------------------------|
| **bool**                  | 1 byte; 0 / 1                                                                            |
| **{u,}int8**              | 1 byte two's‑complement / unsigned                                                       |
| **{u,}int16**             | 2 bytes                                                                                  |
| **{u,}int32**             | 4 bytes                                                                                  |
| **{u,}int64**             | 8 bytes                                                                                  |
| **float32**               | 4 bytes IEEE                                                                             |
| **float64**               | 8 bytes IEEE                                                                             |
| **string**                | *Size* + UTF‑8 bytes                                                                     |
| **scalar array**          | *Size* (#elems) + packed elements                                                        |
| **string array**          | *Size* (#elems) + repeated (*Size + UTF‑8*)                                              |
| **structure**             | Concatenation of each member's PVField in declaration order                              |
| **union**                 | *Selector* (−1 = empty) then the selected member's PVField                               |
| **any**                   | *TypeDesc* (or cache ref) + PVField                                                      |
| **structure/union array** | *Size* (#elems) then repeated **[Selector + PVField]** (union) or **[PVField]** (struct) |

> All multi‑byte scalars use the **byte‑order flag** negotiated in the message header.

### 8.1 Union Encoding Details

- **Selector**: Union discriminator indicating which union member is present
- **Value**: Followed by that member's data
- **Critical Finding**: Selectors are field indices, not type codes

---

## 9. ChangedBitSet (Monitor, Get replies)

For partial‑update messages a **BitSet** precedes the value stream.
The *n*‑th bit set to `1` means "member *n* has been updated and its PVField appears in the payload".
Unset bits indicate that the receiver should reuse its cached copy of that member.
Bit numbering matches the depth‑first order of the `FieldDesc` tree.

---

## 10. Protocol Flow Example

### 10.1 MONITOR Request Flow

1. Client sends MONITOR request with channel ID
2. Server responds with introspection data (type definition)
3. Server sends initial value
4. Server sends updates when value changes

### 10.2 ChannelGet Example

A minimal **ChannelGet response** for a PV of type *double* might be:

| Description                                              | Protocol                                                |
|----------------------------------------------------------|---------------------------------------------------------|
| Magic: Always 0xCA                                       | `0xCA`                                                  |
| Version: Protocol version 2                              | `0x02`                                                  |
| Flags: server→client, little-endian, application message | `0x40`                                                  |
| Command: Channel Get (0x0A)                              | `0x0A`                                                  |
| PayloadSize: 17 bytes (little-endian)                    | `0x00` `0x00` `0x00` `0x11`                             |
| RequestID: 1 (little-endian)                             | `0x00` `0x00` `0x00` `0x01`                             |
| Sub-command: regular GET                                 | `0x00`                                                  |
| Status: OK (single 0xFF byte)                            | `0xFF`                                                  |
| BitSet: 0 bytes (no changed bits, implies full value)    | `0x00`                                                  |
| TypeCode: float64                                        | `0x0A`                                                  |
| Value: IEEE-754 double 100.2                             | `0x40` `0x59` `0x0C` `0xCC` `0xCC` `0xCC` `0xCC` `0xCD` |

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x40
   │  ├─ Direction: server (1)
   │  ├─ Byte order: LSB (0) 
   │  └─ Message type: Application (0)
   ├─ Command: Channel Get (0x0A)
   ├─ Payload Size: 17
   ├─ Server Channel ID: 1
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ Status: OK (0xFF)
   ├─ BitSet: 0 bytes (no changed bits)
   └─ value (0x0A: float64): 100.2
```

The same channel, when monitored, would begin with a `Monitor‑INIT` (type tree identical), then receive periodic **server→client** messages re‑using that tree and only sending a `BitSet` + `value` when the `value` field actually changes.

### 10.3 ChannelPut Example

A **ChannelPut request** for an **established channel** where the `Point` structure array type is already known, with values `[{3.412, 12.3123}, {-12.523, 20.2012}]` would be:

| Description                                              | Protocol                    | ...                                                     | ... |
|----------------------------------------------------------|-----------------------------|---------------------------------------------------------|-----|
| Magic: Always 0xCA                                       | `0xCA`                      |                                                         |     |
| Version: Protocol version 2                              | `0x02`                      |                                                         |     |
| Flags: client→server, little-endian, application message | `0x41`                      |                                                         |     |
| Command: Channel Put (0x0B)                              | `0x0B`                      |                                                         |     |
| PayloadSize: 44 bytes (little-endian)                    | `0x00` `0x00` `0x00` `0x2C` |                                                         |     |
| RequestID: 2 (little-endian)                             | `0x00` `0x00` `0x00` `0x02` |                                                         |     |
| ChannelID: 5 (little-endian)                             | `0x00` `0x00` `0x00` `0x05` |                                                         |     |
| Sub-command: regular PUT                                 | `0x00`                      |                                                         |     |
| BitSet: 0 bytes (full value update)                      | `0x00`                      |                                                         |     |
| Array size: 2 elements                                   |                             | `0x02`                                                  |     |
| Point[0].x: IEEE-754 double 3.412                        |                             | `0x40` `0x0B` `0x4F` `0xDF` `0x3B` `0x64` `0x5A` `0x1D` |     |
| Point[0].y: IEEE-754 double 12.3123                      |                             | `0x40` `0x28` `0xA0` `0xF5` `0xC2` `0x8F` `0x5C` `0x29` |     |
| Point[1].x: IEEE-754 double -12.523                      |                             | `0xC0` `0x29` `0x0F` `0x5C` `0x28` `0xF5` `0xC2` `0x8F` |     |
| Point[1].y: IEEE-754 double 20.2012                      |                             | `0x40` `0x34` `0x33` `0xD7` `0x0A` `0x3D` `0x70` `0xA4` |     |

**Wireshark Display:**
```
└─ Process Variable Access Protocol
   ├─ Magic: 0xCA
   ├─ Version: 2
   ├─ Flags: 0x41
   │  ├─ Direction: client (0)
   │  ├─ Byte order: LSB (0)
   │  └─ Message type: Application (0)
   ├─ Command: Channel Put (0x0B)
   ├─ Payload Size: 44
   ├─ Request ID: 2
   ├─ Server Channel ID: 5
   ├─ Sub-command: 0x00
   │  ├─ Init: No (0)
   │  ├─ Destroy: No (0)
   │  └─ Process: No (0)
   ├─ BitSet: 0 bytes (full value update)
   └─ value (0x20: Point[]): 2 elements
      ├─ Point[0]
      │  ├─ x (0x0B: float64): 3.412
      │  └─ y (0x0B: float64): 12.3123
      └─ Point[1]
         ├─ x (0x0B: float64): -12.523
         └─ y (0x0B: float64): 20.2012
```

> **Note**: For new channels, the first PUT operation may include a FieldDesc (type definition). Subsequent operations on established channels can omit the type information, as shown above, for improved efficiency.

---

## 11. Normative Types (NT) — Reference Structures

The EPICS **Normative Types Specification** defines a library of standard PVStructure layouts that tools can rely on.
Below are the core NT definitions (all field names *case‑sensitive*).

### 11.1 Common auxiliary sub‑types

| Name (`id`)   | Structure layout                                                                                                    |
|---------------|---------------------------------------------------------------------------------------------------------------------|
| **alarm_t**   | `int32 severity`, `int32 status`, `string message`                                                                  |
| **time_t**    | `int64 secondsPastEpoch`, `int32 nanoseconds`, `int32 userTag`                                                      |
| **display_t** | `double limitLow`, `double limitHigh`, `double displayLow`, `double displayHigh`, `string units`, `int32 precision` |

### 11.2 Primary normative types

| Type name         | Mandatory fields                                                                                           | Optional fields                                                               |
|-------------------|------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **NTScalar**      | `scalar_t value`                                                                                           | `string descriptor`, `alarm_t alarm`, `time_t timeStamp`, `display_t display` |
| **NTScalarArray** | `scalar_t[] value`                                                                                         | same optionals as NTScalar                                                    |
| **NTEnum**        | `string[] choices`, `int32 index`                                                                          | `string descriptor`, `alarm_t alarm`, `time_t timeStamp`                      |
| **NTMatrix**      | `double[] value`, `int32[] dim`                                                                            | `alarm_t`, `time_t`, `display_t`                                              |
| **NTNameValue**   | `string[] name`, `any[] value`                                                                             | —                                                                             |
| **NTTable**       | `string[] labels`, `any[][] value`                                                                         | —                                                                             |
| **NTURI**         | `string scheme`, `string authority`, `string path`, `string query`                                         | —                                                                             |
| **NTNDArray**     | `uint8[] value`, `dimension_t[] dimension`, `time_t timeStamp`, `alarm_t alarm`, `attribute_t[] attribute` | many others (uniqueID, codec, ... see spec)                                   |
| **NTAttribute**   | `string name`, `any value`, `string tags`                                                                  | `alarm_t`, `time_t`                                                           |
| **NTHistogram**   | `double[] ranges`, `double[] value`                                                                        | `descriptor/alarm/timeStamp/display`                                          |
| **NTAggregate**   | `double[] aggValue`, `string[] aggrName`                                                                   | …                                                                             |

> Each "_t" reference above is itself a structure defined in the spec and serialized using the same rules (TypeDesc + value).

### 11.3 NTScalar Wire Format Example

An NTScalar structure would be encoded as:

| Description                           | Protocol                       | ...                | ...                       |
|---------------------------------------|--------------------------------|--------------------|---------------------------|
| TypeCode: union                       | `0x0E`                         |                    |                           |
| Type ID (Size=22 + UTF-8 string)      | `0x16` `epics:nt/NTScalar:1.0` |                    |                           |
| Union choice count: 3 choices         |                                | `0x03`             |                           |
| Choice 0 name (Size=5 + UTF-8 string) |                                | `0x05` `value`     |                           |
| Choice 0 type: int32_t                |                                | `0x04`             |                           |
| Choice 1 name (Size=5 + UTF-8 string) |                                | `0x05` `alarm`     |                           |
| Choice 1 type: structure              |                                | `0x0D`             |                           |
| Choice 1 Type ID:                     |                                | `0x07` `alarm_t`   |                           |
| Field count: 3 fields                 |                                |                    | `0x03`                    |
| Field name (Size=8 + UTF-8 string)    |                                |                    | `0x08` `severity`         |
| Field type: int32_t                   |                                |                    | `0x04`                    |
| Field name (Size=6 + UTF-8 string)    |                                |                    | `0x06` `status`           |
| Field type: int32_t                   |                                |                    | `0x04`                    |
| Field name (Size=7 + UTF-8 string)    |                                |                    | `0x07` `message`          |
| Field type: string                    |                                |                    | `0x0C`                    |
| Choice 2 name (Size=9 + UTF-8 string) |                                | `0x09` `timeStamp` |                           |
| Choice 2 type: structure              |                                | `0x0D`             | `                         |
| Type ID (Size=6 + UTF-8 string)       |                                | `0x06` `time_t`    |                           |
| Field count: 3 fields                 |                                |                    | `0x03`                    |
| Field name (Size=17 + UTF-8 string)   |                                |                    | `0x11` `secondsPastEpoch` |
| Field type: int64_t                   |                                |                    | `0x05`                    |
| Field name (Size=11 + UTF-8 string)   |                                |                    | `0x0B` `nanoseconds`      |
| Field type: int32_t                   |                                |                    | `0x04`                    |
| Field name (Size=7 + UTF-8 string)    |                                |                    | `0x07` `userTag`          |
| Field type: int32_t                   |                                |                    | `0x04`                    |

**Wireshark Display:**
```
└─ value (0x0E: NTScalar)
   ├─ value (0x04: int32_t):
   ├─ alarm (0x0D: alarm_t)
   │  ├─ severity (0x04: int32_t):
   │  ├─ status (0x04: int32_t):
   │  └─ message (0x0C: string):
   └─ timeStamp (0x0D: time_t)
      ├─ secondsPastEpoch (0x05: int64_t):
      ├─ nanoseconds (0x04: int32_t):
      └─ userTag (0x04: int32_t):
```

Normative‑type instances declare themselves by sending a `FieldDesc` whose **top‑level ID string** equals the NT name (e.g. `"epics:nt/NTScalar:1.0"`) so that generic GUIs can recognise and render them automatically.

### 11.4 Key Points

- **NTScalar value field**: Can contain either a scalar OR an array (scalar_t can be any basic type or array type)
- **Arrays are fundamental**: Arrays are a core part of the protocol, not an extension
- **EPICS Epoch**: 1990-01-01 00:00:00 UTC for timeStamp calculations

---

## 12. Array Support

Arrays are fundamental to PVA protocol design. All basic types can be arrays:
- `byte[]`, `int[]`, `double[]`, `string[]`, etc.
- Arrays include Size information
- Arrays are encoded as Size (#elements) + packed elements

---

## 13. Inter‑operability Notes

* PVXS **never transmits fixed‑length strings or fixed‑width arrays**, even though the pvData type table reserves bit 4 of the TypeCode for such encodings (they are deprecated). Receivers should still reject TypeCodes with bit 4 set.
* A single TCP connection may carry **multiple cached type trees**; each tree is keyed by the server‑assigned *TypeCache ID* (16‑bit).
* **ChangedBitSet + value** pairs are always aligned directly after the status field—there is no padding beyond the segmentation rules described in Section 1.
* Scalar values are transmitted in **native IEEE**; PVAccess performs no NaN canonicalisation—dissectors should preserve bit‑patterns.

---

## 14. Command Reference

### 14.1 Complete Command Code Table

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
3. pvAccessCPP source code (GitHub: epics-base/pvAccessCPP)
4. EPICS Base 7 Channel Access vs PV Access comparison
5. Captured network traffic analysis (July 2025)
6. PVXS Protocol Documentation (GitHub: epics-base/pvxs)
7. PVXS Source Implementation (epics-base/pvxs)
