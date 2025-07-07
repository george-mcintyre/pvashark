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
   └─ value (0x80: NTScalar)
      ├─ value (0x43: double): 
      ├─ alarm (0x80: alarm_t) 
      │  ├─ severity (0x22: int32_t): 
      │  ├─ status (0x22: int32_t):  
      │  └─ message (0x60: string):  
      ├─ timeStamp (0x80: time_t) 
      │  ├─ secondsPastEpoch (0x23: int64_t): 
      │  ├─ nanoseconds: (0x22: int32_t): 
      │  └─ userTag (0x22: int32_t): 
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

| First byte on wire               | Total bytes on wire | Value range represented                   | Notes                                                                                              |
|----------------------------------|---------------------|-------------------------------------------|----------------------------------------------------------------------------------------------------|
| `0x00` … `0xFE`                  | 1 byte              | 0 – 254                                   | Value is the byte itself                                                                           |
| `0xFF` + 4-byte N                | 5 bytes             | 255 – 2,147,483,646                       | N is signed 32-bit little-endian; MUST be < 2^31-1                                                 |
| `0xFF` + `0x7FFFFFFF` + 8-byte L | 13 bytes            | 2,147,483,647 – 9,223,372,036,854,775,807 | The 4-byte sentinel `0x7FFFFFFF` says "size continues in 64-bit". L is signed 64-bit little-endian |

**Key points:**
- All meta-types (BitSet, union selector, etc.) that are "encoded as a Size" inherit this same 3-tier scheme
- `0xFF 0xFF 0x00 0x00 0x00 0x00` indicates an empty Union in a Union Selector

> *Strings* use **Size + UTF‑8 bytes**.  
> *Arrays* use **Size + payload elements**.

### 6.2 Encoding Rules

* 8‑, 16‑, 32‑, 64‑bit scalars follow the negotiated byte order.
* **Strings** – Size field + UTF‑8 bytes (no NUL terminator).
* **Arrays** – Size (#elements) followed by packed elements (unless otherwise noted for _Search_ 16‑bit counts).
* **BitSet** – Size (#bytes), then packed little‑endian bytes of the bitmap.

Alignment: Except for segmentation padding, structures are packed; there is **no implicit padding** between successive fields.

---

## 7. Introspection

### 7.1 Why introspection exists

pvAccess allows arbitrary, nested pvData structures. To avoid resending the same type description every time,
the sender assigns a 16‑bit type‑ID and sends the full description once. Later messages can refer to the same
type with the much shorter “ID‑only” form. The rules are normative: a sender must send the full form before the first ID‑only reference, and the mapping is per connection and per direction  ￼.

| Lead byte(s)                        | Name                       | Payload that follows                                                                |
|-------------------------------------|----------------------------|-------------------------------------------------------------------------------------|
| `0xFF`                              | `NULL_TYPE_CODE`           | Nothing. Means “no introspection here (and no user data that would need it)”.       |
| `0xFE` `<id>`                       | `ONLY_ID_TYPE_CODE`        | 2‑byte id (little‑ or big‑endian = connection byte order).                          | 
| `0xFD` `<id>` `<FieldDesc>`         | `FULL_WITH_ID_TYPE_CODE`   | 2‑byte id then the complete FieldDesc tree.                                         | 
| `0xFC` `<id>` `<tag>` `<FieldDesc>` | `FULL_TAGGED_ID_TYPE_CODE` | As above plus a 32‑bit tag used only on lossy transports.                           |
| `0x00` ... `0xDF`                   | `FULL_TYPE_CODE`           | Stand‑alone FieldDesc with no ID (rare in TCP; mainly inside Variant‑Union values). |

#### 7.1.1 Where each form is seen in pvAccess messages

##### 7.1.1.1  `INIT` responses (server → client)

| Command                  | Message                    | Field that carries introspection                 | Typical first send      | 
|--------------------------|----------------------------|--------------------------------------------------|-------------------------|
| Channel GET              | channelGetResponseInit     | pvStructureIF                                    | FULL_WITH_ID            | 
| Channel PUT              | channelPutResponseInit     | pvPutStructureIF                                 | FULL_WITH_ID            |
| Channel PUT‑GET          | channelPutGetResponseInit  | pvPutStructureIF, pvGetStructureIF               | FULL_WITH_ID            |
| Channel MONITOR          | channelMonitorResponseInit | pvStructureIF                                    | FULL_WITH_ID            | 
| Channel ARRAY            | channelArrayResponseInit   | pvArrayIF                                        | FULL_WITH_ID            | 
| Channel PROCESS          | channelProcessResponseInit | (none – only status)                             |                         |
| Get‑Field (command 0x11) | channelGetFieldResponse    | subFieldIF                                       | FULL_WITH_ID or ONLY_ID | 
| Beacon / Validation      | serverStatusIF, etc.       | May be NULL_TYPE_CODE if server sends no status. |                         |


Complex payloads start with a **FieldDesc tree** that fully describes the `PVStructure` or `PVScalarArray` layout.  
The descriptors are **interned** per connection; both sides cache them by integer `<id>` to avoid resending.  
Whenever a sender wishes to refer to an already‑sent layout it can send the compact `ONLY_ID_TYPE_CODE` form instead of repeating the full tree.

##### 7.1.1.2  Data responses (`GET`, `MONITOR` updates, `ARRAY` slices…)

Once the type has been established, data‑bearing messages include no introspection at all.
They start directly with:

```text
BitSet changedBitSet   // GET & MONITOR
PVField valueData      // encoded per FieldDesc already cached
(optional BitSet overrunBitSet)
```

For these messages we must look up the cached `FieldDesc` using the `type‑ID` that was assigned in the corresponding `INIT` step.  
Then we will know the field name, and type (so how many bytes to pull and how to display them). The bit-set will show us what fields
to get from the cached info and therefore how to decode the bytes that follow. 

##### 7.1.1.3  Requests originating from the client

If the client needs to embed a pvRequest structure (e.g. filter options) it follows the same rules: send FULL_WITH_ID the first time, then ONLY_ID in subsequent identical requests.


## 8 TypeCode System

Each node in a **FieldDesc tree** begins with **one opaque byte** `TypeCode`.
The PVXS implementation maps these bytes exactly to the EPICS pvData enumeration:

### 8.1 Standard Type Codes

**PVXS TypeCodes** (from `src/pvxs/data.h`):

|   Code | Kind             | Array code | Size | Description                       |
|-------:|------------------|-----------:|------|-----------------------------------|
| `0x00` | **bool**         |     `0x08` | 1    | Boolean (0/1)                     |
| `0x20` | **int8_t**       |     `0x28` | 1    | Signed 8‑bit integer              |
| `0x21` | **int16_t**      |     `0x29` | 2    | Signed 16‑bit integer             |
| `0x22` | **int32_t**      |     `0x2A` | 4    | Signed 32‑bit integer             |
| `0x23` | **int64_t**      |     `0x2B` | 8    | Signed 64‑bit integer             |
| `0x24` | **uint8_t**      |     `0x2C` | 1    | Unsigned 8‑bit integer            |
| `0x25` | **uint16_t**     |     `0x2D` | 2    | Unsigned 16‑bit integer           |
| `0x26` | **uint32_t**     |     `0x2E` | 4    | Unsigned 32‑bit integer           |
| `0x27` | **uint64_t**     |     `0x2F` | 8    | Unsigned 64‑bit integer           |
| `0x42` | **float**        |     `0x4A` | 4    | IEEE‑754 32‑bit float             |
| `0x43` | **double**       |     `0x4B` | 8    | IEEE‑754 64‑bit double            |
| `0x60` | **string**       |     `0x68` | var  | UTF‑8 encoded string              |
| `0x80` | **struct**       |     `0x88` | —    | Composite structure               |
| `0x81` | **union**        |     `0x89` | —    | Discriminated union               |
| `0x82` | **any**          |     `0x8A` | —    | "variant *any*" type              |


### 8.2 FieldDesc Encoding (on‑wire introspection)

Every **FieldDesc** begins with one lead **TypeCode** byte whose bit layout is:

| bit(s) | Purpose                  | Value set                                                                                                                                                      |
|--------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 7‑5    | **Kind selector**        | `000` Bool & enum<br>`001`Integer<br>`010` Floating‑point<br>`011` String (UTF‑8)<br>`100` Complex (struct/union/variant/bounded‑string)<br>`101…111` Reserved |
| 4‑3    | **Array flag**           | `00` Scalar<br>`01` Variable‑size array<br>`10` Bounded‑size array (followed by *Size* bound)<br>`11` Fixed‑size array (followed by *Size* count)              |
| 2‑0    | **Kind‑specific detail** | see tables below                                                                                                                                               |

#### Integer detail bits (`kind=001`)

| bits 2‑0 | Size   | Signedness                   |
|----------|--------|------------------------------|
| `00x`    | 8 bit  | `x=0` signed, `x=1` unsigned |
| `01x`    | 16 bit | ”                            |
| `10x`    | 32 bit | ”                            |
| `11x`    | 64 bit | ”                            |  

#### Floating‑point detail bits (`kind=010`)

| bits 2‑0 | IEEE‑754 type                     |
|----------|-----------------------------------|
| `010`    | binary32 (float)                  |
| `011`    | binary64 (double)                 |
| `1xx`    | reserved (half/quad not yet used) |  

#### Complex detail bits (`kind=100`)

| bits 2‑0 | Meaning                   | Extra payload                                                       |
|----------|---------------------------|---------------------------------------------------------------------|
| `000`    | **Structure**             | *id* (string) + *fieldCount* (Size) + `fieldName + FieldDesc` × N   |
| `001`    | **Union**                 | *id* (string) + *memberCount* (Size) + `memberName + FieldDesc` × N |
| `010`    | **Variant Union** (“any”) | *no additional data*                                                |
| `011`    | **Bounded String**        | *Size* bound (**bytes**)                                            |
| `1xx`    | reserved                  |                                                                     |  

Arrays of complex types carry **one extra FieldDesc** that describes the element type (after any optional bound/count).

---

#### Quick reference — lead‑byte patterns

| Lead byte mask           | Interpretation                                      |
|--------------------------|-----------------------------------------------------|
| `0bxxx00xxx`             | Scalar (any kind)                                   |
| `0bxxx01xxx`             | Variable‑size **array** (element kind in same byte) |
| `0bxxx10xxx` + *Size*    | Bounded‑size **array**                              |
| `0bxxx11xxx` + *Size*    | Fixed‑size **array**                                |
| `0b10000000` + payload   | **Structure**                                       |
| `0b10001000` + FieldDesc | Array of Structures                                 |
| `0b10000001` + payload   | **Union**                                           |
| `0b10001001` + FieldDesc | Array of Unions                                     |
| `0b10000010`             | **Variant Union**                                   |
| `0b10001010` + FieldDesc | Array of Variant Unions                             |
| `0b10000110` + *Size*    | **Bounded String**                                  | 

---

#### Putting it together (Struct or Array example)

A **Structure FieldDesc** therefore serialises as

```text
<lead‑byte 0x80 | 0x88>   // scalar or array flag
 “typeID”                 // UTF‑8
                          // member count
repeat N times:
 “memberName”
                          // recursive
```

### Examples 

A **scalar Int32**: typeCode `0b00100 010` → `0x22` (`kind=001` Int, signed, scalar) – no extra data.

A **double[16]** fixed array: typeCode `kind=010` (float) + `11` (fixed array) + size bits `011` → `0x6B` followed by the **Size** value 16.

A **NTScalar** for **double**: typeCode `0b10000 000` → `0x80` (`kind=100` (complex) + `00` (non-array) + `000` (struct))
 - `0x80` typeCode 
 - `0x15 65 70 69 63 73 3a 6e 74 2f 4e 54 53 63 61 6c 61 72 3a 31 2e 30` typeID
   - `21` characters`"epics:nt/NTScalar:1.0"` 
   - (required for struct/union only) 
   - otherwise we just use "value" as the field name in the output
 - `0x06` Field Count - size-encoded,
 - FIELD 1
   - `0x05 76 61 6c 75 65` typeId
     - `5` characters`"value"`
   - `0x43` - a **scalar double**: typeCode `0b01000 011` (`kind=010` (floating point) + `00` (non-array) + `011` (scalar))
   - optional - 8-bytes-value depending if this is introspection-only or if it contains values as well
 - other Normative Type FIELDS for NTScalar (`descriptor`, `alarm`, `timestamp`, `display`, `control`)
   - other fields have their own typeIDs, and typeCodes which will determine how they are decoded

---

### Notes

* **Type ID** is *only* present for `kind=100` **structure/union** (and their arrays) – it is *not* used for scalar or basic arrays
* **Element Type** appears *only* for arrays of complex kinds; scalar arrays do **not** carry a second FieldDesc
* **Field Count** is a **Size‑encoded integer** that precedes the repeated `(name + FieldDesc)` list.
* Bounded/fixed arrays of scalars carry a **bound/count Size value**, not a nested FieldDesc. 
* The lead‑byte flags, not separate columns, distinguish scalar vs. array and encode signed/unsigned and width for integers.

#### 7.2.2 Encoding Examples

**Leaf Node (Scalar):**

| Description       | Protocol |
|-------------------|----------|
| TypeCode: int32_t | `0x22`   |

**Wireshark Display:**
```
└─ value (0x22: int32_t)
```

**Simple Structure:**

| Description                        | Protocol | ...                | ... |
|------------------------------------|----------|--------------------|-----|
| TypeCode: struct                   | `0x80`   | `0x08` `MyStruct`  |     |
| Type ID (Size=8 + UTF-8 string)    |          | `0x02`             |     |
| Field count: 2 fields              |          | `0x06` `field1`    |     |
| Field name (Size=6 + UTF-8 string) |          | `0x22`             |     |
| Field type: int32_t                |          | `0x06` `field2`    |     |
| Field name (Size=6 + UTF-8 string) |          | `0x43`             |     |
| Field type: double                 |          |                    |     |

**Wireshark Display:**
```
└─ value (0x80: MyStruct)
   ├─ field1 (0x22: int32_t):
   └─ field2 (0x43: double):
```

**Union:**

| Description                         | Protocol | ...                | ... |
|-------------------------------------|----------|--------------------|-----|
| TypeCode: union                     | `0x81`   | `0x07` `MyUnion`   |     |
| Type ID (Size=7 + UTF-8 string)     |          | `0x02`             |     |
| Choice count: 2 choices             |          | `0x07` `choice1`   |     |
| Choice name (Size=7 + UTF-8 string) |          | `0x22`             |     |
| Choice type: int32_t                |          | `0x07` `choice2`   |     |
| Choice name (Size=7 + UTF-8 string) |          | `0x60`             |     |
| Choice type: string                 |          |                    |     |

**Wireshark Display:**
```
└─ value (0x81: MyUnion)
   ├─ choice1 (0x22: int32_t):
   └─ choice2 (0x60: string):
```

**Nested Structure:**

| Description                        | Protocol            | ...               | ...               |
|------------------------------------|---------------------|-------------------|-------------------|
| TypeCode: struct                   | `0x80`              |                   |                   |
| Type ID (Size=9 + UTF-8 string)    | `0x09` `Container`  |                   |                   |
| Field count: 2 fields              |                     | `0x02`            |                   |
| Field name (Size=5 + UTF-8 string) |                     | `0x05` `value`    |                   |
| Field type: uint32_t               |                     | `0x26`            |                   |
| Field name (Size=5 + UTF-8 string) |                     | `0x05` `alarm`    |                   |
| Field type: struct (nested)        |                     | `0x80`            |                   |
| Type ID (Size=7 + UTF-8 string)    |                     | `0x07` `alarm_t`  |                   |
| Field count: 3 fields              |                     |                   | `0x03`            |
| Field name (Size=8 + UTF-8 string) |                     |                   | `0x08` `severity` |
| Field type: int32_t                |                     |                   | `0x22`            |
| Field name (Size=6 + UTF-8 string) |                     |                   | `0x06` `status`   |
| Field type: int32_t                |                     |                   | `0x22`            |
| Field name (Size=7 + UTF-8 string) |                     |                   | `0x07` `message`  |
| Field type: string                 |                     |                   | `0x60`            |

**Wireshark Display:**
```
└─ value (0x80: Container)
   ├─ value (0x26: uint32_t):
   └─ alarm (0x80: alarm_t)
      ├─ severity (0x22: int32_t):
      ├─ status (0x22: int32_t):
      └─ message (0x60: string):
```

**Structure Array:**

| Description                        | Protocol | ...               |
|------------------------------------|----------|-------------------|
| TypeCode: struct array             | `0x88`   |                   |
| Element type: struct               | `0x80`   | `0x05` `Point`    |
| Type ID (Size=5 + UTF-8 string)    |          | `0x02`            |
| Field count: 2 fields              |          | `0x01` `x`        |
| Field name (Size=1 + UTF-8 string) |          | `0x22`            |
| Field type: int32_t                |          | `0x01` `y`        |
| Field name (Size=1 + UTF-8 string) |          | `0x22`            |
| Field type: int32_t                |          |                   |

**Wireshark Display:**
```
└─ value (0x88: Point[])
   ├─ x (0x22: int32_t):
   └─ y (0x22: int32_t):
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

## 9. Value (PVField) Serialization

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

### 9.1 Union Encoding Details

- **Selector**: Union discriminator indicating which union member is present
- **Value**: Followed by that member's data
- **Critical Finding**: Selectors are field indices, not type codes

---

## 10. ChangedBitSet (Monitor, Get replies)

For partial‑update messages a **BitSet** precedes the value stream.
The *n*‑th bit set to `1` means "member *n* has been updated and its PVField appears in the payload".
Unset bits indicate that the receiver should reuse its cached copy of that member.
Bit numbering matches the depth‑first order of the `FieldDesc` tree.

Example of breadth-first numbering used by `BitSet` fpr `NTScalar double`:

```text
0 value  (double)
1 alarm          (structure)
2 timeStamp      (structure)
        ├─3 secondsPastEpoch (int64)
        ├─4 nanoseconds      (int32)
        └─5 userTag          (int32)
6 display        (structure)
7 control        (structure)
8 valueAlarm     (structure)
```

Only the root indices matter when you flag “whole sub‑structure changed”.
If you wanted individual `nanoseconds` only, you would also set bit 4.

### 10.1 Full example of exchange using BitSet

#### 10.1.1  `MONITOR INIT` (introspection only)

```text
-- 8‑byte header -------------------------------------------------------
CA 01 40 0D   34 00 00 00        # magic, ver, flags=0x40(server‑msg), cmd, size
-- payload ------------------------------------------------------------
2A 00 00 00                     # requestID   (0x2A)
08                              # subcommand  0x08  = INIT
FF                              # Status      0xFF  = OK (no text)
FD 01 00                        # FULL_WITH_ID, id = 1   (little‑endian)
80                              # FieldDesc lead‑byte: structure, scalar
15 "epics:nt/NTScalar:1.0"      # typeID (Size+UTF‑8)
09                              # member count = 9
   05 "value"   21              # double  (lead‑byte 0x21)
   05 "alarm"   FD 02 00 83 …   # FULL_WITH_ID id=2  (alarm_t schema)
   09 "timeStamp" FD 03 00 83…  # FULL_WITH_ID id=3  (timeStamp_t)
   07 "display" FD 04 00 83…    # etc.
   ...
```

The whole NTScalar description is sent once; the disector mus cache every (id → FieldDesc) found.

#### 10.1.1.2 monitor data message (only value + `timeStamp` changed)

```text
-- header --------------------------------------------------------------
CA 01 40 0D   26 00 00 00        # payload is now 0x26 bytes
-- payload -------------------------------------------------------------
2A 00 00 00                     # requestID   (same as before)
00                              # subcommand  0x00  = DATA
01 05                           # changedBitSet
                                #   Size=1 byte, mask=0b00000101
                                #                            ^bit0 (value)
                                #                              ^bit2 (timeStamp)
40 9C C6 F7 6E 58 2D 40         # value = 12.345 (IEEE754 little‑endian)
00 00 00 00 00 60 EE 5E         # secondsPastEpoch = 1 599 999 000
00 40 27 09                     # nanoseconds      = 150 000 000
00 00 00 00                     # userTag          = 0
00                              # overrunBitSet Size=0  (no overruns)
```

We use the Request ID to lookup the FieldDesc structure.  This contains the individual type IDs of the fields
indexed from 0, .. N-1.  And so we can directly use the bitmask to pull up the definitions.

Note: In that in this example ALL fields in timestamp are provided because the whole `timestamp_t` structure is referenced in the
`BitSet`.  Meaning that we need to store the relationship between the elements stored in the cache.


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

### 11.3 FULL_WITH_ID_TYPE_CODE (0xFD) 

The special TypeCode `0xFD` means **FULL_WITH_ID_TYPE_CODE** - "I'm sending a full Field‑introspection description and assigning it an ID."

**Wire format:**
```
0xFD                  FULL_WITH_ID_TYPE_CODE
01 00                 16-bit type-ID (little-endian → ID = 1)
80 15 "epics:nt/..."  First FieldDesc byte + Type ID string
```

**Example decode sequence:**
```
... FF FD 01 00 80 15 "epics:nt/NTScalar:1.0" ...
```

Decodes as:
1. `FF` → Status OK
2. `FD 01 00` → full introspection, assign type ID = 1
3. `80 15 "epics:nt/NTScalar:1.0"` → FieldDesc for top-level NTScalar structure

When the server later sends value updates (subcommand 0x00), it starts with a ChangedBitSet (e.g., `01 80` for bit 7 set) followed by the changed field values.

### 11.4 ChannelGet Example

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
| TypeCode: double                                         | `0x43`                                                  |
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
   └─ value (0x43: double): 100.2
```

The same channel, when monitored, would begin with a `Monitor‑INIT` (type tree identical), then receive periodic **server→client** messages re‑using that tree and only sending a `BitSet` + `value` when the `value` field actually changes.

### 11.5 ChannelPut Example

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
   └─ value (0x88: Point[]): 2 elements
      ├─ Point[0]
      │  ├─ x (0x43: double): 3.412
      │  └─ y (0x43: double): 12.3123
      └─ Point[1]
         ├─ x (0x43: double): -12.523
         └─ y (0x43: double): 20.2012
```

> **Note**: For new channels, the first PUT operation may include a FieldDesc (type definition). Subsequent operations on established channels can omit the type information, as shown above, for improved efficiency.

---

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
└─ value (0x80: NTScalar)
   ├─ value (0x26: uint32_t):
   ├─ alarm (0x80: alarm_t)
   │  ├─ severity (0x22: int32_t):
   │  ├─ status (0x22: int32_t):
   │  └─ message (0x60: string):
   ├─ timeStamp (0x80: time_t)
   │  ├─ secondsPastEpoch (0x23: int64_t):
   │  ├─ nanoseconds (0x22: int32_t):
   │  └─ userTag (0x22: int32_t):
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

* PVXS **never transmits fixed‑length strings or fixed‑width arrays**, even though the pvData type table reserves bit 4 of the TypeCode for such encodings (they are deprecated). Receivers should still reject TypeCodes with bit 4 set.
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
3. pvAccessCPP source code (GitHub: epics-base/pvAccessCPP)
4. EPICS Base 7 Channel Access vs PV Access comparison
5. Captured network traffic analysis (July 2025)
6. PVXS Protocol Documentation (GitHub: epics-base/pvxs)
7. PVXS Source Implementation (epics-base/pvxs)
