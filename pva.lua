-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- Copyright 2021 Michael Davidsaver, 2025 George McIntyre
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
io.stderr:write("Loading PVA...\n")

-- application messages
local application_messages = {
    [0]  = "BEACON",
    [1]  = "CONNECTION_VALIDATION",
    [2]  = "ECHO",
    [3]  = "SEARCH",
    [4]  = "SEARCH_RESPONSE",
    [5]  = "AUTHNZ",
    [6]  = "ACL_CHANGE",
    [7]  = "CREATE_CHANNEL",
    [8]  = "DESTROY_CHANNEL",
    [9]  = "CONNECTION_VALIDATED",
    [10] = "GET",
    [11] = "PUT",
    [12] = "PUT_GET",
    [13] = "MONITOR",
    [14] = "ARRAY",
    [15] = "DESTROY_REQUEST",
    [16] = "PROCESS",
    [17] = "GET_FIELD",
    [18] = "MESSAGE",
    [19] = "MULTIPLE_DATA",
    [20] = "RPC",
    [21] = "CANCEL_REQUEST",
    [22] = "ORIGIN_TAG",
}

-- control messages
local control_messages = {
    [0] = "MARK_TOTAL_BYTES_SENT",
    [1] = "ACK_TOTAL_BYTES_RECEIVED",
    [2] = "SET_BYTE_ORDER",
}

-- status codes
local status_codes = {
    [0xff] = "OK",
    [0]    = "OK",
    [1]    = "Warning",
    [2]    = "Error",
    [3]    = "Fatal Error",
}

----------------------------------------------
-- Simple TypeCodes
----------------------------------------------

local TYPE_CODE_BOOLEAN                 = 0x00;

local TYPE_CODE_BYTE                    = 0x20;
local TYPE_CODE_SHORT                   = 0x21;
local TYPE_CODE_INT                     = 0x22;
local TYPE_CODE_LONG                    = 0x23;

local TYPE_CODE_UBYTE                   = 0x24;
local TYPE_CODE_USHORT                  = 0x25;
local TYPE_CODE_UINT                    = 0x26;
local TYPE_CODE_ULONG                   = 0x27;

local TYPE_CODE_FLOAT                   = 0x42;
local TYPE_CODE_DOUBLE                  = 0x43;

local TYPE_CODE_STRING                  = 0x60;

local TYPE_CODE_STRUCT                  = 0x80;
local TYPE_CODE_UNION                   = 0x81;
local TYPE_CODE_ANY                     = 0x82;

----------------------------------------------
-- Array TypeCodes
----------------------------------------------

local TYPE_CODE_BOOLEAN_ARRAY           = 0x08;

local TYPE_CODE_BYTE_ARRAY              = 0x28;
local TYPE_CODE_SHORT_ARRAY             = 0x29;
local TYPE_CODE_INT_ARRAY               = 0x2A;
local TYPE_CODE_LONG_ARRAY              = 0x2B;

local TYPE_CODE_UBYTE_ARRAY             = 0x2C;
local TYPE_CODE_USHORT_ARRAY            = 0x2D;
local TYPE_CODE_UINT_ARRAY              = 0x2E;
local TYPE_CODE_ULONG_ARRAY             = 0x2F;

local TYPE_CODE_FLOAT_ARRAY             = 0x4A;
local TYPE_CODE_DOUBLE_ARRAY            = 0x4B;

local TYPE_CODE_STRING_ARRAY            = 0x68;

local TYPE_CODE_STRUCT_ARRAY            = 0x88;
local TYPE_CODE_UNION_ARRAY             = 0x89;
local TYPE_CODE_ANY_ARRAY               = 0x8A;

----------------------------------------------
-- Cache and special codes
----------------------------------------------

local CACHE_STORE_CODE                  = 0xFD;
local CACHE_FETCH_CODE                  = 0xFE;
local TYPE_CODE_NULL                    = 0xFF;

-- Legacy codes (not in PVXS specification)
local TYPE_CODE_INTROSPECTION_ONLY      = 0x01;

----------------------------------------------
-- TypeCode to name mapping table
----------------------------------------------

local PVD_TYPES = {
    --
    [TYPE_CODE_BOOLEAN]                 = "bool",
    [TYPE_CODE_BYTE]                    = "int8_t",
    [TYPE_CODE_SHORT]                   = "int16_t",
    [TYPE_CODE_INT]                     = "int32_t",
    [TYPE_CODE_LONG]                    = "int64_t",
    [TYPE_CODE_UBYTE]                   = "uint8_t",
    [TYPE_CODE_USHORT]                  = "uint16_t",
    [TYPE_CODE_UINT]                    = "uint32_t",
    [TYPE_CODE_ULONG]                   = "uint64_t",
    [TYPE_CODE_FLOAT]                   = "float",
    [TYPE_CODE_DOUBLE]                  = "double",
    [TYPE_CODE_STRING]                  = "string",
    [TYPE_CODE_STRUCT]                  = "struct",
    [TYPE_CODE_UNION]                   = "union",
    [TYPE_CODE_ANY]                     = "any",

    -- Array types
    [TYPE_CODE_BOOLEAN_ARRAY]           = "bool[]",
    [TYPE_CODE_BYTE_ARRAY]              = "int8_t[]",
    [TYPE_CODE_SHORT_ARRAY]             = "int16_t[]",
    [TYPE_CODE_INT_ARRAY]               = "int32_t[]",
    [TYPE_CODE_LONG_ARRAY]              = "int64_t[]",
    [TYPE_CODE_UBYTE_ARRAY]             = "uint8_t[]",
    [TYPE_CODE_USHORT_ARRAY]            = "uint16_t[]",
    [TYPE_CODE_UINT_ARRAY]              = "uint32_t[]",
    [TYPE_CODE_ULONG_ARRAY]             = "uint64_t[]",
    [TYPE_CODE_FLOAT_ARRAY]             = "float[]",
    [TYPE_CODE_DOUBLE_ARRAY]            = "double[]",
    [TYPE_CODE_STRING_ARRAY]            = "string[]",
    [TYPE_CODE_STRUCT_ARRAY]            = "struct[]",
    [TYPE_CODE_UNION_ARRAY]             = "union[]",
    [TYPE_CODE_ANY_ARRAY]               = "any[]",

    -- Special/cache codes
    [CACHE_STORE_CODE]                  = "cache_store",
    [CACHE_FETCH_CODE]                  = "cache_fetch",
    [TYPE_CODE_NULL]                    = "null",

    [TYPE_CODE_INTROSPECTION_ONLY]      = "introspectionOnly"
}

----------------------------------------------
-- ProtoFields
----------------------------------------------

local pva = Proto("pva", "Process Variable Access")

local placeholder   = ProtoField.bytes("pva.placeholder", " ")

----------------------------------------------
-- Magic, Version, Flags, Command, Control Command, Control Data, Size, Body, PVData, GUID
----------------------------------------------

local fmagic        = ProtoField.uint8(     "pva.magic",        "Magic",            base.HEX)
local fver          = ProtoField.uint8(     "pva.version",      "Version",          base.DEC)
local fflags        = ProtoField.uint8(     "pva.flags",        "Flags",            base.HEX)
local fflag_dir     = ProtoField.uint8(     "pva.direction",    "Direction",        base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end     = ProtoField.uint8(     "pva.endian",       "Byte order",       base.HEX, {[0]="LSB",[1]="MSB"}, 0x80)
local fflag_msgtype = ProtoField.uint8(     "pva.msg_type",     "Message type",     base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented = ProtoField.uint8(   "pva.segmented",    "Segmented",        base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd          = ProtoField.uint8(     "pva.command",      "Command",          base.HEX, application_messages)
local fctrlcmd      = ProtoField.uint8(     "pva.ctrlcommand",  "Control Command",  base.HEX, control_messages)
local fctrldata     = ProtoField.uint32(    "pva.ctrldata",     "Control Data",     base.HEX)
local fsize         = ProtoField.uint32(    "pva.size",         "Size",             base.DEC)
local fbody         = ProtoField.bytes(     "pva.body",         "Body")
local fpvd          = ProtoField.bytes(     "pva.pvd",          "PVData Body")
local fguid         = ProtoField.bytes(     "pva.guid",         "GUID")

----------------------------------------------
-- PVData Fields
----------------------------------------------

local fpvd_struct   = ProtoField.bytes(     "pva.pvd_struct",   "PVStructure")
local fpvd_field    = ProtoField.bytes(     "pva.pvd_field",    "Field")
local fpvd_field_name = ProtoField.string(  "pva.pvd_field_name", "Field Name")
local fpvd_type     = ProtoField.uint8(     "pva.pvd_type",     "Type",             base.HEX)
local fpvd_value    = ProtoField.bytes(     "pva.pvd_value",    "Value")
local fpvd_introspection = ProtoField.bytes("pva.pvd_introspection", "Introspection Data")
local fpvd_debug    = ProtoField.bytes(     "pva.pvd_debug",    "Debug Info")

----------------------------------------------
-- Common Fields
----------------------------------------------

local fcid          = ProtoField.uint32(    "pva.cid",          "Client Channel ID")
local fsid          = ProtoField.uint32(    "pva.sid",          "Server Channel ID")
local fioid         = ProtoField.uint32(    "pva.ioid",         "Operation ID")
local fsubcmd       = ProtoField.uint8(     "pva.subcmd",       "Sub-command",      base.HEX)
local fsubcmd_proc  = ProtoField.uint8(     "pva.process",      "Process",          base.HEX, {[0]="",[1]="Yes"}, 0x04)
local fsubcmd_init  = ProtoField.uint8(     "pva.init",         "Init   ",          base.HEX, {[0]="",[1]="Yes"}, 0x08)
local fsubcmd_dstr  = ProtoField.uint8(     "pva.destroy",      "Destroy",          base.HEX, {[0]="",[1]="Yes"}, 0x10)
local fsubcmd_get   = ProtoField.uint8(     "pva.get",          "Get    ",          base.HEX, {[0]="",[1]="Yes"}, 0x40)
local fsubcmd_gtpt  = ProtoField.uint8(     "pva.getput",       "GetPut ",          base.HEX, {[0]="",[1]="Yes"}, 0x80)
local fstatus       = ProtoField.uint8(     "pva.status",       "Status",           base.HEX, status_codes)

----------------------------------------------
-- BEACON
----------------------------------------------

local fbeacon_seq = ProtoField.uint8("pva.bseq", "Beacon sequence#")
local fbeacon_change = ProtoField.uint16("pva.change", "Beacon change count")

-- For CONNECTION_VALIDATION

local fvalid_bsize  = ProtoField.uint32(    "pva.qsize",        "Client Queue Size")
local fvalid_isize  = ProtoField.uint16(    "pva.isize",        "Client Introspection registery size")
local fvalid_qos    = ProtoField.uint16(    "pva.qos",          "Client QoS",   base.HEX)
local fvalid_method = ProtoField.string(    "pva.method",       "AuthZ method")
local fvalid_azflg  = ProtoField.uint8 (    "pva.authzflag",    "AuthZ Flags",  base.HEX)
local fvalid_azcnt  = ProtoField.uint8 (    "pva.authzcnt",     "AuthZ Elem‑cnt", base.DEC)

-- For AUTHZ_REQUEST

local fauthz_request = ProtoField.string(   "pva.authzrequest", "AuthZ request")
local fvalid_host   = ProtoField.string(    "pva.host",         "AuthZ host")
local fvalid_authority = ProtoField.string( "pva.authority",    "AuthZ authority")
local fvalid_user   = ProtoField.string(    "pva.user",         "AuthZ name")
local fvalid_account = ProtoField.string(   "pva.account",      "AuthZ account")
local fvalid_isTLS  = ProtoField.uint8(     "pva.isTLS",        "AuthZ isTLS")

-- For AUTHZ_RESPONSE

local fauthz_response = ProtoField.string("pva.authzresponse",  "AuthZ response")

-- For AuthZ Entry Array (removed fauth_entry_index as no longer needed)

-- For SEARCH
local fsearch_seq   = ProtoField.uint32(    "pva.seq",          "Search Sequence #")
local fsearch_addr  = ProtoField.bytes(     "pva.addr",          "Address")
local fsearch_port  = ProtoField.uint16(    "pva.port",         "Port")
local fsearch_mask  = ProtoField.uint8(     "pva.mask",         "Mask",         base.HEX)
local fsearch_mask_repl  = ProtoField.uint8("pva.reply",        "Reply",        base.HEX, {[0]="Optional",[1]="Required"}, 0x01)
local fsearch_mask_bcast = ProtoField.uint8("pva.ucast",        "Reply",        base.HEX, {[0]="Broadcast",[1]="Unicast"}, 0x80)
local fsearch_proto = ProtoField.string(    "pva.proto",        "Transport Protocol")
local fsearch_count = ProtoField.uint16(    "pva.count",        "PV Count")
local fsearch_cid   = ProtoField.uint32(    "pva.cid",          "CID")
local fsearch_name  = ProtoField.string(    "pva.pv",           "Name")

-- For SEARCH_RESPONSE
local fsearch_found = ProtoField.bool(      "pva.found",        "Found")

----------------------------------------------
-- ProtoFields variables
----------------------------------------------

pva.fields = {
    placeholder, fmagic, fver, fflags, fflag_dir, fflag_end, fflag_msgtype, fflag_segmented, fcmd, fctrlcmd, fctrldata, fsize, fbody, fpvd, fguid,
    fcid, fsid, fioid, fsubcmd, fsubcmd_proc, fsubcmd_init, fsubcmd_dstr, fsubcmd_get, fsubcmd_gtpt, fstatus,
    fbeacon_seq, fbeacon_change,
    fvalid_bsize, fvalid_isize, fvalid_qos, fvalid_host, fvalid_method, fvalid_authority, fvalid_account, fvalid_user, fvalid_isTLS,
    fvalid_azflg, fvalid_azcnt, fauthz_request, fauthz_response,
    fpvd_struct, fpvd_field, fpvd_field_name, fpvd_type, fpvd_value, fpvd_introspection, fpvd_debug,
    fsearch_seq, fsearch_addr, fsearch_port, fsearch_mask, fsearch_mask_repl, fsearch_mask_bcast,
    fsearch_proto, fsearch_count, fsearch_cid, fsearch_name,
    fsearch_found,
}

----------------------------------------------
-- Utility functions
----------------------------------------------

local function getUint(src, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return src:uint()
    else
        return src:le_uint()
    end
end

-- decodeSize: decode a size from a buffer
-- size is encoded as a single byte, or 4 bytes if the first byte is 0xFE or 0xFF
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @param , is_nullable: true if the buffer is nullable (default true)
-- @return the size and the remaining buffer
local function decodeSize(buf, is_big_endian, is_nullable)
    if is_nullable == nil then
        is_nullable = true
    end
    local buf_len = buf:len()
    if buf_len < 1 then
        return 0, buf
    end

    local remaining_buf = buf_len > 1 and buf(1) or buf
    local short_size = buf(0,1):uint()
    if short_size==0xFF and is_nullable then
        -- null
        return 0, remaining_buf
    elseif short_size==0xFE and not is_nullable then
        -- 2 byte size
        if buf_len < 3 then
            return 0, buf
        end
        return getUint(buf(1,2), is_big_endian), buf(3)
    elseif short_size<0xFE then
        -- one byte size
        return short_size, remaining_buf
    else
        -- 4 byte size
        if buf_len < 5 then
            return 0, buf
        end
        return getUint(buf(1,4), is_big_endian), buf(5)
    end
end

----------------------------------------------
-- String decoding
----------------------------------------------

-- decodeString: extract a string and return that string, and the remaining buffer
-- string is encoded as a size (1 or 4 bytes) followed by the actual string
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @param , is_nullable: true if the buffer is nullable
-- @return the string and the remaining buffer
local function decodeString(buf, is_big_endian, is_nullable)
    if buf:len() == 0 then
        return buf(0,0), nil
    end

    local len, remaining_buf = decodeSize(buf, is_big_endian, is_nullable)

    -- Check if we have enough bytes for the string
    if not remaining_buf or remaining_buf:len() < len then
        -- Not enough data, return what we have
        return buf(0, math.min(len, buf:len())), nil
    end

    if len == remaining_buf:len() then
        return remaining_buf(0, len), nil
    else
        return remaining_buf(0, len), remaining_buf(len)
    end
end

-- skipNextElement: skip the next element and return the remaining buffer
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @return the remaining buffer
local function skipNextElement(buf, is_big_endian)
    local len, remaining_buf = decodeSize(buf, is_big_endian, is_nullable)
    if len == remaining_buf:len() then
        return nil
    else
        return remaining_buf(len + 1)
    end
end


-- Helper function to read PVData size (Phase 2)
local function readPVSize(buf, offset, is_big_endian)
    if not buf or offset >= buf:len() then
        return 0, offset
    end

    local size_byte = buf(offset, 1):uint()
    if size_byte < 0xFE then
        return size_byte, offset + 1
    elseif size_byte == 0xFE then
        if offset + 2 >= buf:len() then return 0, offset end
        local size = is_big_endian and buf(offset + 1, 2):uint() or buf(offset + 1, 2):le_uint()
        return size, offset + 3
    elseif size_byte == 0xFF then
        if offset + 4 >= buf:len() then return 0, offset end
        local size = is_big_endian and buf(offset + 1, 4):uint() or buf(offset + 1, 4):le_uint()
        return size, offset + 5
    end
    return 0, offset
end

-- Helper function to read PVData string (Phase 2)
local function readPVString(buf, offset, is_big_endian)
    local str_len, new_offset = readPVSize(buf, offset, is_big_endian)
    if str_len == 0 or new_offset + str_len > buf:len() then
        return "", new_offset
    end
    local str = buf(new_offset, str_len):string()
    return str, new_offset + str_len
end

-- EPICS timestamp conversion to human readable format
local function formatEpicsTimestamp(seconds, nanoseconds)
    -- EPICS epoch is January 1, 1990 00:00:00 UTC
    -- Unix epoch is January 1, 1970 00:00:00 UTC
    -- Difference: 631152000 seconds (20 years)
    local unix_seconds = seconds + 631152000
    local date_str = os.date("!%Y-%m-%d %H:%M:%S", unix_seconds)
    return string.format("%s.%09d UTC", date_str, nanoseconds)
end

-- Enhanced alarm status decoder
local function decodeAlarmStatus(severity, status)
    local severity_names = {
        [0] = "NO_ALARM",
        [1] = "MINOR",
        [2] = "MAJOR",
        [3] = "INVALID"
    }

    local status_names = {
        [0] = "NO_ALARM",
        [1] = "READ",
        [2] = "WRITE",
        [3] = "HIHI",
        [4] = "HIGH",
        [5] = "LOLO",
        [6] = "LOW",
        [7] = "STATE",
        [8] = "COS",
        [9] = "COMM",
        [10] = "TIMEOUT",
        [11] = "HWLIMIT",
        [12] = "CALC",
        [13] = "SCAN",
        [14] = "LINK",
        [15] = "SOFT",
        [16] = "BAD_SUB",
        [17] = "UDF",
        [18] = "DISABLE",
        [19] = "SIMM",
        [20] = "READ_ACCESS",
        [21] = "WRITE_ACCESS"
    }

    local sev_name = severity_names[severity] or string.format("UNKNOWN(%d)", severity)
    local stat_name = status_names[status] or string.format("UNKNOWN(%d)", status)

    return sev_name, stat_name
end









-- Helper function to get type size (simplified version)
local function getTypeSize(type_byte)
    if type_byte == TYPE_CODE_BOOLEAN then return 1 -- bool
    elseif type_byte == TYPE_CODE_BYTE then return 1 -- int8_t
    elseif type_byte == TYPE_CODE_SHORT then return 2 -- int16_t
    elseif type_byte == TYPE_CODE_INT then return 4 -- int32_t
    elseif type_byte == TYPE_CODE_LONG then return 8 -- int64_t
    elseif type_byte == TYPE_CODE_UBYTE then return 1 -- uint8_t
    elseif type_byte == TYPE_CODE_USHORT then return 2 -- uint16_t
    elseif type_byte == TYPE_CODE_UINT then return 4 -- uint32_t
    elseif type_byte == TYPE_CODE_ULONG then return 8 -- uint64_t
    elseif type_byte == TYPE_CODE_FLOAT then return 4 -- float
    elseif type_byte == TYPE_CODE_DOUBLE then return 8 -- double
    else return 0 -- variable length or unknown
    end
end

-- Helper function to identify authentication method strings
-- Context-aware: "anonymous" is usually a username, not a method
local function isAuthMethod(str, position, prev_was_method)
    local s = str:string():lower()

    -- Strong method indicators
    local strong_methods = {"x509", "ca", "plain", "kerberos", "tls", "ssl", "digest", "basic"}
    for _, method in ipairs(strong_methods) do
        if s == method then
            return true
        end
    end

    -- "anonymous" is typically a username unless it's clearly in method position
    if s == "anonymous" then
        -- Treat as method only if we've already seen a method (meaning this starts a new entry)
        return prev_was_method
    end

    return false
end


-- Since PVA has some identifiable header we can
-- avoid having to select "Decode as..." every time :)
local function test_pva (buf, pkt, root)
    -- check for 8 byte minimum length, prefix [MAGIC, 1, _, cmd] where cmd is a valid command #
    if buf:len()<8 or buf(0,1):uint()~= PVA_MAGIC or buf(1,1):uint()==0 or not application_messages[buf(3,1):uint()]
    then
        return false
    end
    pva.dissector(buf, pkt, root)
    pkt.conversation = pva
    return true
end

local status, err = pcall(function() pva:register_heuristic("tcp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic TCP dissector.  Must manually specify TCP port! (try newer wireshark?)")
    print(err)
end
-- Wireshark 2.0 errors if the same protocol name is given for two
-- heuristic dissectors, even for different transports.
local status, err = pcall(function() pva:register_heuristic("udp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic UDP dissector.  Must manually specify UDP port! (try newer wireshark?)")
    print(err)
end

local function decodeStatus (buf, pkt, t, is_big_endian)
    local code = buf(0,1):uint()
    local subt = t:add(fstatus, buf(0,1))
    if buf:len()>1 then
        buf = buf(1):tvb()
    end
    if code==0xff
    then
        return buf
    else
        local message, stack
        message, buf = decodeString(buf, is_big_endian)
        stack, buf = decodeString(buf, is_big_endian)
        subt:append_text(message:string())
        if(code~=0 and stack:len()>0)
        then
            subt:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
        end
        return buf
    end
end


-- ===================================================================
-- UNIFIED FIELDDESC PARSING SYSTEM
-- ===================================================================

-- Forward declaration
local parseFieldDesc

-- Parse structure FieldDesc: Type ID + field count + fields
local function parseStructDesc(buf, offset, is_big_endian, tree, type_code)
    -- Read optional Type ID string
    local type_id, type_id_offset = readPVString(buf, offset, is_big_endian)
    local clean_name = "struct"
    if type_id and type_id ~= "" then
        offset = type_id_offset
        -- Extract clean type name
        clean_name = type_id:match("([^:]+)") or type_id
    end

    -- Update tree display name
    tree:set_text(string.format("(0x%02X: %s)", type_code, clean_name))

    -- Read field count
    local field_count, count_offset = readPVSize(buf, offset, is_big_endian)
    offset = count_offset

    -- Parse each field: name + FieldDesc
    for i = 1, math.min(field_count, 20) do -- Limit to prevent runaway
        if offset >= buf:len() then break end

        local field_name, name_offset = readPVString(buf, offset, is_big_endian)
        offset = name_offset

        offset = parseFieldDesc(buf, offset, is_big_endian, tree, field_name)
    end

    return offset
end

-- Parse union FieldDesc: Type ID + field count + fields
local function parseUnionDesc(buf, offset, is_big_endian, tree, type_code)
    -- Read optional Type ID string
    local type_id, type_id_offset = readPVString(buf, offset, is_big_endian)
    local clean_name = "union"
    if type_id and type_id ~= "" then
        offset = type_id_offset
        clean_name = type_id:match("([^:]+)") or type_id
    end

    -- Update tree display name
    tree:set_text(string.format("(0x%02X: %s)", type_code, clean_name))

    -- Read field count
    local field_count, count_offset = readPVSize(buf, offset, is_big_endian)
    offset = count_offset

    -- Parse each field: name + FieldDesc
    for i = 1, math.min(field_count, 20) do
        if offset >= buf:len() then break end

        local field_name, name_offset = readPVString(buf, offset, is_big_endian)
        offset = name_offset

        offset = parseFieldDesc(buf, offset, is_big_endian, tree, field_name)
    end

    return offset
end

-- Parse cache store: cache key + FieldDesc
local function parseCacheStore(buf, offset, is_big_endian, tree)
    if offset + 1 < buf:len() then
        local cache_key = is_big_endian and buf(offset, 2):uint() or buf(offset, 2):le_uint()
        tree:set_text(string.format("Cache Store %d", cache_key))
        offset = offset + 2

        -- Parse the stored FieldDesc
        offset = parseFieldDesc(buf, offset, is_big_endian, tree, nil)
    end
    return offset
end

-- Parse cache fetch: cache key only
local function parseCacheFetch(buf, offset, is_big_endian, tree)
    if offset + 1 < buf:len() then
        local cache_key = is_big_endian and buf(offset, 2):uint() or buf(offset, 2):le_uint()
        tree:set_text(string.format("Cache Fetch %d", cache_key))
        offset = offset + 2
    end
    return offset
end

-- Core FieldDesc parser - handles all TypeCodes uniformly
parseFieldDesc = function(buf, offset, is_big_endian, tree, field_name)
    if not buf or offset >= buf:len() then
        return offset
    end

    local type_code = buf(offset, 1):uint()
    local type_name = PVD_TYPES[type_code] or string.format("unknown(0x%02X)", type_code)
    offset = offset + 1

    -- Create field display with standard format: fieldname (0xHH: typename)
    local display_name = field_name and string.format("%s (0x%02X: %s)", field_name, type_code, type_name)
            or string.format("(0x%02X: %s)", type_code, type_name)
    local field_tree = tree:add(buf(offset - 1, 1), display_name)

    -- Handle TypeCode-specific parsing
    if type_code == TYPE_CODE_STRUCT then
        offset = parseStructDesc(buf, offset, is_big_endian, field_tree, type_code)
    elseif type_code == TYPE_CODE_UNION then
        offset = parseUnionDesc(buf, offset, is_big_endian, field_tree, type_code)
    elseif type_code == CACHE_STORE_CODE then
        offset = parseCacheStore(buf, offset, is_big_endian, field_tree)
    elseif type_code == CACHE_FETCH_CODE then
        offset = parseCacheFetch(buf, offset, is_big_endian, field_tree)
        -- All other types (scalars, arrays) are just TypeCode - no additional data
    end

    return offset
end

-- ===================================================================
-- MONITOR-INIT PARSER (uses unified FieldDesc system)
-- ===================================================================

local function parseMonitorInit(buf, pkt, t, is_big_endian)
    if not buf or buf:len() == 0 then
        return
    end

    local offset = 0

    -- Parse ChangedBitSet
    if offset < buf:len() then
        local bitset_byte = buf(offset, 1):uint()
        local bits_set = {}
        for i = 0, 7 do
            if bit.band(bitset_byte, bit.lshift(1, i)) ~= 0 then
                table.insert(bits_set, i)
            end
        end
        local bits_str = table.concat(bits_set, ",")
        t:add(buf(offset, 1), string.format("ChangedBitSet: 0x%02X (bits: %s)", bitset_byte, bits_str))
        offset = offset + 1
    end

    -- Parse Type ID string
    if offset < buf:len() then
        local type_id, type_id_offset = readPVString(buf, offset, is_big_endian)
        if type_id then
            t:add(buf(offset, type_id_offset - offset), string.format("Type ID: %s", type_id))
            offset = type_id_offset
        end
    end

    -- Parse FieldDesc structure (starts with field count, not TypeCode)
    if offset < buf:len() then
        local field_count, count_offset = readPVSize(buf, offset, is_big_endian)
        t:add(buf(offset, count_offset - offset), string.format("Field Count: %d", field_count))
        offset = count_offset

        -- Parse each field using unified system
        for i = 1, math.min(field_count, 10) do
            if offset >= buf:len() then break end

            local field_name, name_offset = readPVString(buf, offset, is_big_endian)
            if not field_name then break end
            offset = name_offset

            offset = parseFieldDesc(buf, offset, is_big_endian, t, field_name)
        end

        -- Show remaining data if any
        if offset < buf:len() then
            t:add(buf(offset), string.format("Remaining data (%d bytes)", buf:len() - offset))
        end
    end
end

-- ===================================================================
-- SIMPLIFIED PVDATA DECODER
-- ===================================================================

function decodePVData(buf, pkt, t, is_big_endian, label)
    if not buf or buf:len() == 0 then
        return
    end

    local pvd_tree = t:add(placeholder, label or "PVData Body")

    if buf:len() == 0 then
        pvd_tree:append_text(" [Empty]")
        return pvd_tree
    end

    -- Simple unified parsing - just parse the FieldDesc at the start
    parseFieldDesc(buf, 0, is_big_endian, pvd_tree, "value")

    return pvd_tree
end


----------------------------
-- command decoders
----------------------------


----------------------------------------------
-- pvaClientSearchDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientSearchDecoder (message_body, pkt, tree, is_big_endian)
    local SEARCH_HEADER_SIZE = 26
    local raw_sequence_number = message_body(0,4)
    local sequence_number = getUint(raw_sequence_number, is_big_endian)
    local port = getUint(message_body(24,2), is_big_endian)
    pkt.cols.info:append("SEARCH(".. sequence_number)

    tree:add(fsearch_seq, raw_sequence_number, sequence_number)

    local raw_mask = message_body(4,1)
    local mask = tree:add(fsearch_mask, raw_mask)
    mask:add(fsearch_mask_repl, raw_mask)
    mask:add(fsearch_mask_bcast, raw_mask)
    tree:add(fsearch_addr, message_body(8,16))
    tree:add(fsearch_port, message_body(24,2), port)

    local n_protocols

    -- get protocols list
    n_protocols, message_body = decodeSize(message_body(SEARCH_HEADER_SIZE), is_big_endian)
    for i=0, n_protocols -1 do
        local name
        name, message_body = decodeString(message_body, is_big_endian)
        tree:add(fsearch_proto, name)
    end

    -- get pvs list
    local raw_n_pv = message_body(0,2)
    local n_pvs = getUint(raw_n_pv, is_big_endian)
    tree:add(fsearch_count, raw_n_pv, n_pvs);
    if n_pvs >0 then
        message_body = message_body(2)

        for i=0, n_pvs -1 do
            local name
            local raw_cid = message_body(0,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            name, message_body = decodeString(message_body(4), is_big_endian)
            tree:add(fsearch_name, name)

            pkt.cols.info:append(', '..cid..":'"..name:string().."'")
        end
    end
    pkt.cols.info:append("), ")
end

----------------------------------------------
-- pvaServerBeaconDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerBeaconDecoder (message_body, pkt, tree, is_big_endian)
    local raw_beacon_header = message_body(0,12)
    tree:add(fguid, raw_beacon_header)
    local sequence_number = getUint(message_body(13,1), is_big_endian)
    local change = getUint(message_body(14,2), is_big_endian)
    local port = getUint(message_body(32,2), is_big_endian)
    tree:add(fbeacon_seq, message_body(13,1), sequence_number)
    tree:add(fbeacon_change, message_body(14,2), change)
    tree:add(fsearch_addr, message_body(16,16))
    tree:add(fsearch_port, message_body(32,2), port)

    pkt.cols.info:append("BEACON(0x".. raw_beacon_header ..", ".. sequence_number ..", "..change..")")

    local proto
    proto, message_body = decodeString(message_body(34), is_big_endian)
    tree:add(fsearch_proto, proto)
end

----------------------------------------------
-- pvaServerSearchResponseDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerSearchResponseDecoder (message_body, pkt, tree, is_big_endian)
    local sequence_number = getUint(message_body(12,4), is_big_endian)
    local port = getUint(message_body(32,2), is_big_endian)
    pkt.cols.info:append("SEARCH_RESPONSE(".. sequence_number)

    tree:add(fguid, message_body(0,12))
    tree:add(fsearch_seq, message_body(12,4), sequence_number)
    tree:add(fsearch_addr, message_body(16,16))
    tree:add(fsearch_port, message_body(32,2), port)

    local proto
    proto, message_body = decodeString(message_body(34), is_big_endian)
    tree:add(fsearch_proto, proto)

    tree:add(fsearch_found, message_body(0, 1))

    local n_pvs = getUint(message_body(1,2), is_big_endian)
    if n_pvs >0 then
        message_body = message_body(3)
        for i=0, n_pvs -1 do
            local raw_cid = message_body(i*4,4)
            local cid = getUint(raw_cid, is_big_endian)
            tree:add(fsearch_cid, raw_cid, cid)
            pkt.cols.info:append(', '..cid)
        end
    end
    pkt.cols.info:append(")")

end

----------------------------------------------
-- pvaClientValidateDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientValidateDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local bsize  = getUint(message_body(0,4), is_big_endian)
    local isize = getUint(message_body(4,2), is_big_endian)
    local qos = getUint(message_body(6,2), is_big_endian)
    tree:add(fvalid_bsize, message_body(0,4), bsize)
    tree:add(fvalid_isize, message_body(4,2), isize)
    tree:add(fvalid_qos, message_body(6,2), qos)

    local method
    method, message_body = decodeString(message_body(8), is_big_endian)

    -- Declare variables for authz processing
    local n_authz = 0
    local has_authz_extensions = false

    -- extensions to the AUTHZ message
    if (message_body and message_body:len() > 1)
    then
        local authzmessage, authzflags
        authzmessage = message_body(0,1):uint()
        if authzmessage == 0xfd
        then
            message_body = message_body(3)
        end
        -- Add authz flags at the main level (applies to all entries)
        tree:add(fvalid_azflg,  message_body(1,1))
        authzflags = message_body(1,1):uint()
        n_authz = message_body(2,1):uint()
        message_body = message_body(3)
        has_authz_extensions = true
    end

    -- Add appropriate info message based on method
    if method:string():lower() == "x509" then
        pkt.cols.info:append("X509 AUTHZ, ")
    elseif has_authz_extensions then
        if n_authz == 2 then
            pkt.cols.info:append("CA AUTHZ, ")
        elseif n_authz == 3 then
            pkt.cols.info:append("PVA AUTHZ, ")
        end
    end

    -- Start with basic auth entry for the method
    local entry_tree = tree:add("AuthZ Entry 1")
    entry_tree:add(fvalid_method, method)

    -- Process authz extensions if present
    if has_authz_extensions
    then
        local peer, authority, account
        if n_authz == 2
        then
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)

            account, message_body = decodeString(message_body, is_big_endian)
            peer, message_body = decodeString(message_body, is_big_endian)

            -- Add additional fields to the existing auth entry
            entry_tree:add(fvalid_user, account)
            entry_tree:add(fvalid_host, peer)

        elseif n_authz == 3
        then
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)
            message_body = skipNextElement(message_body, is_big_endian)

            peer, message_body = decodeString(message_body, is_big_endian)
            authority, message_body = decodeString(message_body, is_big_endian)
            account, message_body = decodeString(message_body, is_big_endian)

            -- Add additional fields to the existing auth entry
            entry_tree:add(fvalid_host, peer)
            -- Only show AuthZ authority field when method is not 'ca'
            if method:string():lower() ~= "ca" then
                entry_tree:add(fvalid_authority, authority)
                entry_tree:add(fvalid_isTLS, 1)
            end
            entry_tree:add(fvalid_user, account)
        end
    end
end

----------------------------------------------
-- pvsServerValidateDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvsServerValidateDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CONNECTION_VALIDATION, ")
    local VALIDATION_HEADER_LEN = 7

    if message_body:len() >= VALIDATION_HEADER_LEN then
        -- Parse header: 4 bytes buffer size, 2 bytes introspection size, 1 byte flags
        local bsize getUint(message_body(0,4), is_big_endian)
        local isize getUint(message_body(4,2), is_big_endian)
        local flags = message_body(6,1):uint()
        tree:add(fvalid_bsize, message_body(0,4), bsize)
        tree:add(fvalid_isize, message_body(4,2), isize)
        tree:add(fvalid_azflg, message_body(6,1), flags)

        -- Parse all strings into a table first
        if message_body:len() > VALIDATION_HEADER_LEN then
            local remaining = message_body(VALIDATION_HEADER_LEN):tvb()
            local strings = {}

            -- Collect all strings
            while remaining and remaining:len() > 0 do
                local str
                str, remaining = decodeString(remaining, is_big_endian)
                if str and str:len() > 0 then
                    table.insert(strings, str)
                else
                    break
                end
            end

            -- Process strings into auth entries
            if #strings > 0 then
                local auth_entries = {}
                local current_entry = {}
                local has_seen_method = false

                for i, str in ipairs(strings) do
                    if isAuthMethod(str, i, has_seen_method) then
                        -- This is a method string
                        if current_entry.method then
                            -- Current entry already has a method, start new entry
                            table.insert(auth_entries, current_entry)
                            current_entry = {method = str}
                        else
                            -- Add method to current entry
                            current_entry.method = str
                        end
                        has_seen_method = true
                    else
                        -- This is likely a name/user string
                        if not current_entry.name then
                            current_entry.name = str
                        else
                            -- Could be additional data like response
                            current_entry.response = str
                        end
                    end
                end

                -- Add the last entry
                if current_entry.method or current_entry.name or current_entry.response then
                    table.insert(auth_entries, current_entry)
                end

                -- Create subtrees for each auth entry
                for i, entry in ipairs(auth_entries) do
                    local entry_tree = tree:add("AuthZ Entry " .. i)

                    if entry.name then
                        entry_tree:add(fvalid_user, entry.name)
                    end
                    if entry.method then
                        entry_tree:add(fvalid_method, entry.method)
                    end
                    if entry.response then
                        entry_tree:add(fauthz_response, entry.response)
                    end
                end
            end

            -- Handle any remaining unprocessed data
            if remaining and remaining:len() > 0 then
                tree:add(fbody, remaining)
            end
        end
    else
        -- Too short, show as raw body
        tree:add(fbody, message_body)
    end
end

local function pvaClientCreateChannelDecoder (buf, pkt, t, is_big_endian, cmd)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local npv
    if is_big_endian then
        npv = buf(0,2):uint()
    else
        npv = buf(0,2):le_uint()
    end
    buf = buf(2)

    for i=0,npv-1 do
        local cid, name
        if is_big_endian then
            cid = buf(0,4):uint()
        else
            cid = buf(0,4):le_uint()
        end
        t:add(fsearch_cid, buf(0,4), cid)
        name, buf = decodeString(buf(4), is_big_endian)
        t:add(fsearch_name, name)

        if i<npv-1 then pkt.cols.info:append("', '") end
        pkt.cols.info:append("'"..name:string())
    end
    pkt.cols.info:append("'), ")
end

local function pvaServerCreateChannelDecoder (buf, pkt, t, is_big_endian, cmd)
    local cid, sid
    if is_big_endian
    then
        cid = buf(0,4):uint()
        sid = buf(4,4):uint()
    else
        cid = buf(0,4):le_uint()
        sid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fcid, buf(0,4), cid)
    t:add(fsid, buf(4,4), sid)
    decodeStatus(buf(8), pkt, t, is_big_endian)
end

local function pvaDestroyChannelDecoder (buf, pkt, t, is_big_endian, cmd)
    local cid, sid
    if is_big_endian
    then
        sid = buf(0,4):uint()
        cid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        cid = buf(4,4):le_uint()
    end
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    t:add(fsid, buf(0,4), sid)
    t:add(fcid, buf(4,4), cid)
end

local function pvaClientDestroyDecoder (buf, pkt, t, is_big_endian, cmd)
    local cname = application_messages[cmd]
    local sid, ioid;
    if is_big_endian
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u), ", cname, sid, ioid))
end

local function pvaGenericClientOpDecoder (buf, pkt, t, is_big_endian, cmd)
    local cname = application_messages[cmd]
    local sid, ioid, subcmd
    if is_big_endian
    then
        sid = buf(0,4):uint()
        ioid = buf(4,4):uint()
    else
        sid = buf(0,4):le_uint()
        ioid = buf(4,4):le_uint()
    end
    subcmd = buf(8,1):uint()
    t:add(fsid, buf(0,4), sid)
    t:add(fioid, buf(4,4), ioid)
    local cmd = t:add(fsubcmd, buf(8,1), subcmd)
    cmd:add(fsubcmd_proc, buf(8,1), subcmd)
    cmd:add(fsubcmd_init, buf(8,1), subcmd)
    cmd:add(fsubcmd_dstr, buf(8,1), subcmd)
    cmd:add(fsubcmd_get, buf(8,1), subcmd)
    cmd:add(fsubcmd_gtpt, buf(8,1), subcmd)
    if buf:len()>9 then
        decodePVData(buf(9):tvb(), pkt, t, is_big_endian, "PVData Body")
    end

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u, sub=%02x), ", cname, sid, ioid, subcmd))
end


local function pvaGenericServerOpDecoder (buf, pkt, t, is_big_endian, cmd)
    local cname = application_messages[cmd]
    local ioid, subcmd
    if is_big_endian
    then
        ioid = buf(0,4):uint()
    else
        ioid = buf(0,4):le_uint()
    end
    subcmd = buf(4,1):uint()
    t:add(fioid, buf(0,4), ioid)
    local tcmd = t:add(fsubcmd, buf(4,1), subcmd)
    tcmd:add(fsubcmd_proc, buf(4,1), subcmd)
    tcmd:add(fsubcmd_init, buf(4,1), subcmd)
    tcmd:add(fsubcmd_dstr, buf(4,1), subcmd)
    tcmd:add(fsubcmd_get, buf(4,1), subcmd)
    tcmd:add(fsubcmd_gtpt, buf(4,1), subcmd)
    buf = buf(5):tvb()

    if cmd~=13 or bit.band(subcmd,0x08)~=0 then
        -- monitor updates have no status
        buf = decodeStatus(buf(0), pkt, t, is_big_endian)
    end

    if buf and buf:len()>0 then
        -- Special handling for MONITOR-INIT messages
        if cmd == 13 and bit.band(subcmd, 0x08) == 0 then -- MONITOR with INIT flag
            parseMonitorInit(buf, pkt, t, is_big_endian)
        else
            decodePVData(buf, pkt, t, is_big_endian, "PVData Body")
        end
    end

    pkt.cols.info:append(string.format("%s(ioid=%u, sub=%02x), ", cname, ioid, subcmd))
end

local server_cmd_handler = {
    [0] = pvaServerBeaconDecoder,
    [1] = pvsServerValidateDecoder,
    [4] = pvaServerSearchResponseDecoder,
    [7] = pvaServerCreateChannelDecoder,
    [8] = pvaDestroyChannelDecoder,
    [10] = pvaGenericServerOpDecoder,
    [11] = pvaGenericServerOpDecoder,
    [12] = pvaGenericServerOpDecoder,
    [13] = pvaGenericServerOpDecoder,
    [14] = pvaGenericServerOpDecoder,
    [20] = pvaGenericServerOpDecoder,
}

local client_cmd_handler = {
    [1] = pvaClientValidateDecoder,
    [3] = pvaClientSearchDecoder,
    [7] = pvaClientCreateChannelDecoder,
    [8] = pvaDestroyChannelDecoder,
    [10] = pvaGenericClientOpDecoder,
    [11] = pvaGenericClientOpDecoder,
    [12] = pvaGenericClientOpDecoder,
    [13] = pvaGenericClientOpDecoder,
    [14] = pvaGenericClientOpDecoder,
    [15] = pvaClientDestroyDecoder,
    [20] = pvaGenericClientOpDecoder,
    [21] = pvaClientDestroyDecoder,
}

local PVA_MAGIC = 0xCA;
local PVA_HEADER_LEN = 8;

----------------------------------------------
-- decode: decode the given buffer into the given packet and root tree node
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param root: the root tree node to decode into
-- @return the number of bytes consumed
----------------------------------------------
local function decode (buf, pkt, root)
    -- minimum of 8 byte header
    if buf:len() < PVA_HEADER_LEN then
        return 0
    end

    -- must start with magic
    local raw_magic = buf(0, 1);
    if raw_magic:uint() ~= PVA_MAGIC
    then
        pkt.cols.info:append("Corrupt message.  Bad magic.")
        return 0;
    end

    -- decode flags
    local raw_flags     = buf(2, 1)
    local flags_val     = raw_flags:uint()
    local is_big_endian = bit.band(flags_val, 0x80)
    local is_ctrl_cmd   = bit.band(flags_val, 0x01)

    -- decode message length
    local message_len = 0
    local raw_len = buf(4, 4)
    if is_ctrl_cmd == 0
    then
        -- decode length with 4 bytes with correct endianness
        message_len = getUint(raw_len, is_big_endian ~= 0)
    end

    -- check that buffer length is long enough
    if buf:len() < PVA_HEADER_LEN + message_len
    then
        return (buf:len() - (PVA_HEADER_LEN + message_len))
    end

    -- decode header
    local header_tree_node = root:add(pva, buf(0, PVA_HEADER_LEN + message_len))

    local raw_cmd = buf(3, 1);
    header_tree_node:add(fmagic,        raw_magic)              -- magic
    header_tree_node:add(fver,          buf(1, 1))              -- protocol version
    local flags = header_tree_node:add(fflags, raw_flags)       -- flags
    if is_ctrl_cmd == 0
    then
        header_tree_node:add(fcmd,      raw_cmd)                -- command
        header_tree_node:add(fsize,     raw_len, message_len)   -- size
    else
        header_tree_node:add(fctrlcmd,  raw_cmd)                -- control command
        header_tree_node:add(fctrldata, raw_len)                -- control data
    end

    -- decode flags
    flags:add(fflag_msgtype,            raw_flags)              -- message type
    flags:add(fflag_segmented,          raw_flags)              -- segmented
    flags:add(fflag_dir,                raw_flags)              -- direction
    flags:add(fflag_end,                raw_flags)              -- endianness

    -- decode command op code
    local cmd = raw_cmd:uint()
    local show_generic_cmd = 1

    local message_body = buf(PVA_HEADER_LEN, message_len);
    if is_ctrl_cmd == 0
    then
        -- application message
        if bit.band(flags_val, 0x40) ~= 0
        then
            -- server
            local cmd_handler = server_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(message_body, pkt, header_tree_node, is_big_endian ~= 0, cmd)
                show_generic_cmd = 0
            end
        else
            -- client
            local cmd_handler = client_cmd_handler[cmd]
            if cmd_handler
            then
                cmd_handler(message_body, pkt, header_tree_node, is_big_endian ~= 0, cmd)
                show_generic_cmd = 0
            end
        end
    else
        -- control message
        local cmd_name = control_messages[cmd]
        if cmd_name
        then
            pkt.cols.info:append(cmd_name .. ", ")
        else
            pkt.cols.info:append("Msg: " .. cmd .. " ")
        end
        show_generic_cmd = 0
    end

    if show_generic_cmd ~= 0
    then
        local cmd_name = application_messages[cmd]
        if cmd_name
        then
            pkt.cols.info:append(cmd_name .. ", ")
        else
            pkt.cols.info:append("Msg: " .. cmd .. " ")
        end

        if is_big_endian
        then
            header_tree_node:add(fbody, buf(8, message_len))
        else
            header_tree_node:addle(fbody, buf(8, message_len))
        end
    end

    return PVA_HEADER_LEN + message_len
end

----------------------------------------------
-- dissector: the dissector function
-- Implementation of the PVA disector
-- @param buf: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param root: the root tree node to decode into
----------------------------------------------
function pva.dissector (buf, pkt, root)
    -- must start with magic
    local raw_magic = buf(0, 1);
    if raw_magic:uint() ~= PVA_MAGIC
    then
        return
    end

    -- set protocol name in protocol column
    pkt.cols.protocol = pva.name

    -- set up initial part of info column
    pkt.cols.info:clear()
    pkt.cols.info:append(pkt.src_port .. " -> " .. pkt.dst_port .. " ")
    if bit.band(buf(2, 1):uint(), 0x40) ~= 0
    then
        pkt.cols.info:append("Server ")
    else
        pkt.cols.info:append("Client ")
    end

    local total_consumed = 0

    while buf:len() > 0
    do
        local consumed = decode(buf, pkt, root)

        if consumed < 0
        then
            -- overrun
            pkt.desegment_offset = total_consumed
            pkt.desegment_len = -consumed
            return
        elseif consumed < PVA_HEADER_LEN
        then
            -- incomplete
            pkt.cols.info:preppend("[Incomplete] ")
            break
        else
            -- just right
            total_consumed = total_consumed + consumed
            buf = buf(consumed):tvb()
        end
    end
end

-- initialise
local utbl = DissectorTable.get("udp.port")
utbl:add(5075, pva)
utbl:add(5076, pva)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5075, pva)
DissectorTable.get("tls.alpn"):add("pva/1", pva)

io.stderr:write("Loaded PVA\n")
