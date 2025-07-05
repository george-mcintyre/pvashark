-- Wireshark Lua script plugin
-- packet disector for PV Access protocol
--
-- Copyright 2021 Michael Davidsaver, 2025 George McIntyre
--
-- Distribution and use subject to the EPICS Open License
-- See the file LICENSE
--
io.stderr:write("Loading PVA...\n")

local BEACON_MESSAGE = 0
local CONNECTION_VALIDATION_MESSAGE = 1
local ECHO_MESSAGE = 2
local SEARCH_MESSAGE = 3
local SEARCH_RESPONSE_MESSAGE = 4
local AUTHNZ_MESSAGE = 5
local ACL_CHANGE_MESSAGE = 6
local CREATE_CHANNEL_MESSAGE = 7
local DESTROY_CHANNEL_MESSAGE = 8
local CONNECTION_VALIDATED_MESSAGE = 9
local GET_MESSAGE = 10
local PUT_MESSAGE = 11
local PUT_GET_MESSAGE = 12
local MONITOR_MESSAGE = 13
local ARRAY_MESSAGE = 14
local DESTROY_REQUEST_MESSAGE = 15
local PROCESS_MESSAGE = 16
local GET_FIELD_MESSAGE = 17
local MESSAGE_MESSAGE = 18
local MULTIPLE_DATA_MESSAGE = 19
local RPC_MESSAGE = 20
local CANCEL_REQUEST_MESSAGE = 21
local ORIGIN_TAG_MESSAGE = 22

-- application messages
local application_messages = {
    [BEACON_MESSAGE]  = "BEACON",
    [CONNECTION_VALIDATION_MESSAGE]  = "CONNECTION_VALIDATION",
    [ECHO_MESSAGE]  = "ECHO",
    [SEARCH_MESSAGE]  = "SEARCH",
    [SEARCH_RESPONSE_MESSAGE]  = "SEARCH_RESPONSE",
    [AUTHNZ_MESSAGE]  = "AUTHNZ",
    [ACL_CHANGE_MESSAGE]  = "ACL_CHANGE",
    [CREATE_CHANNEL_MESSAGE]  = "CREATE_CHANNEL",
    [DESTROY_CHANNEL_MESSAGE]  = "DESTROY_CHANNEL",
    [CONNECTION_VALIDATED_MESSAGE]  = "CONNECTION_VALIDATED",
    [GET_MESSAGE] = "GET",
    [PUT_MESSAGE] = "PUT",
    [PUT_GET_MESSAGE] = "PUT_GET",
    [MONITOR_MESSAGE] = "MONITOR",
    [ARRAY_MESSAGE] = "ARRAY",
    [DESTROY_REQUEST_MESSAGE] = "DESTROY_REQUEST",
    [PROCESS_MESSAGE] = "PROCESS",
    [GET_FIELD_MESSAGE] = "GET_FIELD",
    [MESSAGE_MESSAGE] = "MESSAGE",
    [MULTIPLE_DATA_MESSAGE] = "MULTIPLE_DATA",
    [RPC_MESSAGE] = "RPC",
    [CANCEL_REQUEST_MESSAGE] = "CANCEL_REQUEST",
    [ORIGIN_TAG_MESSAGE] = "ORIGIN_TAG",
}

local PVA_MAGIC = 0xCA;
local PVA_HEADER_LEN = 8;

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

local nt_types = {
    "epics:nt/NTScalar:1.0", "NTScalar",
    "epics:nt/NTScalarArray:1.0", "NTScalarArray",
    "epics:nt/NTEnum:1.0", "NTEnum",
    "epics:nt/NTMatrix:1.0", "NTMatrix",
    "epics:nt/NTURI:1.0", "NTURI",
    "epics:nt/NameValue:1.0", "NameValue",
    "epics:nt/NTTable:1.0", "NTTable",
    "epics:nt/NTAttribute:1.0", "NTAttribute",
    "epics:nt/NTMultiChannel:1.0", "NTMultiChannel",
    "epics:nt/NTNDArray:1.0", "NTNDArray",
    "epics:nt/NTHistogram:1.0", "NTHistogram",
    "epics:nt/NTAggregate:1.0", "NTAggregate",
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
local fflag_dir     = ProtoField.uint8(     "pva.direction",    "Direction",
        base.HEX, {[0]="client",[1]="server"}, 0x40)
local fflag_end     = ProtoField.uint8(     "pva.endian",       "Byte order",
        base.HEX, {[0]="LSB",[1]="MSB"}, 0x80)
local fflag_msgtype = ProtoField.uint8(     "pva.msg_type",     "Message type",
        base.HEX, {[0]="Application",[1]="Control"}, 0x01)
local fflag_segmented = ProtoField.uint8(   "pva.segmented",    "Segmented",
        base.HEX, {[0]="Not segmented",[1]="First segment",[2]="Last segment",[3]="In-the-middle segment"}, 0x30)
local fcmd          = ProtoField.uint8(     "pva.command",      "Command",
        base.HEX, application_messages)
local fctrlcmd      = ProtoField.uint8(     "pva.ctrlcommand",  "Control Command",
        base.HEX, control_messages)
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

----------------------------------------------
--- getUint: get an unsigned integer with the correct byte order
--- @param src to read the uint from
--- @param is_big_endian flag to indicate the bigendianness
----------------------------------------------
local function getUint(src, is_big_endian)
    if is_big_endian == nil or is_big_endian then
        return src:uint()
    else
        return src:le_uint()
    end
end

----------------------------------------------
-- decodeSize: decode a size from a buffer
-- size is encoded as a single byte, or 4 bytes if the first byte is 0xFE or 0xFF
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @param , is_nullable: true if the buffer is nullable (default true)
-- @return the size and the remaining buffer
----------------------------------------------
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
-- decodeString: extract a string and return that string, and the remaining buffer
-- string is encoded as a size (1 or 4 bytes) followed by the actual string
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @param , is_nullable: true if the buffer is nullable
-- @return the string and the remaining buffer
----------------------------------------------
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
        return remaining_buf(0, len), remaining_buf(len):tvb()
    end
end

-- Parse Type ID string
local function getTypeId(message_body, is_big_endian)
    local display_name = nil
    if message_body:len() > 0 then
        local type_id, remaining_buf = decodeString(message_body, is_big_endian, false)
        if type_id and type_id:len() > 0 then
            local type_id_str = type_id:string()
            display_name = type_id_str

            -- Look for normative type translation
            for i = 1, #nt_types, 2 do
                if nt_types[i] == type_id_str then
                    display_name = nt_types[i + 1]
                    break
                end
            end

            message_body = remaining_buf
        end
    end
    return type_id, message_body, display_name
end


----------------------------------------------
-- skipNextElement: skip the next element and return the remaining buffer
-- @param buf: the buffer to decode from
-- @param is_big_endian: true if the buffer is big endian
-- @return the remaining buffer
----------------------------------------------
local function skipNextElement(buf, is_big_endian)
    local len, remaining_buf = decodeSize(buf, is_big_endian, is_nullable)
    if len == remaining_buf:len() then
        return nil
    else
        return remaining_buf(len + 1)
    end
end

----------------------------
-- PVData decoders
----------------------------

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
local function getTypeSize(type_code)
    if type_code == TYPE_CODE_BOOLEAN then return 1 -- bool
    elseif type_code == TYPE_CODE_BYTE then return 1 -- int8_t
    elseif type_code == TYPE_CODE_SHORT then return 2 -- int16_t
    elseif type_code == TYPE_CODE_INT then return 4 -- int32_t
    elseif type_code == TYPE_CODE_LONG then return 8 -- int64_t
    elseif type_code == TYPE_CODE_UBYTE then return 1 -- uint8_t
    elseif type_code == TYPE_CODE_USHORT then return 2 -- uint16_t
    elseif type_code == TYPE_CODE_UINT then return 4 -- uint32_t
    elseif type_code == TYPE_CODE_ULONG then return 8 -- uint64_t
    elseif type_code == TYPE_CODE_FLOAT then return 4 -- float
    elseif type_code == TYPE_CODE_DOUBLE then return 8 -- double
    else return 0 -- variable length or unknown
    end
end

-- Helper function to identify authentication method strings
local function isAuthMethod(method_name, prev_was_method)
    local lower_case_method_name = method_name:string():lower()

    -- Strong method indicators
    local strong_methods = {"x509", "ca"}
    for _, method in ipairs(strong_methods) do
        if lower_case_method_name == method then
            return true
        end
    end

    -- "anonymous" is typically a username unless it's clearly in method position
    if lower_case_method_name == "anonymous" then
        -- Treat as method only if we've already seen a method (meaning this starts a new entry)
        return prev_was_method
    end

    return false
end

----------------------------------------------
-- decodeStatus: decode the given message body to extract the status
-- @param message_body: the buffer to decode from
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function decodeStatus (message_body, tree, is_big_endian)
    local status_code = message_body(0,1):uint()
    local sub_tree = tree:add(fstatus, message_body(0,1))
    if message_body:len()>1 then
        message_body = message_body(1)
    end

    if status_code ==0xFF then
        return message_body
    else
        local message, stack
        message, message_body = decodeString(message_body, is_big_endian)
        stack, message_body = decodeString(message_body, is_big_endian)
        sub_tree:append_text(message:string())
        if(status_code ~=0 and stack:len()>0)
        then
            sub_tree:add_expert_info(PI_RESPONSE_CODE, PI_WARN, stack:string())
        end
        return message_body
    end
end


-- Parse structure FieldDesc: field count + fields
local function parseStructDesc(message_body, is_big_endian, tree, type_code)
    -- Read field count
    if (message_body ~= nil and message_body:len() > 0) then
        local field_count, message_body = decodeSize(message_body, is_big_endian, false)
        if (field_count ~= nil and message_body ~= nil and message_body:len() > 0) then
            -- Parse each field: name + FieldDesc
            for i = 1, field_count do
                local field_name, message_body = decodeString(message_body, is_big_endian, false)
                message_body = parseFieldDesc(message_body, is_big_endian, tree, field_name)
            end
        end
    end

    return message_body
end

-- Parse union FieldDesc: field count + fields
local function parseUnionDesc(message_body, is_big_endian, tree, type_code)
    -- Read field count
    if (message_body ~= nil and message_body:len() > 0) then
        local field_count, message_body = decodeSize(message_body, is_big_endian, false)
        if (field_count ~= nil and message_body ~= nil and message_body:len() > 0) then
            -- Parse each field: name + FieldDesc
            for i = 1, field_count do
                local field_name, message_body = decodeString(message_body, is_big_endian, false)
                message_body = parseFieldDesc(message_body, is_big_endian, tree, field_name)
            end
        end
    end

    return message_body
end

local function parseCacheStore(buf, is_big_endian, tree)
    if buf and buf:len() >= 2 then
        local cache_key = getUint(buf(0, 2), is_big_endian)

        -- Parse the stored FieldDesc
        buf = buf(2)
        buf = parseFieldDesc(buf, is_big_endian, tree, nil)
    end
    return buf
end

local function parseCacheFetch(buf, is_big_endian, tree)
    if buf and buf:len() >= 2 then
        local cache_key = getUint(buf(0, 2), is_big_endian)
        if ( buf:len() == 2 ) then
            return nil
        end
        buf = buf(2)
    end
    return buf
end

parseFieldDesc = function(buf, is_big_endian, tree, field_name)
    if not buf or buf:len() < 1 then
        return buf
    end

    -- Read Type code
    local type_code = buf(0, 1):uint()
    buf = buf(1)
    local type_name = PVD_TYPES[type_code] or string.format("unknown(0x%02X)", type_code)

    local field_tree

    if type_code == TYPE_CODE_STRUCT or type_code == TYPE_CODE_UNION then
        -- Read optional Type ID string
        local type_id, buf, translated_name = getTypeId(buf, is_big_endian)
        local clean_name = "struct"
        if type_code == TYPE_CODE_UNION then clean_name = "union" end

        if translated_name then
            clean_name = translated_name
        elseif type_id and type_id:len() > 0 then
            -- Extract clean type name
            local type_id_str = type_id:string()
            clean_name = type_id_str:match("nt/([^:]+)") or type_id_str:match("([^:]+)") or type_id_str
        else
            clean_name = type_name
        end

        -- Create field display with standard format: fieldname (0xHH: typename)
        local display_name = field_name and string.format("%s (0x%02X: %s)", field_name, type_code, clean_name)
                or string.format("(0x%02X: %s)", type_code, clean_name)
        field_tree = tree:add(type_code, display_name)
    else
        field_tree = tree:add(placeholder, "Body")
    end

    -- Handle TypeCode-specific parsing
    if type_code == TYPE_CODE_STRUCT then
        buf = parseStructDesc(buf, is_big_endian, field_tree, type_code)
    elseif type_code == TYPE_CODE_UNION then
        buf = parseUnionDesc(buf, is_big_endian, field_tree, type_code)
    elseif type_code == CACHE_STORE_CODE then
        buf = parseCacheStore(buf, is_big_endian, field_tree)
    elseif type_code == CACHE_FETCH_CODE then
        buf = parseCacheFetch(buf, is_big_endian, field_tree)
        -- All other types (scalars, arrays) are just TypeCode - no additional data
    end

    return buf
end

-- ===================================================================
-- MONITOR-INIT PARSER (uses unified FieldDesc system)
-- ===================================================================

local function parseMonitorInit(message_body, pkt, tree, is_big_endian)
    if not message_body or message_body:len() == 0 then
        return
    end

    -- Parse ChangedBitSet
    local bitset_byte = message_body(0, 1):uint()
    local bits_set = {}
    for i = 0, 7 do
        if bit.band(bitset_byte, bit.lshift(1, i)) ~= 0 then
            table.insert(bits_set, i)
        end
    end
    local bits_str = table.concat(bits_set, ",")
    local field_tree = tree:add(message_body, "Body")

    field_tree:add(message_body(0, 1), string.format("ChangedBitSet: 0x%02X (bits: %s)", bitset_byte, bits_str))
    message_body = message_body(1):tvb()

    -- Parse FieldDesc structure (starts with field count)
    if message_body and message_body:len() > 0 then
        local field_count, remaining_buf = decodeSize(message_body, is_big_endian, false)
        if field_count then
            message_body = remaining_buf

            if field_count > 0 then
                -- Parse each field using unified system
                for i = 1, field_count do
                    if not message_body or message_body:len() <= 0 then break end

                    local field_name, remaining_buf = decodeString(message_body, is_big_endian, false)
                    if not field_name then break end
                    message_body = remaining_buf
                    message_body = parseFieldDesc(message_body, is_big_endian, field_tree, field_name:string())
                end
            end
        end

        -- Show remaining data if any
        if message_body and message_body:len() > 0 then
            tree:add(message_body, string.format("Remaining data (%d bytes)", message_body:len()))
        end
    end
end

function decodePVData(buf, pkt, t, is_big_endian, label)
    if not buf or buf:len() == 0 then
        return
    end

    local pvd_tree = t:add(placeholder, label or "PVData Body")

    if buf:len() == 0 then
        pvd_tree:append_text(" [Empty]")
        return pvd_tree
    end

    parseFieldDesc(buf, is_big_endian, pvd_tree, "value")

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
        local bsize = getUint(message_body(0,4), is_big_endian)
        local isize = getUint(message_body(4,2), is_big_endian)
        local flags = message_body(6,1):uint()
        tree:add(fvalid_bsize, message_body(0,4), bsize)
        tree:add(fvalid_isize, message_body(4,2), isize)
        tree:add(fvalid_azflg, message_body(6,1), flags)

        -- Parse all strings into a table first
        if message_body:len() > VALIDATION_HEADER_LEN then
            local remaining = message_body(VALIDATION_HEADER_LEN)
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

                for _, method_name in ipairs(strings) do
                    if isAuthMethod(method_name, has_seen_method) then
                        -- This is a method string
                        if current_entry.method then
                            -- Current entry already has a method, start new entry
                            table.insert(auth_entries, current_entry)
                            current_entry = {method = method_name }
                        else
                            -- Add method to current entry
                            current_entry.method = method_name
                        end
                        has_seen_method = true
                    else
                        -- This is likely a name/user string
                        if not current_entry.name then
                            current_entry.name = method_name
                        else
                            -- Could be additional data like response
                            current_entry.response = method_name
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

----------------------------------------------
-- pvaClientCreateChannelDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaClientCreateChannelDecoder (message_body, pkt, tree, is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(")
    local n_pvs = getUint(message_body(0,2), is_big_endian)
    message_body = message_body(2)

    for i=0, n_pvs -1 do
        local cid = getUint(message_body(0,4), is_big_endian)
        tree:add(fsearch_cid, message_body(0,4), cid)
        local name
        name, message_body = decodeString(message_body(4), is_big_endian)
        tree:add(fsearch_name, name)
        if i< n_pvs -1 then pkt.cols.info:append("', '") end
        pkt.cols.info:append("'"..name:string())
    end
    pkt.cols.info:append("'), ")
end

----------------------------------------------
-- pvaServerCreateChannelDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
----------------------------------------------
local function pvaServerCreateChannelDecoder (message_body, pkt, tree, is_big_endian)
    local cid = getUint(message_body(0,4), is_big_endian)
    local sid = getUint(message_body(4,4), is_big_endian)
    pkt.cols.info:append("CREATE_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fcid, message_body(0,4), cid)
    tree:add(fsid, message_body(4,4), sid)
    decodeStatus(message_body(8), tree, is_big_endian)
end

----------------------------------------------
-- pvaDestroyChannelDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaDestroyChannelDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local cid = getUint(message_body(0,4), is_big_endian)
    local sid = getUint(message_body(4,4), is_big_endian)
    pkt.cols.info:append("DESTROY_CHANNEL(cid="..cid..", sid="..sid.."), ")
    tree:add(fsid, message_body(0,4), sid)
    tree:add(fcid, message_body(4,4), cid)
end

----------------------------------------------
-- pvaClientDestroyDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaClientDestroyDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local command_name = application_messages[cmd]
    local sid = getUint(message_body(0,4), is_big_endian)
    local ioid = getUint(message_body(4,4), is_big_endian)
    tree:add(fsid, message_body(0,4), sid)
    tree:add(fioid, message_body(4,4), ioid)
    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u), ", command_name, sid, ioid))
end

----------------------------------------------
-- pvaGenericClientOpDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericClientOpDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local GENERIC_COMMAND_HEADER = 9
    local cname = application_messages[cmd]
    local sid = getUint(message_body(0,4), is_big_endian)
    local ioid = getUint(message_body(4,4), is_big_endian)
    local raw_sub_command = message_body(8,1)
    local sub_command = raw_sub_command:uint()
    tree:add(fsid, message_body(0,4), sid)
    tree:add(fioid, message_body(4,4), ioid)
    local sub_tree = tree:add(fsubcmd, message_body(8,1), sub_command)
    sub_tree:add(fsubcmd_proc, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_init, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_dstr, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_get,  raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_gtpt, raw_sub_command, sub_command)
    if message_body:len()>GENERIC_COMMAND_HEADER then
        decodePVData(message_body(GENERIC_COMMAND_HEADER):tvb(), pkt, tree, is_big_endian, "PVData Body")
    end

    pkt.cols.info:append(string.format("%s(sid=%u, ioid=%u, sub=%02x), ", cname, sid, ioid, sub_command))
end


----------------------------------------------
-- pvaGenericServerOpDecoder: decode the given message body into the given packet and root tree node
-- @param message_body: the buffer to decode from
-- @param pkt: the packet to decode into
-- @param tree: the tree node to decode into
-- @param is_big_endian is the byte stream big endian
-- @param cmd the command number
----------------------------------------------
local function pvaGenericServerOpDecoder (message_body, pkt, tree, is_big_endian, cmd)
    local GENERIC_COMMAND_HEADER = 5
    local cname = application_messages[cmd]
    local ioid = getUint(message_body(0,4), is_big_endian)
    local raw_sub_command = message_body(4,1)
    local sub_command = raw_sub_command:uint()

    -- Add fields to tree
    tree:add(fioid, message_body(0,4), ioid)
    local sub_tree = tree:add(fsubcmd, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_proc, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_init, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_dstr, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_get, raw_sub_command, sub_command)
    sub_tree:add(fsubcmd_gtpt, raw_sub_command, sub_command)

    -- Skip the header
    message_body = message_body(GENERIC_COMMAND_HEADER):tvb()

    -- Define monitor-specific flags for clarity
    local is_monitor_init = cmd == MONITOR_MESSAGE and bit.band(sub_command, 0x08) ~= 0
    local is_monitor_update = cmd == MONITOR_MESSAGE and bit.band(sub_command, 0x08) == 0

    -- Status handling: All messages except MONITOR UPDATE have status
    if not is_monitor_update then
        message_body = decodeStatus(message_body, tree, is_big_endian)
    end

    -- Process remaining payload
    if message_body and message_body:len() > 0 then
        if is_monitor_init then
            -- MONITOR INIT: Contains type information after status
            parseMonitorInit(message_body, pkt, tree, is_big_endian)
        else
            -- All other cases: Regular PVData
            decodePVData(message_body, pkt, tree, is_big_endian, "PVData Body")
        end
    end

    pkt.cols.info:append(string.format("%s(ioid=%u, sub=%02x), ", cname, ioid, sub_command))
end

local server_cmd_handler = {
    [BEACON_MESSAGE] =                  pvaServerBeaconDecoder,
    [CONNECTION_VALIDATION_MESSAGE] =   pvsServerValidateDecoder,
    [SEARCH_RESPONSE_MESSAGE] =         pvaServerSearchResponseDecoder,
    [CREATE_CHANNEL_MESSAGE] =          pvaServerCreateChannelDecoder,
    [DESTROY_CHANNEL_MESSAGE] =         pvaDestroyChannelDecoder,
    [GET_MESSAGE] =                     pvaGenericServerOpDecoder,
    [PUT_MESSAGE] =                     pvaGenericServerOpDecoder,
    [PUT_GET_MESSAGE] =                 pvaGenericServerOpDecoder,
    [MONITOR_MESSAGE] =                 pvaGenericServerOpDecoder,
    [ARRAY_MESSAGE] =                   pvaGenericServerOpDecoder,
    [RPC_MESSAGE] =                     pvaGenericServerOpDecoder,
}

local client_cmd_handler = {
    [CONNECTION_VALIDATION_MESSAGE] =   pvaClientValidateDecoder,
    [SEARCH_MESSAGE] =                  pvaClientSearchDecoder,
    [CREATE_CHANNEL_MESSAGE] =          pvaClientCreateChannelDecoder,
    [DESTROY_CHANNEL_MESSAGE] =         pvaDestroyChannelDecoder,
    [GET_MESSAGE] =                     pvaGenericClientOpDecoder,
    [PUT_MESSAGE] =                     pvaGenericClientOpDecoder,
    [PUT_GET_MESSAGE] =                 pvaGenericClientOpDecoder,
    [MONITOR_MESSAGE] =                 pvaGenericClientOpDecoder,
    [ARRAY_MESSAGE] =                   pvaGenericClientOpDecoder,
    [DESTROY_REQUEST_MESSAGE] =         pvaClientDestroyDecoder,
    [RPC_MESSAGE] =                     pvaGenericClientOpDecoder,
    [CANCEL_REQUEST_MESSAGE] =          pvaClientDestroyDecoder,
}

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
            header_tree_node:add(fpvd, buf(8, message_len))
        else
            header_tree_node:addle(fpvd, buf(8, message_len))
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

local function test_pva (buf, pkt, root)
    if buf:len()<PVA_HEADER_LEN or buf(0,1):uint()~= PVA_MAGIC or buf(1,1):uint()==0 or not application_messages[buf(3,1):uint()]
    then
        return false
    end
    pva.dissector(buf, pkt, root)
    pkt.conversation = pva
    return true
end

-- initialise
local utbl = DissectorTable.get("udp.port")
utbl:add(5075, pva)
utbl:add(5076, pva)
local ttbl = DissectorTable.get("tcp.port")
ttbl:add(5075, pva)
DissectorTable.get("tls.alpn"):add("pva/1", pva)

local status, err = pcall(function() pva:register_heuristic("tcp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic TCP dissector.  Must manually specify TCP port! (try newer wireshark?)")
    print(err)
end

local status, err = pcall(function() pva:register_heuristic("udp", test_pva) end)
if not status then
    print("Failed to register PVA heuristic UDP dissector.  Must manually specify UDP port! (try newer wireshark?)")
    print(err)
end

io.stderr:write("Loaded PVA\n")
